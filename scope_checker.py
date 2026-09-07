from __future__ import annotations
"""
Deterministic scope checker — code check, not LLM judgment.

Validates URLs against an allowlist of domain patterns before any outbound request.
Uses anchored suffix matching (not raw fnmatch) to prevent subdomain confusion:
  - "*.target.com" matches "sub.target.com" but NOT "evil-target.com"
  - "target.com" matches exactly "target.com"

Known limitation: IP addresses and CIDR ranges are NOT supported (returns False + warning).
"""

import sys
from fnmatch import fnmatch
from urllib.parse import urlparse


class ScopeChecker:
    """Deterministic scope validator for bug bounty targets."""

    def __init__(
        self,
        domains: list[str],
        excluded_domains: list[str] | None = None,
        excluded_classes: list[str] | None = None,
    ):
        """
        Args:
            domains: Allowlist patterns like ["*.target.com", "api.target.com"]
            excluded_domains: Blocklist patterns like ["blog.target.com"]
            excluded_classes: Vuln classes excluded by program (e.g., ["dos"])
        """
        self.domains = [d.lower() for d in domains]
        self.excluded_domains = [d.lower() for d in (excluded_domains or [])]
        self.excluded_classes = [c.lower() for c in (excluded_classes or [])]

    def is_in_scope(self, url: str) -> bool:
        """Check if a URL's hostname is in scope.

        Returns:
            True if the hostname matches an allowed pattern and is not excluded.
            False otherwise (including for malformed URLs, empty input, IP addresses).
        """
        if not url or not isinstance(url, str):
            return False

        # Ensure we have a scheme for urlparse
        normalized = url if "://" in url else f"https://{url}"

        try:
            parsed = urlparse(normalized)
        except Exception:
            return False

        hostname = parsed.hostname
        if not hostname:
            return False

        # Normalize: lowercase and strip the trailing dot of an absolute
        # (rooted) FQDN — "sub.target.com." resolves identically to
        # "sub.target.com" and must match the same patterns. Doing it here
        # keeps the exclusion and allowlist matchers consistent.
        hostname = hostname.lower().rstrip(".")

        # IP address check — not supported, return False with warning
        if _is_ip(hostname):
            print(
                f"WARNING: scope checker does not support IP addresses: {hostname}",
                file=sys.stderr,
            )
            return False

        # Strip port if present (urlparse handles this, but be safe)
        # hostname from urlparse should already exclude port

        # Check exclusion list first. Exclusions use SUBTREE semantics: a
        # bare excluded host ("internal.target.com") excludes itself AND every
        # subdomain beneath it ("deep.internal.target.com"). Bug bounty
        # programs that list a bare host as out-of-scope mean the whole tree.
        for excluded in self.excluded_domains:
            if _excludes(hostname, excluded):
                return False

        # Check allowlist
        for pattern in self.domains:
            if _domain_matches(hostname, pattern):
                return True

        return False

    def is_vuln_class_allowed(self, vuln_class: str) -> bool:
        """Check if a vulnerability class is allowed by the program."""
        return vuln_class.lower() not in self.excluded_classes

    def filter_urls(self, urls: list[str]) -> tuple[list[str], list[str]]:
        """Split a list of URLs into (in_scope, out_of_scope)."""
        in_scope = []
        out_of_scope = []
        for url in urls:
            if self.is_in_scope(url):
                in_scope.append(url)
            else:
                out_of_scope.append(url)
        return in_scope, out_of_scope

    def filter_file(self, input_path: str, output_path: str | None = None) -> tuple[int, int]:
        """Filter a file of URLs (one per line) through scope check.

        Args:
            input_path: Path to file with URLs, one per line.
            output_path: If provided, write in-scope URLs here. If None, filter in-place.

        Returns:
            (in_scope_count, out_of_scope_count)
        """
        with open(input_path, "r") as f:
            lines = [line.strip() for line in f if line.strip()]

        in_scope, out_of_scope = self.filter_urls(lines)

        dest = output_path or input_path
        with open(dest, "w") as f:
            for url in in_scope:
                f.write(url + "\n")

        if out_of_scope:
            print(
                f"WARNING: filtered {len(out_of_scope)} out-of-scope URLs from {input_path}",
                file=sys.stderr,
            )

        return len(in_scope), len(out_of_scope)


def _domain_matches(hostname: str, pattern: str) -> bool:
    """Anchored domain matching — prevents subdomain confusion.

    *.target.com  → matches sub.target.com, a.b.target.com
                  → does NOT match target.com, evil-target.com
    target.com    → matches target.com exactly
    """
    pattern = pattern.rstrip(".")
    if pattern.startswith("*."):
        # Wildcard: must be a proper subdomain
        suffix = pattern[1:]  # ".target.com"
        return hostname.endswith(suffix) and hostname != suffix[1:]
    else:
        # Exact match
        return hostname == pattern


def _excludes(hostname: str, pattern: str) -> bool:
    """Subtree-aware exclusion matching.

    Unlike the allowlist (which is exact-match for a bare host), an exclusion
    for a bare host blocks that host AND its entire subtree:

    *.target.com         → blocks sub.target.com, a.b.target.com (proper subs)
    internal.target.com  → blocks internal.target.com AND deep.internal.target.com
    """
    pattern = pattern.rstrip(".")
    if pattern.startswith("*."):
        # Wildcard exclusion: proper subdomains of the suffix.
        suffix = pattern[1:]  # ".target.com"
        return hostname.endswith(suffix) and hostname != suffix[1:]
    # Bare host excludes itself and its whole subtree.
    return hostname == pattern or hostname.endswith("." + pattern)


def _is_ip(hostname: str) -> bool:
    """Check if hostname looks like an IP address (v4 or v6)."""
    # IPv6 in brackets
    if hostname.startswith("[") or ":" in hostname:
        return True
    # IPv4
    parts = hostname.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    return False


# ── S1: canonical EXACT-HOST allowlist for --scope-lock (P0) ─────────────────────────────────
# scope_lock_allows() is the ONE matcher every recon/scan/redirect/archive site must consult under
# scope-lock. It differs from ScopeChecker.is_in_scope: NO wildcards, NO subtree — the host must be
# EXACTLY a listed host (or a listed host:port / IP). Rejects www, subdomains, suffix-confusion,
# userinfo @-tricks; a non-default port is in scope only if 'host:port' is explicitly listed. It
# FAILS CLOSED — empty/missing allowlist or any parse ambiguity ⇒ False (scope nothing).

_DEFAULT_PORTS = frozenset({80, 443})


def _parse_host_port(s: str):
    """(host_lower_no_trailing_dot, port_or_None) from a host or URL. Fail-closed → (None, None)."""
    if not s or not isinstance(s, str):
        return (None, None)
    s = s.strip()
    if not s:
        return (None, None)
    has_scheme_sep = "://" in s
    normalized = s if has_scheme_sep else f"https://{s}"
    try:
        parsed = urlparse(normalized)
    except Exception:
        return (None, None)
    if has_scheme_sep and not parsed.scheme:
        return (None, None)               # "://example.com" — malformed, fail closed
    host = parsed.hostname
    if not host:
        return (None, None)
    host = host.lower().rstrip(".")
    if not host:
        return (None, None)
    try:
        port = parsed.port                # urlparse raises ValueError on a bad port
    except ValueError:
        return (None, None)
    return (host, port)


def scope_lock_allows(host_or_url: str, exact_hosts) -> bool:
    """True ONLY if host_or_url's host is EXACTLY an allowed host under scope-lock. Fail-closed."""
    if not exact_hosts:
        return False
    allow = {h.strip().lower().rstrip(".") for h in exact_hosts if h and str(h).strip()}
    if not allow:
        return False
    host, port = _parse_host_port(host_or_url)
    if not host:
        return False
    if port is not None and port not in _DEFAULT_PORTS:
        return f"{host}:{port}" in allow   # alt-port: only the exact host:port
    return host in allow                   # default/no port: exact host (also a listed IP)


def filter_scope_lock(urls, exact_hosts) -> list:
    """Keep only the URLs/hosts that are exactly in scope under scope-lock."""
    return [u for u in urls if scope_lock_allows(u, exact_hosts)]


def _load_allow_file(path) -> set:
    hosts = set()
    if not path:
        return hosts
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.strip()
                if ln and not ln.startswith("#"):
                    hosts.add(ln)
    except OSError:
        pass
    return hosts


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="scope-lock exact-host allowlist shim (fail-closed)")
    ap.add_argument("--scope-lock-check", action="store_true",
                    help="exit 0 iff the host arg is exactly in scope (else nonzero)")
    ap.add_argument("--scope-lock-filter", action="store_true",
                    help="filter --in through the allowlist to --out (drops off-scope)")
    ap.add_argument("--allow-file", help="file of exact allowed hosts (one per line)")
    ap.add_argument("--in", dest="infile")
    ap.add_argument("--out", dest="outfile")
    ap.add_argument("host", nargs="?")
    a = ap.parse_args()
    allow = _load_allow_file(a.allow_file)

    if a.scope_lock_filter:
        try:
            with open(a.infile, "r", encoding="utf-8") as fh:
                lines = [ln.strip() for ln in fh if ln.strip()]
        except OSError:
            lines = []
        kept = filter_scope_lock(lines, allow)
        with open(a.outfile, "w", encoding="utf-8") as fh:
            for u in kept:
                fh.write(u + "\n")
        sys.exit(0)

    # default: single-host check (fail-closed → nonzero when off-scope / empty allowlist)
    sys.exit(0 if scope_lock_allows(a.host or "", allow) else 1)
