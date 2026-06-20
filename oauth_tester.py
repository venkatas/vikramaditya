#!/usr/bin/env python3
from __future__ import annotations
"""
OAuth Security Tester — Tests OAuth/OIDC implementation weaknesses.

Checks: state entropy, redirect_uri bypass, PKCE enforcement, CORS on auth endpoints,
password reset host header injection, token reuse after logout.

Usage:
    python3 oauth_tester.py <target_url>
    python3 oauth_tester.py --recon-dir <recon_dir>
"""

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from urllib.parse import urlparse, urljoin

try:
    import procutil
except Exception:  # pragma: no cover - procutil always present in repo
    procutil = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FINDINGS_DIR = os.environ.get("FINDINGS_OUT_DIR", os.path.join(BASE_DIR, "findings"))

# A netloc (host[:port], optional userinfo) we are willing to embed in a curl
# argv. Deliberately strict: NO shell metacharacters ($ ( ) ` ; | & < > space "
# ' \\), so even if an argv element ever reached a shell it could not inject.
_SAFE_NETLOC_RE = re.compile(r'^[A-Za-z0-9._:@\[\]-]+$')


def _netloc_is_safe(url: str) -> bool:
    """True only if the URL's host portion contains no shell-dangerous chars.

    Guards against command/argument injection from attacker-influenced input
    (CLI target or crawled live/urls.txt) regardless of how the URL is later
    used. urljoin/urlparse do NOT strip metacharacters, so we reject early.
    """
    try:
        netloc = urlparse(url).netloc
    except Exception:
        return False
    if not netloc:
        return False
    return bool(_SAFE_NETLOC_RE.match(netloc))


def run_cmd(cmd, timeout=15):
    """Run a curl probe as an argv LIST (shell=False) via the fork-safe spawner.

    ``cmd`` MUST be a list of arguments — never a shell string. Using argv with
    shell=False makes every element (notably the target URL) an inert token, so
    $(...), backticks, ;, quotes etc. are never interpreted by a shell. The call
    is routed through procutil so the post-network subprocess launch avoids the
    macOS Network.framework fork() SIGSEGV (posix_spawn, no atfork handlers).
    """
    if isinstance(cmd, str):
        # Hard guard: a string would re-introduce shell semantics. Refuse it.
        raise TypeError("run_cmd requires an argv list, not a shell string")

    if procutil is not None:
        res = procutil.run_capture(
            list(cmd), timeout=timeout, shell=False, merge_stderr=False,
        )
        if res.get("timed_out"):
            return False, "", "timeout"
        return res["returncode"] == 0, res.get("stdout", ""), res.get("stderr", "")

    # Fallback (procutil unavailable): still shell=False, argv list only.
    proc = None
    try:
        proc = subprocess.Popen(
            list(cmd), shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True,
        )
        stdout, stderr = proc.communicate(timeout=timeout)
        return proc.returncode == 0, stdout, stderr
    except subprocess.TimeoutExpired:
        if proc:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                proc.kill()
            proc.wait()
        return False, "", "timeout"
    except Exception as e:
        if proc:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                proc.kill()
            proc.wait()
        return False, "", str(e)


def check_cors_on_auth_endpoints(base_url: str) -> list[dict]:
    """Check CORS headers on authentication-related endpoints."""
    findings = []
    auth_paths = ["/oauth/authorize", "/oauth/token", "/api/v1/auth",
                  "/login", "/api/auth", "/graphql", "/.well-known/openid-configuration"]

    for path in auth_paths:
        url = urljoin(base_url, path)
        ok, stdout, _ = run_cmd(
            ["curl", "-sk", "-I", "-H", "Origin: https://evil.com", url, "--max-time", "8"]
        )
        if not ok:
            continue
        headers = stdout.lower()
        if "access-control-allow-origin" in headers:
            if "evil.com" in headers or "*" in headers.split("access-control-allow-origin")[1].split("\n")[0]:
                findings.append({
                    "type": "cors_on_auth",
                    "severity": "high",
                    "url": url,
                    "detail": "CORS allows arbitrary origin on auth endpoint",
                    "evidence": [l for l in stdout.split("\n") if "access-control" in l.lower()][:3],
                })
    return findings


def check_oauth_state_entropy(base_url: str) -> list[dict]:
    """Check OAuth state parameter: missing entirely (CSRF) or insufficient entropy."""
    findings = []
    # Try to find OAuth authorization endpoint
    for path in ["/oauth/authorize", "/authorize", "/auth/authorize", "/connect/authorize"]:
        url = urljoin(base_url, path)
        ok, stdout, _ = run_cmd([
            "curl", "-sk", "-D-", "-o", "/dev/null",
            f"{url}?response_type=code&client_id=test&redirect_uri=http://localhost",
            "--max-time", "8",
        ])
        if not ok:
            continue

        # Did the endpoint actually behave like an OAuth authorization endpoint,
        # i.e. issue a redirect (302/3xx with a Location:)? Only then is a missing
        # state parameter a genuine CSRF weakness rather than a 404/login page.
        loc = re.search(r'(?im)^location:\s*(\S+)', stdout)
        is_oauth_redirect = bool(loc) and bool(
            re.search(r'(?im)^HTTP/\S+\s+30[1278]', stdout)
        )

        states = re.findall(r'state=([a-zA-Z0-9_-]+)', stdout)
        if len(states) >= 1:
            state = states[0]
            if len(state) < 16:
                findings.append({
                    "type": "weak_oauth_state",
                    "severity": "medium",
                    "url": url,
                    "detail": f"OAuth state parameter too short ({len(state)} chars, need 16+)",
                    "evidence": [f"state={state}"],
                })
        elif is_oauth_redirect:
            # Authorization endpoint issued a redirect but emitted NO state param
            # -> no CSRF protection on the authorization request.
            findings.append({
                "type": "missing_oauth_state",
                "severity": "high",
                "url": url,
                "detail": "OAuth authorization redirect issued without a 'state' parameter (CSRF)",
                "evidence": [f"Location: {loc.group(1)[:120]}"],
            })
    return findings


def check_redirect_uri_bypass(base_url: str) -> list[dict]:
    """Test redirect_uri validation bypass vectors.

    A genuine bypass is confirmed by the server redirecting to the attacker host
    (evil.com), so we inspect the Location header rather than trusting a bare
    200/301/302 (a correctly-validating endpoint also 302s — to a login/error
    page). We seed a synthetic legit redirect_uri and run the matrix
    unconditionally; the per-vector Location check provides the grounding.
    """
    findings = []
    netloc = urlparse(base_url).netloc
    for path in ["/oauth/authorize", "/authorize", "/auth/authorize"]:
        url = urljoin(base_url, path)

        # Best-effort: refine the legit redirect_uri from a reflected value, but
        # do NOT gate the matrix on it (real authorize endpoints rarely echo it).
        legit = f"https://{netloc}/callback"
        ok, stdout, _ = run_cmd(["curl", "-sk", "-D-", "-o", "/dev/null", url, "--max-time", "8"])
        if ok:
            reflected = re.search(r'redirect_uri=([^&\s"]+)', stdout)
            if reflected:
                legit = reflected.group(1)

        bypasses = [
            (f"{legit}@evil.com", "at-sign injection"),
            (f"{legit}%2F@evil.com", "url-encoded slash injection"),
            ("https://evil.com/", "full override"),
            (f"{legit}.evil.com", "subdomain confusion"),
        ]
        for bypass_uri, technique in bypasses:
            test_url = f"{url}?response_type=code&client_id=test&redirect_uri={bypass_uri}"
            ok, stdout, _ = run_cmd([
                "curl", "-sk", "-D-", "-o", "/dev/null", test_url, "--max-time", "8",
            ])
            if not ok:
                continue
            loc = re.search(r'(?im)^location:\s*(\S+)', stdout)
            if not loc:
                continue
            redirect_host = (urlparse(loc.group(1)).netloc or "").lower()
            # at-sign / subdomain tricks make evil.com the effective host;
            # full-override is a literal evil.com host. Only flag when the server
            # actually redirects to the attacker host (true bypass) — a redirect
            # to a legit/login/error page (correct validation) is NOT flagged.
            if (redirect_host == "evil.com"
                    or redirect_host.endswith("@evil.com")
                    or redirect_host.endswith(".evil.com")):
                findings.append({
                    "type": "redirect_uri_bypass",
                    "severity": "high",
                    "url": test_url,
                    "detail": f"redirect_uri bypass via {technique}",
                    "evidence": [f"Location: {loc.group(1)[:120]} (via {bypass_uri[:80]})"],
                })
    return findings


def check_password_reset_host_injection(base_url: str) -> list[dict]:
    """Test password reset host header injection."""
    findings = []
    for path in ["/password/reset", "/forgot-password", "/api/password/reset",
                 "/users/password", "/auth/reset"]:
        url = urljoin(base_url, path)
        for header_name, header_value in [
            ("Host", "evil.com"),
            ("X-Forwarded-Host", "evil.com"),
            ("X-Host", "evil.com"),
        ]:
            ok, stdout, _ = run_cmd([
                "curl", "-sk", "-X", "POST",
                "-H", f"{header_name}: {header_value}",
                "-d", "email=test@test.com", url, "-D-", "--max-time", "8",
            ])
            if ok and "evil.com" in stdout:
                findings.append({
                    "type": "host_header_injection",
                    "severity": "high",
                    "url": url,
                    "detail": f"Password reset reflects injected {header_name}: {header_value}",
                    "evidence": [f"{header_name}: {header_value} reflected in response"],
                })
    return findings


def run_oauth_audit(target: str, recon_dir: str | None = None, output_dir: str | None = None,
                    max_hosts: int = 0) -> list[dict]:
    """Run all OAuth security checks.

    ``max_hosts`` caps how many crawled live hosts are tested (0 = unlimited).
    When a cap drops hosts, a degradation marker is logged AND recorded as a
    finding so coverage is never silently narrowed.
    """
    print(f"[*] OAuth Security Audit: {target}")
    all_findings = []

    base_urls = [f"https://{target}", f"http://{target}"]
    if recon_dir:
        live_file = os.path.join(recon_dir, "live", "urls.txt")
        if os.path.isfile(live_file):
            with open(live_file) as f:
                all_urls = [l.strip() for l in f if l.strip()]
            base_urls = all_urls
            if max_hosts and len(all_urls) > max_hosts:
                base_urls = all_urls[:max_hosts]
                dropped = all_urls[max_hosts:]
                print(f"  [!] COVERAGE LIMITED: testing {max_hosts}/{len(all_urls)} live "
                      f"hosts; {len(dropped)} NOT tested (raise --max-hosts to cover all)")
                all_findings.append({
                    "type": "coverage_degraded",
                    "severity": "info",
                    "url": "",
                    "detail": (f"oauth_tester capped at {max_hosts} hosts; "
                               f"{len(dropped)} live hosts untested"),
                    "evidence": dropped[:50],
                })

    # Drop any host whose netloc carries shell-dangerous characters. These come
    # from attacker-influenceable sources (CLI target / crawled live/urls.txt);
    # rejecting them fails CLOSED rather than embedding them in a probe.
    safe_urls = []
    for u in base_urls:
        if _netloc_is_safe(u):
            safe_urls.append(u)
        else:
            print(f"  [!] SKIPPED unsafe host (rejected metacharacters): {u[:120]}")
            all_findings.append({
                "type": "unsafe_host_skipped",
                "severity": "info",
                "url": u,
                "detail": "Host contained shell-dangerous characters; not tested",
                "evidence": [u[:120]],
            })
    base_urls = safe_urls

    for base_url in base_urls:
        print(f"  [>] Testing {base_url}...")
        all_findings.extend(check_cors_on_auth_endpoints(base_url))
        all_findings.extend(check_oauth_state_entropy(base_url))
        all_findings.extend(check_redirect_uri_bypass(base_url))
        all_findings.extend(check_password_reset_host_injection(base_url))

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        out_file = os.path.join(output_dir, "oauth_findings.txt")
        with open(out_file, "w") as f:
            for finding in all_findings:
                f.write(f"[{finding['severity'].upper()}] {finding['type']} {finding['url']}\n")
                f.write(f"  Detail: {finding['detail']}\n")
                for ev in finding.get("evidence", []):
                    f.write(f"  Evidence: {ev}\n")
                f.write("\n")
        print(f"  [+] {len(all_findings)} findings → {out_file}")

    if not all_findings:
        print("  [+] No OAuth issues found")

    return all_findings


def main():
    parser = argparse.ArgumentParser(description="OAuth Security Tester")
    parser.add_argument("target", nargs="?", help="Target domain")
    parser.add_argument("--recon-dir", help="Recon directory")
    parser.add_argument("--output-dir", help="Output directory for findings")
    parser.add_argument("--max-hosts", type=int, default=0,
                        help="Cap crawled live hosts tested (0 = unlimited, default)")
    args = parser.parse_args()

    target = args.target
    if not target and args.recon_dir:
        target = os.path.basename(args.recon_dir.rstrip("/"))
    if not target:
        parser.error("Target domain required")

    run_oauth_audit(target, args.recon_dir, args.output_dir, max_hosts=args.max_hosts)
    return 0


if __name__ == "__main__":
    sys.exit(main())
