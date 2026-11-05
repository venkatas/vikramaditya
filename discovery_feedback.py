"""Promote scoped Ferox response URLs into the recon discovery corpus.

This is a file-only discovery handoff, not vulnerability validation. It never
requests a URL, follows a redirect, or treats an authentication/catchall response
as a discovered application page.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from scope_checker import _load_allow_file, scope_lock_allows
from storage import atomic_write_text


_JS_SUFFIX = re.compile(r"\.(?:js|mjs|cjs)$", re.I)
_HTML_SUFFIX = re.compile(r"\.(?:html?|xhtml|aspx?|jsp|jspx|php\d*|cgi|cfm)$", re.I)
_BINARY_SUFFIX = re.compile(
    r"\.(?:png|jpe?g|gif|webp|avif|svg|ico|css|map|woff2?|ttf|eot|otf|"
    r"pdf|zip|gz|tar|7z|rar|mp[34]|wav|ogg|webm|mov|avi|exe|dmg|apk|ipa)$", re.I)
_API_PATH = re.compile(r"/(?:api|graphql|swagger|openapi)(?:/|$|\.(?:json|ya?ml)$)", re.I)


def normalize_url(value: object) -> str | None:
    """Normalize HTTP authority/root/fragment aliases without rewriting queries.

    Reject whitespace, backslashes, credentials, encoded authorities and malformed
    ports before using the same exact-host matcher as guarded network paths.
    """
    if not isinstance(value, str) or not value:
        return None
    if any(ord(char) <= 32 or ord(char) == 127 or char == "\\" for char in value):
        return None
    try:
        parsed = urlsplit(value)
        if (parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or "%" in parsed.netloc or parsed.netloc.endswith(":")):
            return None
        host = parsed.hostname.lower().rstrip(".")
        port = parsed.port
        if not host or (port is not None and not 1 <= port <= 65535):
            return None
        # Bracket IPv6 literals; DNS names normalize through the IDNA codec.
        authority = f"[{ipaddress.IPv6Address(host)}]" if ":" in host else host.encode("idna").decode("ascii")
        if ":" not in host and not re.fullmatch(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*", authority):
            return None
        if port is not None and (parsed.scheme.lower(), port) not in {("http", 80), ("https", 443)}:
            authority += f":{port}"
        return urlunsplit((parsed.scheme.lower(), authority, parsed.path or "/", parsed.query, ""))
    except (ValueError, UnicodeError):
        return None


def _validated_authorities(hosts) -> set[str]:
    if isinstance(hosts, (str, bytes)):
        raise ValueError("exact scope must be a collection of host authorities")
    result = set()
    for value in hosts:
        if not isinstance(value, str):
            raise ValueError("exact scope must contain host authorities")
        value = value.strip()
        if not value or re.search(r"[\s/@?#\\%*]", value):
            raise ValueError("invalid exact-host scope authority")
        candidate = normalize_url(f"https://{value}")
        if candidate is None:
            raise ValueError("invalid exact-host scope authority")
        parsed = urlsplit(candidate)
        # Keep explicit ports in the authorization set, including default ones:
        # the shared matcher determines their actual authorization semantics.
        result.add(value.lower().rstrip("."))
        if parsed.path != "/" or parsed.query:
            raise ValueError("exact scope must contain authorities, not paths")
    if not result:
        raise ValueError("missing or empty exact-host scope authority")
    return result


def _scope_policy(recon_dir: Path, *, target, scope_lock, exact_hosts, allow_file):
    persisted = recon_dir / "scope" / "allow.txt"
    selected_file = Path(allow_file or os.environ.get("SCOPE_ALLOW_FILE") or persisted)
    locked = (scope_lock or exact_hosts is not None or allow_file is not None
              or bool(os.environ.get("SCOPE_ALLOW_FILE")) or persisted.exists()
              or os.environ.get("SCOPE_LOCK") == "1")
    if locked:
        authority = exact_hosts if exact_hosts is not None else _load_allow_file(str(selected_file))
        hosts = _validated_authorities(authority)
        return lambda url: scope_lock_allows(url, hosts)
    if not isinstance(target, str):
        raise ValueError("target authority required for unlocked discovery feedback")
    target_url = normalize_url(target if "://" in target else f"https://{target}")
    if target_url is None:
        raise ValueError("invalid target authority for discovery feedback")
    target_parts = urlsplit(target_url)
    if target_parts.path != "/" or target_parts.query:
        raise ValueError("target must be a host authority")
    host = target_parts.hostname
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    def within_target(url):
        parsed = urlsplit(url)
        same_host = parsed.hostname == host
        descendant = not is_ip and parsed.hostname.endswith("." + host)
        port_matches = target_parts.port is None or parsed.port == target_parts.port
        return (same_host or descendant) and port_matches

    return within_target


def _response_categories(row: dict, url: str) -> set[str]:
    if row.get("type") != "response" or str(row.get("method", "GET")).upper() != "GET":
        return set()
    status = row.get("status")
    if isinstance(status, bool):
        return set()
    if isinstance(status, str) and status.isdigit():
        status = int(status)
    if not isinstance(status, int) or not 200 <= status < 300 or row.get("wildcard"):
        return set()
    parsed = urlsplit(url)
    headers = row.get("headers") or {}
    if not isinstance(headers, dict):
        return set()
    mime = next((str(value).lower().split(";", 1)[0].strip()
                 for name, value in headers.items() if str(name).lower() == "content-type"), "")
    if (_BINARY_SUFFIX.search(parsed.path)
            or mime.startswith(("image/", "audio/", "video/", "font/"))
            or mime in {"text/css", "application/pdf", "application/octet-stream", "application/zip"}):
        return set()
    categories = set()
    if (_JS_SUFFIX.search(parsed.path) and mime in {"", "text/plain"}) or mime in {
            "application/javascript", "text/javascript", "application/ecmascript", "text/ecmascript",
            "application/x-javascript", "text/x-javascript"}:
        categories.add("js")
    if mime in {"text/html", "application/xhtml+xml"} or (not mime and (
            _HTML_SUFFIX.search(parsed.path) or parsed.path.endswith("/")
            or "." not in parsed.path.rsplit("/", 1)[-1])):
        categories.add("html")
    if parsed.query:
        categories.add("parameter")
    if _API_PATH.search(parsed.path) or mime == "application/json" or mime.endswith("+json"):
        categories.add("api")
    return categories


def _merge_lines(path: Path, candidates: list[str]) -> list[str]:
    """Preserve existing entries/order and atomically append genuinely new URLs."""
    existing = path.read_text(encoding="utf-8", errors="replace").splitlines() if path.exists() else []
    seen = {normalize_url(line.strip()) or line.strip() for line in existing if line.strip()}
    added = []
    for url in candidates:
        if url not in seen:
            seen.add(url)
            added.append(url)
    if added:
        kept = [line for line in existing if line.strip()]
        atomic_write_text(str(path), "\n".join(kept + added) + "\n")
    return added


def merge_ferox_discoveries(recon_dir, response_file=None, *, target=None,
                          scope_lock=False, exact_hosts=None, allow_file=None) -> dict:
    """Merge successful scoped discovery responses into downstream URL inputs.

    The caller should mark ``errors`` as incomplete coverage and may revisit
    requested dependent phases using the returned ``added_*`` URL lists. No
    existing corpus is modified when authoritative scope is unavailable.
    """
    recon_dir = Path(recon_dir)
    artifact = Path(response_file) if response_file is not None else recon_dir / "api" / "feroxbuster.json"
    result = {"changed": False, "accepted_urls": [], "added_urls": [],
              "added_html_urls": [], "added_js_urls": [], "added_parameter_urls": [],
              "added_api_urls": [], "rejected_count": 0, "errors": [], "counts": {}}
    try:
        allows = _scope_policy(recon_dir, target=target, scope_lock=scope_lock,
                               exact_hosts=exact_hosts, allow_file=allow_file)
        lines = artifact.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, ValueError, TypeError) as exc:
        result["errors"].append(str(exc))
        return result
    accepted: dict[str, set[str]] = {}
    for index, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            result["errors"].append(f"invalid Ferox JSON at line {index}")
            continue
        if not isinstance(row, dict):
            result["errors"].append(f"unexpected Ferox JSON record at line {index}")
            continue
        if row.get("type") == "error":
            result["errors"].append(f"Ferox reported an error record at line {index}")
            continue
        if row.get("type") != "response":
            continue
        url = normalize_url(row.get("url"))
        if url is None or not allows(url):
            result["rejected_count"] += 1
            continue
        # Never use a response obtained by crossing the authorized boundary as
        # a seed, even if another URL field names an otherwise allowed host.
        related = [normalize_url(row[key]) for key in ("final_url", "original_url") if row.get(key)]
        if any(item is None or not allows(item) for item in related):
            result["rejected_count"] += 1
            continue
        categories = _response_categories(row, url)
        if not categories:
            result["rejected_count"] += 1
            continue
        accepted.setdefault(url, set()).update(categories)
    result["accepted_urls"] = list(accepted)
    urls_dir = recon_dir / "urls"
    try:
        result["added_urls"] = _merge_lines(urls_dir / "all.txt", list(accepted))
        for category, name in (("html", "discovered_html.txt"), ("js", "js_files.txt"), ("parameter", "with_params.txt"),
                               ("api", "api_endpoints.txt")):
            values = [url for url, kinds in accepted.items() if category in kinds]
            result[f"added_{category}_urls"] = _merge_lines(urls_dir / name, values)
    except OSError as exc:
        result["errors"].append(f"could not persist discovery feedback: {exc}")
    result["changed"] = any(result[key] for key in (
        "added_urls", "added_html_urls", "added_js_urls", "added_parameter_urls", "added_api_urls"))
    result["counts"] = {key: len(result[key]) for key in (
        "accepted_urls", "added_urls", "added_html_urls", "added_js_urls", "added_parameter_urls", "added_api_urls")}
    return result
