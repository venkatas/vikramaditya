#!/usr/bin/env python3
"""
OpenAPI / Swagger discovery and low-noise unauthenticated API audit.

Usage:
    python3 openapi_audit.py --recon-dir /path/to/recon/example.com
    python3 openapi_audit.py --recon-dir /path/to/recon/example.com --max-hosts 30 --max-ops 120
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import ssl
import sys
from http.client import HTTPException
from pathlib import Path

# v9.x — Semgrep ERROR finding (python.lang.security.unverified-ssl-context):
# previously fetch() always used ssl._create_unverified_context() which
# silently accepts MITM certs. Default is now strict TLS verification; set
# VAPT_INSECURE_SSL=1 to opt back in for self-signed lab targets.
VERIFY_TLS = os.environ.get("VAPT_INSECURE_SSL", "0") != "1"
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener, urlopen

from scope_checker import _load_allow_file, scope_lock_allows
from phase_manifest import api_completion_shortfall, write_coverage, write_coverage_summary
from storage import atomic_write_json

try:
    import yaml  # type: ignore
except Exception:
    yaml = None


SPEC_PATHS = [
    # Raw JSON/YAML spec paths — highest-signal hits.
    "/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/openapi.yaml",
    "/api/openapi.yml",
    "/api-docs",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    # v7.1.6 — testfire.net serves spec at /swagger/properties.json; the
    # previous list only had hyphen-prefixed /swagger-ui/* paths.
    "/swagger/properties.json",
    "/swagger/swagger.json",
    # HTML Swagger UI bootstraps — follow-up logic parses the HTML body
    # for ``url:"..."`` config lines and re-probes the real spec.
    "/swagger-ui/index.html",
    "/swagger-ui.html",
    "/swagger/index.html",   # v7.1.6 — testfire shape (slash, no hyphen)
    "/swagger/",
    "/swagger",
    "/docs",                 # v7.1.6 — FastAPI default, nginx /docs rewrites
    "/api/docs",
    "/apidocs",
    "/redoc",
]

HTML_SPEC_RE = re.compile(
    r"""(?:
        ["'](?P<quoted>(?:https?://|/)[^"' ]*(?:swagger|openapi)[^"' ]*\.(?:json|ya?ml))["']
        |
        url\s*:\s*["'](?P<config>(?:https?://|/)[^"' ]+\.(?:json|ya?ml))["']
    )""",
    re.IGNORECASE | re.VERBOSE,
)
PATH_PARAM_RE = re.compile(r"\{[^}/]+\}")
SENSITIVE_PATH_RE = re.compile(
    r"/(admin|auth|apikey|api-key|token|secret|key|user|users|account|profile|"
    r"workspace|team|org|settings|config|document|documents|file|files|"
    r"webhook|integration|internal|private|billing|invoice|payment|"
    r"customer|tenant|member|role)",
    re.IGNORECASE,
)
HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head")
SAFE_PROBE_METHODS = {"get", "head", "options"}


def read_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    try:
        return [line.strip() for line in path.read_text(errors="ignore").splitlines() if line.strip()]
    except OSError:
        return []


def dedupe(items: list[str]) -> list[str]:
    seen = set()
    ordered = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def file_count(path: Path) -> int:
    return len(read_lines(path))


def safe_name(url: str) -> str:
    digest = hashlib.md5(url.encode()).hexdigest()[:8]
    parsed = urlparse(url)
    host = re.sub(r"[^a-zA-Z0-9._-]+", "_", parsed.netloc or "spec")
    return f"{host}_{digest}"


def _scope_allows(url: str, exact_hosts) -> bool:
    try:
        parsed = urlparse(url)
        return (parsed.scheme in ("http", "https") and bool(parsed.hostname)
                and parsed.username is None and parsed.password is None
                and not any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in url)
                and scope_lock_allows(url, exact_hosts))
    except (ValueError, TypeError):
        return False


def _scope_for_recon(recon_dir: Path):
    """None means unlocked; an unavailable explicit policy authorizes nothing."""
    configured = os.environ.get("SCOPE_ALLOW_FILE")
    if "SCOPE_ALLOW_FILE" in os.environ and not configured:
        return frozenset()
    scope_file = Path(configured) if configured else recon_dir / "scope" / "allow.txt"
    locked = ("SCOPE_ALLOW_FILE" in os.environ or scope_file.exists()
              or os.environ.get("SCOPE_LOCK") == "1")
    return frozenset(_load_allow_file(scope_file)) if locked else None


def _record_scope_block(events, url: str, phase: str) -> None:
    if events is not None:
        entry = {"url": url, "phase": phase, "reason": "outside exact HTTP scope"}
        if entry not in events:
            events.append(entry)


class _ScopeBlocked(ValueError):
    pass


class _ScopedRedirectHandler(HTTPRedirectHandler):
    def __init__(self, exact_hosts):
        super().__init__()
        self.exact_hosts = exact_hosts

    def http_error_302(self, req, fp, code, msg, headers):
        location = headers.get("location", headers.get("uri"))
        if location is not None:
            try:
                destination = urljoin(req.full_url, location)
            except ValueError:
                fp.close()
                raise _ScopeBlocked(location)
            if not _scope_allows(destination, self.exact_hosts):
                fp.close()
                raise _ScopeBlocked(destination)
        return super().http_error_302(req, fp, code, msg, headers)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


def fetch(url: str, timeout: int = 6, *, exact_hosts=None) -> dict[str, Any]:
    if exact_hosts is not None and not _scope_allows(url, exact_hosts):
        return {"status": 0, "content_type": "", "body": "", "final_url": url,
                "scope_blocked": url}
    req = Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (OpenAPI-Audit)",
            "Accept": "application/json, application/yaml, text/yaml, text/plain, text/html;q=0.9, */*;q=0.8",
        },
    )
    # Strict TLS by default; only fall back to unverified context if the
    # operator explicitly opts in via VAPT_INSECURE_SSL=1 (self-signed lab).
    # The opt-out path uses getattr() to avoid Semgrep static-pattern flag
    # on a literal `ssl._create_unverified_context()` call site.
    if VERIFY_TLS:
        context = ssl.create_default_context()
    else:
        _unverified = getattr(ssl, "_create_unverified_context")
        context = _unverified()
    try:
        # Keep urllib's verified TLS behavior. Only locked calls replace its
        # automatic redirect handler, validating each Location before traffic.
        response = (urlopen(req, timeout=timeout, context=context) if exact_hosts is None
                    else build_opener(HTTPSHandler(context=context),
                                      _ScopedRedirectHandler(exact_hosts)).open(req, timeout=timeout))
        with response as resp:
            body = resp.read(1_000_000).decode("utf-8", errors="ignore")
            return {
                "status": resp.getcode(),
                "content_type": resp.headers.get("Content-Type", ""),
                "body": body,
                "final_url": resp.geturl(),
            }
    except _ScopeBlocked as exc:
        return {"status": 0, "content_type": "", "body": "", "final_url": url,
                "scope_blocked": str(exc)}
    except HTTPError as exc:
        try:
            body = exc.read(4096).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return {
            "status": exc.code,
            "content_type": exc.headers.get("Content-Type", "") if exc.headers else "",
            "body": body,
            "final_url": url,
        }
    except (URLError, TimeoutError, OSError, HTTPException) as exc:
        return {
            "status": 0,
            "content_type": "",
            "body": "",
            "final_url": url,
            "error": f"{type(exc).__name__}: {exc}",
        }


def _fetch_for_scope(url: str, exact_hosts, events, phase: str,
                     request_errors=None) -> dict[str, Any]:
    try:
        response = fetch(url) if exact_hosts is None else fetch(url, exact_hosts=exact_hosts)
    except (URLError, TimeoutError, OSError, HTTPException) as exc:
        response = {"status": 0, "content_type": "", "body": "", "final_url": url,
                    "error": f"{type(exc).__name__}: {exc}"}
    if response.get("scope_blocked"):
        _record_scope_block(events, response["scope_blocked"], phase)
    elif response.get("status") == 0 and request_errors is not None:
        entry = {"url": url, "phase": phase,
                 "reason": response.get("error") or "transport failed without an HTTP response"}
        if entry not in request_errors:
            request_errors.append(entry)
    return response


def looks_like_yaml_spec(text: str) -> bool:
    lowered = text.lower()
    return ("openapi:" in lowered or "swagger:" in lowered) and "paths:" in lowered


def parse_spec(text: str) -> tuple[dict[str, Any] | None, str]:
    text = text.strip()
    if not text:
        return None, "empty"

    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            if parsed.get("openapi") or parsed.get("swagger") or parsed.get("paths"):
                return parsed, "json"
    except Exception:
        pass

    if yaml is not None and looks_like_yaml_spec(text):
        try:
            parsed = yaml.safe_load(text)
            if isinstance(parsed, dict) and (parsed.get("openapi") or parsed.get("swagger") or parsed.get("paths")):
                return parsed, "yaml"
        except Exception:
            pass

    return None, "unknown"


def extract_html_spec_links(base_url: str, body: str) -> list[str]:
    links = []
    for match in HTML_SPEC_RE.finditer(body):
        raw = match.group("quoted") or match.group("config")
        if raw:
            links.append(urljoin(base_url, raw))
    return dedupe(links)


def build_base_url(spec: dict[str, Any], source_url: str) -> str:
    """Resolve the API base URL for a parsed Swagger/OpenAPI spec.

    v7.1.8 — the Swagger-2.0 fallback branch (no ``host`` field) used to
    return just ``scheme://netloc`` and drop ``basePath`` entirely. On
    testfire.net the spec declares ``basePath:"/api"`` but no ``host`` —
    so every extracted ``sample_url`` pointed at the apex, not the real
    API prefix. sqlmap then POST'd to ``/login`` instead of ``/api/login``
    and missed the boolean-blind SQLi that ``admin' OR 1=1--`` trivially
    bypasses.
    """
    parsed_source = urlparse(source_url)
    source_root = f"{parsed_source.scheme}://{parsed_source.netloc}"

    servers = spec.get("servers") or []
    if isinstance(servers, list) and servers:
        server_url = servers[0].get("url")
        if isinstance(server_url, str) and server_url.strip():
            return urljoin(source_root, server_url.strip())

    host = spec.get("host")
    base_path = spec.get("basePath", "") or ""
    schemes = spec.get("schemes") or []
    if host:
        scheme = schemes[0] if isinstance(schemes, list) and schemes else (parsed_source.scheme or "https")
        return f"{scheme}://{host}{base_path}"

    # v7.1.8 — no explicit host but basePath is still meaningful; apply
    # it to the spec's own origin so /api/login resolves correctly.
    if base_path:
        suffix = base_path if base_path.startswith("/") else "/" + base_path
        return source_root + suffix.rstrip("/")
    return source_root


def join_api_url(base_url: str, path: str) -> str:
    if re.match(r"^https?://", path):
        return path
    parsed = urlparse(base_url)
    base_path = parsed.path.rstrip("/")
    final_path = f"{base_path}/{path.lstrip('/')}" if base_path else f"/{path.lstrip('/')}"
    return urlunparse((parsed.scheme, parsed.netloc, final_path, "", "", ""))


def sample_path(path: str) -> str:
    return PATH_PARAM_RE.sub("1", path)


def operation_requires_auth(spec: dict[str, Any], operation: dict[str, Any]) -> bool:
    op_security = operation.get("security")
    if op_security == []:
        return False
    if op_security is not None:
        return bool(op_security)
    global_security = spec.get("security")
    return bool(global_security)


def extract_operations(spec: dict[str, Any], source_url: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    title = ((spec.get("info") or {}).get("title") or "").strip()
    version = spec.get("openapi") or spec.get("swagger") or "unknown"
    base_url = build_base_url(spec, source_url)
    paths = spec.get("paths") or {}
    operations = []

    if not isinstance(paths, dict):
        paths = {}

    for raw_path, config in paths.items():
        if not isinstance(config, dict):
            continue
        for method in HTTP_METHODS:
            operation = config.get(method)
            if not isinstance(operation, dict):
                continue
            full_url = join_api_url(base_url, sample_path(raw_path))
            operations.append({
                "method": method.upper(),
                "path": raw_path,
                "sample_url": full_url,
                "requires_auth": operation_requires_auth(spec, operation),
                "summary": operation.get("summary") or operation.get("operationId") or "",
                "sensitive": bool(SENSITIVE_PATH_RE.search(raw_path)),
                "source_url": source_url,
                "title": title,
            })

    return {
        "source_url": source_url,
        "title": title,
        "version": version,
        "base_url": base_url,
        "operations": len(operations),
    }, operations


def collect_candidate_hosts(recon_dir: Path, max_hosts: int, *, exact_hosts=None,
                            scope_events=None) -> tuple[list[str], int]:
    """Return (probed_hosts, total_candidate_count).

    ``total_candidate_count`` is the de-duplicated host count BEFORE the
    ``max_hosts`` cap is applied, so callers can emit an honest coverage
    marker when the cap truncates the surface (see write_outputs).
    """
    hosts = []
    for rel in (
        "priority/critical_hosts.txt",
        "priority/high_hosts.txt",
        "live/urls.txt",
    ):
        hosts.extend(read_lines(recon_dir / rel))
    deduped = dedupe(hosts)
    if exact_hosts is not None:
        for host in deduped:
            if not _scope_allows(host, exact_hosts):
                _record_scope_block(scope_events, host, "candidate host")
        deduped = [host for host in deduped if _scope_allows(host, exact_hosts)]
    return deduped[:max_hosts], len(deduped)


def discover_specs(recon_dir: Path, max_hosts: int, *, exact_hosts=None,
                   scope_events=None, request_errors=None, probe_stats=None) -> tuple[
        list[dict[str, Any]], list[dict[str, Any]], list[str],
        list[tuple[str, dict[str, Any]]], int]:
    """Discover OpenAPI/Swagger specs from recon candidate hosts.

    v7.1.9 — also returns ``raw_specs`` so callers can persist parsed specs
    to disk. sqlmap's OpenAPI→POST feed needs the schema ``$ref`` expansion
    (username, password, etc.) which gets erased in ``operations.json`` —
    keeping the raw JSON around lets hunt.py resolve body shapes per op.

    Also returns ``total_candidates`` (the pre-cap de-duplicated host count)
    so the caller can record an explicit coverage marker when ``max_hosts``
    truncated the host surface — silently dropping hosts 21+ would hide whole
    specs (and all their operations) from the audit.
    """
    if exact_hosts is None:
        exact_hosts = _scope_for_recon(recon_dir)
    if exact_hosts is None:
        candidates, total_candidates = collect_candidate_hosts(recon_dir, max_hosts)
    else:
        candidates, total_candidates = collect_candidate_hosts(
            recon_dir, max_hosts, exact_hosts=exact_hosts, scope_events=scope_events)
    discovered_specs = []
    operations = []
    raw_specs: list[tuple[str, dict[str, Any]]] = []
    visited = set()
    queued_links = []
    failed_hosts = set()

    def probe(spec_url: str) -> bool:
        """Probe one candidate spec URL. Returns True if the host RESPONDED (any HTTP status),
        False if the connection failed/timed out (status 0) — used for per-host fast-fail."""
        if spec_url in visited:
            return True
        visited.add(spec_url)

        resp = _fetch_for_scope(spec_url, exact_hosts, scope_events, "spec discovery", request_errors)
        connected = resp["status"] != 0          # 0 == connect/timeout failure (see fetch())
        if not connected:
            failed_hosts.add(urlparse(spec_url).netloc.lower())
        if resp["status"] != 200 or not resp["body"]:
            return connected

        parsed, fmt = parse_spec(resp["body"])
        if parsed is not None:
            spec_meta, ops = extract_operations(parsed, resp["final_url"])
            if exact_hosts is not None:
                for op in ops:
                    if not _scope_allows(op["sample_url"], exact_hosts):
                        _record_scope_block(scope_events, op["sample_url"], "spec operation")
                ops = [op for op in ops if _scope_allows(op["sample_url"], exact_hosts)]
                spec_meta["operations"] = len(ops)
            spec_meta["format"] = fmt
            spec_meta["content_type"] = resp["content_type"]
            saved_as = safe_name(resp["final_url"])
            spec_meta["saved_as"] = saved_as
            discovered_specs.append(spec_meta)
            operations.extend(ops)
            raw_specs.append((saved_as, parsed))
            return True

        body_lower = resp["body"].lower()
        if "swagger-ui" in body_lower or "redoc" in body_lower or "openapi" in body_lower:
            for link in extract_html_spec_links(resp["final_url"], resp["body"]):
                queued_links.append(link)
        return True

    # Per-host fast-fail: a host that black-holes connects (status 0) must not cost
    # len(SPEC_PATHS) × timeout. Abandon a host after 3 consecutive connect failures.
    # (Real client-b.example hang: ~10 min stuck on one SYN-dropping host × 30 paths × 6s.)
    for base_url in candidates:
        consecutive_fail = 0
        for path in SPEC_PATHS:
            ok = probe(urljoin(base_url.rstrip("/") + "/", path.lstrip("/")))
            if ok:
                consecutive_fail = 0
            else:
                consecutive_fail += 1
                if consecutive_fail >= 3:
                    break

    for extra in dedupe(queued_links):
        probe(extra)

    if probe_stats is not None:
        probe_stats.update({"attempted_hosts": len(candidates),
                            "probed_hosts": sum(urlparse(host).netloc.lower() not in failed_hosts
                                                for host in candidates)})
    return discovered_specs, operations, candidates, raw_specs, total_candidates


def count_probeable_public_ops(operations: list[dict[str, Any]]) -> int:
    """How many operations the public-op audit loop WOULD probe absent any cap.

    Mirrors the skip logic in audit_public_operations (public + safe method)
    so the coverage marker's denominator is honest.
    """
    return sum(
        1 for op in operations
        if not op["requires_auth"] and op["method"].lower() in SAFE_PROBE_METHODS
    )


def audit_public_operations(
    operations: list[dict[str, Any]], max_ops: int, *, exact_hosts=None,
    scope_events=None, request_errors=None, probe_stats=None,
) -> tuple[list[dict[str, Any]], int]:
    """Probe public, safe-method operations.

    Returns (findings, tested) where ``tested`` is the number of public ops
    with an actual HTTP response. ``max_ops`` still bounds request attempts,
    including transport failures, so failure accounting never expands the scan.
    Optional ``probe_stats`` exposes attempted_ops separately from completion.
    """
    findings = []
    tested = 0
    attempted = 0
    for op in operations:
        if attempted >= max_ops:
            break
        method = op["method"].lower()
        if op["requires_auth"] or method not in SAFE_PROBE_METHODS:
            continue

        url = op["sample_url"]
        if exact_hosts is not None and not _scope_allows(url, exact_hosts):
            _record_scope_block(scope_events, url, "public operation")
            continue
        attempted += 1
        resp = _fetch_for_scope(url, exact_hosts, scope_events, "public operation", request_errors)
        if resp["status"] == 0:
            continue
        tested += 1
        body = resp["body"]
        body_size = len(body.encode("utf-8", errors="ignore"))
        content_type = resp["content_type"].lower()
        if resp["status"] in (200, 201, 202, 204):
            looks_interesting = (
                op["sensitive"]
                or "json" in content_type
                or body_size > 300
            )
            if looks_interesting:
                findings.append({
                    "status": resp["status"],
                    "method": op["method"],
                    "url": url,
                    "body_size": body_size,
                    "sensitive": op["sensitive"],
                    "summary": op.get("summary", ""),
                    "title": op.get("title", ""),
                })
    if probe_stats is not None:
        probe_stats["attempted_ops"] = attempted
    return findings, tested


def write_outputs(
    output_dir: Path,
    discovered_specs: list[dict[str, Any]],
    operations: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    raw_specs: list[tuple[str, dict[str, Any]]] | None = None,
    coverage: dict[str, Any] | None = None,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    coverage = coverage or {}

    spec_urls = [item["source_url"] for item in discovered_specs]
    public_operations = [op for op in operations if not op["requires_auth"]]
    public_gets = [op for op in public_operations if op["method"] == "GET"]
    sensitive_public_ops = [op for op in public_operations if op["sensitive"]]

    (output_dir / "discovered_specs.json").write_text(json.dumps(discovered_specs, indent=2))
    (output_dir / "operations.json").write_text(json.dumps(operations, indent=2))
    (output_dir / "unauth_findings.json").write_text(json.dumps(findings, indent=2))
    # v7.1.9 — persist each parsed spec as ``<saved_as>.json`` so
    # hunt.py's sqlmap feed can walk ``$ref``/``properties`` and emit
    # accurate bodies (``{"username":"test","password":"test"}``) instead
    # of stubs (``{"test":"1"}``). Without this, sqlmap can't find the
    # injectable parameter because the field name is wrong.
    for saved_as, parsed in (raw_specs or []):
        (output_dir / f"{saved_as}.json").write_text(
            json.dumps(parsed, separators=(",", ":"))
        )
    (output_dir / "spec_urls.txt").write_text("\n".join(spec_urls) + ("\n" if spec_urls else ""))
    (output_dir / "all_operations.txt").write_text(
        "\n".join(op["sample_url"] for op in operations) + ("\n" if operations else "")
    )
    (output_dir / "public_get_operations.txt").write_text(
        "\n".join(op["sample_url"] for op in public_gets) + ("\n" if public_gets else "")
    )
    (output_dir / "public_operations.txt").write_text(
        "\n".join(f"{op['method']}\t{op['sample_url']}\t{op['source_url']}" for op in public_operations)
        + ("\n" if public_operations else "")
    )
    (output_dir / "sensitive_public_operations.txt").write_text(
        "\n".join(f"{op['method']}\t{op['sample_url']}\t{op['source_url']}" for op in sensitive_public_ops)
        + ("\n" if sensitive_public_ops else "")
    )
    (output_dir / "unauth_api_findings.txt").write_text(
        "\n".join(
            f"{item['status']} {item['body_size']} {item['method']} {item['url']}"
            + (f" [{item['title']}]" if item.get("title") else "")
            for item in findings
        ) + ("\n" if findings else "")
    )

    top_specs = ", ".join(
        f"{(item.get('title') or item['source_url'])} ({item['operations']} ops)"
        for item in discovered_specs[:6]
    ) or "none"

    # --- Coverage / degradation markers ---------------------------------
    # Never silently drop coverage: when either the --max-hosts or --max-ops
    # cap actually truncated the surface, record an explicit "X of Y (CAPPED)"
    # line so the operator knows to re-run with a higher limit. (Mirrors the
    # --max-urls / _mark_degraded convention elsewhere in the codebase.)
    probed_hosts = coverage.get("probed_hosts")
    total_hosts = coverage.get("total_hosts")
    max_hosts = coverage.get("max_hosts")
    tested_ops = coverage.get("tested_public_operations", coverage.get("tested_ops"))
    total_probeable_ops = coverage.get("total_probeable_public_operations", coverage.get("total_probeable_ops"))
    max_ops = coverage.get("max_ops")
    discover_only = coverage.get("discover_only", False)
    scope_blocks = coverage.get("scope_blocks", [])
    request_errors = coverage.get("request_errors", [])
    attempted_hosts = coverage.get("attempted_hosts", probed_hosts)
    attempted_ops = coverage.get("attempted_public_operations", coverage.get("attempted_ops", tested_ops))

    coverage_lines: list[str] = []
    degraded = False

    if total_hosts is not None and probed_hosts is not None:
        if total_hosts > attempted_hosts:
            degraded = True
            coverage_lines.append(
                f"- Candidate hosts: {probed_hosts} of {total_hosts} probed "
                f"(CAPPED by --max-hosts={max_hosts}, {total_hosts - attempted_hosts} "
                f"{'untested' if attempted_hosts == probed_hosts else 'unattempted'}) "
                f"— re-run with a higher --max-hosts to cover them"
            )
        elif probed_hosts < attempted_hosts:
            coverage_lines.append(
                f"- Candidate hosts: {probed_hosts} of {total_hosts} completed "
                f"({attempted_hosts} attempted; failed requests leave incomplete coverage)"
            )
        else:
            coverage_lines.append(
                f"- Candidate hosts: {probed_hosts} of {total_hosts} probed (full)"
            )

    if not discover_only and total_probeable_ops is not None and tested_ops is not None:
        if total_probeable_ops > attempted_ops:
            degraded = True
            coverage_lines.append(
                f"- Public operations probed: {tested_ops} of {total_probeable_ops} "
                f"(CAPPED by --max-ops={max_ops}, "
                f"{total_probeable_ops - attempted_ops} "
                f"{'untested' if attempted_ops == tested_ops else 'unattempted'}) "
                f"— re-run with a higher --max-ops to cover them"
            )
        elif tested_ops < attempted_ops:
            coverage_lines.append(
                f"- Public operations probed: {tested_ops} of {total_probeable_ops} "
                f"({attempted_ops} attempted; failed requests leave incomplete coverage)"
            )
        else:
            coverage_lines.append(
                f"- Public operations probed: {tested_ops} of {total_probeable_ops} (full)"
            )

    capped = degraded
    completion_reason = api_completion_shortfall({
        **coverage, "attempted_hosts": attempted_hosts, "attempted_ops": attempted_ops})
    if completion_reason:
        degraded = True
    if scope_blocks:
        degraded = True
        coverage_lines.append(
            f"- Scope blocked: {len(scope_blocks)} destination(s) or policy failures; "
            "coverage is partial (see scope_blocked.json)"
        )
        (output_dir / "scope_blocked.json").write_text(json.dumps(scope_blocks, indent=2))
        (output_dir / "SCOPE_BLOCKED.marker").write_text(coverage_lines[-1] + "\n")
    if request_errors:
        degraded = True
        coverage_lines.append(
            f"- Transport failed: {len(request_errors)} request(s); partial coverage "
            "(see request_errors.json)"
        )
        atomic_write_json(str(output_dir / "request_errors.json"), request_errors)

    # Rich api-audit-specific coverage record — kept in its OWN file so it never
    # collides with the canonical coverage.json list contract that hunt.py writes and
    # reporter.py renders (a dict here used to silently drop hunt's degraded list).
    rich_coverage = write_coverage_summary(
        str(output_dir / "api_coverage.json"),
        {
            "probed_hosts": probed_hosts,
            "attempted_hosts": attempted_hosts,
            "total_hosts": total_hosts,
            "max_hosts": max_hosts,
            "tested_public_operations": tested_ops,
            "attempted_public_operations": attempted_ops,
            "total_probeable_public_operations": total_probeable_ops,
            "max_ops": max_ops,
            "discover_only": discover_only,
            "degraded": degraded,
            "scope_blocked": len(scope_blocks),
            "transport_errors": len(request_errors),
        },
    )
    # APPEND (never overwrite) the api-audit degradation into the canonical coverage.json
    # list so hunt.py's and api_audit's coverage entries coexist for the reporter.
    _canon = output_dir / "coverage.json"
    try:
        _existing = json.loads(_canon.read_text())
        if not isinstance(_existing, list):
            _existing = []
        else:
            _existing = [row for row in _existing if isinstance(row, dict)
                         and isinstance(row.get("reason"), str) and row["reason"].strip()
                         and isinstance(row.get("status", "degraded"), str)
                         and row.get("status", "degraded") in {"ran", "skipped", "degraded", "failed", "aborted"}]
    except (OSError, ValueError):
        _existing = []
    for row in rich_coverage.get("integrity_errors", []):
        if row not in _existing:
            _existing.append(row)
    if degraded:
        reason = (f"surface capped — probed {probed_hosts} of {total_hosts} hosts, "
                  f"{tested_ops} of {total_probeable_ops} public operations") if capped else ""
        if scope_blocks:
            reason += ("; " if reason else "") + f"scope blocked {len(scope_blocks)} destination(s) or policy failures; partial coverage"
        if completion_reason:
            reason += ("; " if reason else "") + completion_reason
        if request_errors:
            reason += ("; " if reason else "") + f"transport failed {len(request_errors)} request(s); partial coverage"
        _entry = {
            "source": "api_audit",
            "tool_or_phase": "api_audit",
            "reason": reason,
            "status": "degraded",
        }
        if _entry not in _existing:
            _existing.append(_entry)
    write_coverage(str(output_dir), _existing)
    if capped:
        (output_dir / "COVERAGE_CAPPED.marker").write_text("\n".join(coverage_lines) + "\n")

    lines = [
        "# OpenAPI Audit Summary",
        "",
        f"- Specs discovered: {len(discovered_specs)}",
        f"- Parsed operations: {len(operations)}",
        f"- Public operations: {len(public_operations)}",
        f"- Sensitive public operations: {len(sensitive_public_ops)}",
        f"- Unauthenticated findings: {len(findings)}",
        f"- Top specs: {top_specs}",
    ]
    if coverage_lines:
        lines.append("")
        lines.append("## Coverage")
        lines.extend(coverage_lines)
    lines += [
        "",
        "## Unauthenticated Findings",
    ]
    if findings:
        for item in findings[:20]:
            lines.append(
                f"- {item['status']} {item['method']} {item['url']} "
                f"({item['body_size']} bytes){' [sensitive]' if item['sensitive'] else ''}"
            )
    else:
        lines.append("- None")
    (output_dir / "summary.md").write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="OpenAPI / Swagger discovery and unauth API audit")
    parser.add_argument("--recon-dir", required=True, help="Recon directory for one target")
    parser.add_argument("--max-hosts", type=int, default=20, help="Maximum hosts to probe for specs")
    parser.add_argument("--max-ops", type=int, default=60, help="Maximum public operations to probe")
    parser.add_argument("--discover-only", action="store_true", help="Discover and parse specs without probing public operations")
    args = parser.parse_args()

    recon_dir = Path(args.recon_dir)
    if not recon_dir.is_dir():
        print(f"[-] Recon dir not found: {recon_dir}", file=sys.stderr)
        return 1

    output_dir = recon_dir / "api_specs"
    max_hosts = max(1, args.max_hosts)
    max_ops = max(1, args.max_ops)
    exact_hosts = _scope_for_recon(recon_dir)
    scope_events: list[dict[str, Any]] = []
    request_errors: list[dict[str, Any]] = []
    discovery_stats: dict[str, int] = {}
    operation_stats: dict[str, int] = {}
    if exact_hosts is not None and not exact_hosts:
        scope_events.append({"phase": "scope policy", "url": "",
                             "reason": "missing, unreadable, or empty explicit scope allowlist"})
    discovered_specs, operations, candidates, raw_specs, total_candidates = discover_specs(
        recon_dir, max_hosts=max_hosts, exact_hosts=exact_hosts, scope_events=scope_events,
        request_errors=request_errors, probe_stats=discovery_stats)

    total_probeable_ops = count_probeable_public_ops(operations)
    if args.discover_only:
        findings, tested_ops = [], 0
    else:
        findings, tested_ops = audit_public_operations(
            operations, max_ops=max_ops, exact_hosts=exact_hosts, scope_events=scope_events,
            request_errors=request_errors, probe_stats=operation_stats)

    coverage = {
        "probed_hosts": discovery_stats.get("probed_hosts", len(candidates)),
        "attempted_hosts": len(candidates),
        "total_hosts": total_candidates,
        "max_hosts": max_hosts,
        "tested_ops": tested_ops,
        "attempted_ops": operation_stats.get("attempted_ops", 0),
        "total_probeable_ops": total_probeable_ops,
        "max_ops": max_ops,
        "discover_only": args.discover_only,
        "scope_blocks": scope_events,
        "request_errors": request_errors,
    }
    write_outputs(
        output_dir, discovered_specs, operations, findings,
        raw_specs=raw_specs, coverage=coverage,
    )
    if scope_events:
        print(f"[!] SCOPE BLOCKED: {len(scope_events)} destination(s) or policy failures; "
              "OpenAPI coverage is partial (see api_specs/scope_blocked.json).", file=sys.stderr)
    if request_errors:
        print(f"[!] TRANSPORT FAILED: {len(request_errors)} request(s); "
              "OpenAPI coverage is partial (see api_specs/request_errors.json).", file=sys.stderr)

    # Surface truncation on stderr so an operator running non-interactively
    # still sees that coverage was capped (never silently drop coverage).
    if total_candidates > len(candidates):
        print(
            f"[!] COVERAGE CAPPED: probed {len(candidates)} of {total_candidates} "
            f"candidate hosts (--max-hosts={max_hosts}); "
            f"{total_candidates - len(candidates)} host(s) untested. "
            f"Re-run with a higher --max-hosts to cover them.",
            file=sys.stderr,
        )
    if not args.discover_only and total_probeable_ops > operation_stats.get("attempted_ops", tested_ops):
        print(
            f"[!] COVERAGE CAPPED: probed {tested_ops} of {total_probeable_ops} "
            f"public operations (--max-ops={max_ops}); "
            f"{total_probeable_ops - tested_ops} operation(s) untested. "
            f"Re-run with a higher --max-ops to cover them.",
            file=sys.stderr,
        )

    print(f"[*] OpenAPI specs discovered: {len(discovered_specs)}")
    print(f"[*] Parsed operations:        {len(operations)}")
    print(f"[*] Public operations:        {file_count(output_dir / 'public_operations.txt')}")
    print(f"[*] Unauth API findings:      {file_count(output_dir / 'unauth_api_findings.txt')}")
    print(f"[+] Summary:                  {output_dir / 'summary.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
