#!/usr/bin/env python3
"""tls_impersonation.py — JA3/JA4 TLS ClientHello + HTTP/2 fingerprint impersonation.

Confirmed gap: agent_http.py/hunt.py's Python-level HTTP calls use the stock Python
TLS stack with zero fingerprint spoofing, so a Cloudflare/Akamai/F5-fronted
enterprise perimeter can 403 a plain httpx probe outright regardless of header
correctness. Wraps curl_cffi (MIT) for browser-matched TLS+HTTP2 fingerprints;
degrades gracefully to stock httpx if curl_cffi's native wheel is unavailable
(air-gapped / ARM / hardened client boxes) — this must never hard-fail a scan.

This module is INFRASTRUCTURE, not a finding-producing phase: detecting a bot-
management product is not itself a client vulnerability. record_waf_block writes
an info-severity coverage lead so operators see degraded coverage instead of a
silent gap — it never escalates to a real finding on its own.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

try:
    from curl_cffi import requests as _curl_cffi_requests
    _CURL_CFFI_AVAILABLE = True
except ImportError:
    _CURL_CFFI_AVAILABLE = False

import httpx

_FINGERPRINT_MAP = {
    "chrome124": "chrome124",
    "firefox133": "firefox133",
    "safari18": "safari18_4",
    "okhttp4": "okhttp4",
}

_MOBILE_PATH_MARKERS = ("/mobile/", "/app/api", "/api/mobile")

_BOT_MGMT_SIGNATURES = (
    ("cloudflare", ("cf-ray", "cf-cache-status")),
    ("akamai", ("x-akamai-transformed", "akamai-x-cache")),
    ("f5", ("x-iinfo", "x-wa-info")),
)


def select_fingerprint(url: str) -> str:
    """Mobile-API-shaped paths get an OkHttp (Android) fingerprint; everything
    else defaults to a current desktop Chrome fingerprint."""
    lowered = url.lower()
    if any(marker in lowered for marker in _MOBILE_PATH_MARKERS):
        return "okhttp4"
    return "chrome124"


def detect_bot_management(response) -> str | None:
    """Given a response-like object (status_code, headers), return a bot-management
    product name if a known signature header is present on a blocking status."""
    if response.status_code not in (403, 429, 503):
        return None
    headers = {k.lower(): v for k, v in dict(response.headers).items()}
    for product, marker_headers in _BOT_MGMT_SIGNATURES:
        if any(h in headers for h in marker_headers):
            return product
    return None


def record_waf_block(findings_dir: str, url: str, product: str) -> None:
    """Append an info-severity [WAF-BLOCK-DETECTED] coverage lead. Never a finding
    on its own — reporter.py's NON_FINDING_PREFIXES keeps this out of the report
    body while still being visible to the operator/brain for coverage triage."""
    out_dir = os.path.join(findings_dir, "misconfig")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "waf_fingerprint.txt")
    ts = datetime.now(timezone.utc).isoformat()
    with open(out_path, "a") as f:
        f.write(f"[WAF-BLOCK-DETECTED] {ts} | product={product} | url={url}\n")


class _HttpxClientAdapter:
    """Thin wrapper so the httpx fallback exposes the same .get/.post surface
    curl_cffi's requests.Session provides, keeping callers backend-agnostic."""

    def __init__(self, timeout: float, proxy: str | None):
        self._client = httpx.Client(timeout=timeout, proxy=proxy, verify=False,
                                     follow_redirects=False)

    def get(self, url, **kwargs):
        return self._client.get(url, **kwargs)

    def post(self, url, **kwargs):
        return self._client.post(url, **kwargs)


def get_client(fingerprint: str = "chrome124", proxy: str | None = None,
               timeout: float = 15.0):
    """Return an HTTP client impersonating the given browser's TLS/HTTP2
    fingerprint. Falls back to stock httpx (no fingerprint spoofing, but still
    functional) if curl_cffi is unavailable — coverage degrades, the scan
    continues."""
    if not _CURL_CFFI_AVAILABLE:
        return _HttpxClientAdapter(timeout=timeout, proxy=proxy)
    impersonate = _FINGERPRINT_MAP.get(fingerprint, "chrome124")
    return _curl_cffi_requests.Session(impersonate=impersonate, proxies={"https": proxy, "http": proxy} if proxy else None,
                                        timeout=timeout, verify=False)
