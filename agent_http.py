#!/usr/bin/env python3
"""agent_http.py — a native, LLM-digestible HTTP probe for the agent/brain.

Ported from xalgorix's `http_request` tool. Vikramaditya's agent could only reach
the network by shelling out to curl / scanner.sh, which is clumsy for the things an
LLM actually wants to do mid-loop: fuzz a numeric ID for IDOR, replay a request with
a stripped Authorization header for auth-bypass, or inspect a 3xx `Location` for an
open-redirect/SSRF without following it. `probe()` gives a single structured call:

  {status, headers, body, bytes, truncated, is_binary, content_type,
   elapsed_ms, url, final_url, method, error}

Design choices that keep it safe for an autonomous loop:
  * method whitelist (no TRACE/CONNECT/arbitrary verbs);
  * body capped (default 50 KB) so one fat HTML page can't blow the context window;
  * binary content (images/pdf/zip/…) is NOT decoded into the body — just summarised;
  * timeout hard-capped (≤60 s) so a slow target can't hang the agent;
  * never raises — transport failures come back as {status:0, error:...}.

Scope-gating is the caller's job: wire this behind scopeguard.scan_command() in
agent.py exactly like the other tools, so an in-scope-only policy still holds.
"""
from __future__ import annotations

import time
from urllib.parse import urljoin

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import os

VERIFY_TLS = os.environ.get("VAPT_INSECURE_SSL", "0") != "1"

_ALLOWED_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
_MAX_TIMEOUT = 60
_DEFAULT_TIMEOUT = 30
_DEFAULT_MAX_BODY = 50_000

# Content types whose bytes are useless (and dangerous) to dump into an LLM prompt.
_BINARY_CT = (
    "image/", "audio/", "video/", "font/",
    "application/pdf", "application/zip", "application/gzip",
    "application/x-gzip", "application/octet-stream", "application/x-tar",
    "application/x-7z-compressed", "application/x-rar", "application/wasm",
)


def _is_binary_content_type(ct: str) -> bool:
    low = (ct or "").lower()
    return any(low.startswith(p) or p in low for p in _BINARY_CT)


def _normalize_headers(headers: dict | None) -> dict:
    """requests wants single string values; allow list values (multi-value
    headers like Accept-Encoding chains) by joining per RFC 7230 (", ")."""
    out = {}
    for k, v in (headers or {}).items():
        if isinstance(v, (list, tuple)):
            out[k] = ", ".join(str(x) for x in v)
        else:
            out[k] = str(v)
    return out


def _looks_binary_bytes(sample: bytes) -> bool:
    """Byte-sniff: a NUL byte or a high ratio of non-text control bytes means the
    payload is binary regardless of a (possibly lying) Content-Type header."""
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    text_ctrl = {9, 10, 13}  # tab, LF, CR are fine in text
    ctrl = sum(1 for b in sample if b < 32 and b not in text_ctrl)
    return ctrl / len(sample) > 0.3


def _read_capped(resp, max_body: int) -> bytes:
    """Read at most ~max_body bytes. Stream when the transport supports it so a
    multi-GB response is never fully buffered; fall back to .content otherwise."""
    limit = max_body + 4096  # small slack so truncation is detectable
    it = getattr(resp, "iter_content", None)
    if callable(it):
        buf = bytearray()
        try:
            for chunk in it(8192):
                if chunk:
                    buf += chunk
                    if len(buf) >= limit:
                        break
        except Exception:
            pass
        return bytes(buf)
    return getattr(resp, "content", b"") or b""


def _finalize(result: dict, resp, final_url: str, max_body: int) -> dict:
    """Populate result from a terminal response (status/headers/body).

    Always closes ``resp`` before returning. With ``stream=True`` (see probe())
    requests/urllib3 does NOT auto-release the connection back to the pool, and
    ``_read_capped`` deliberately stops short of consuming a large body — so
    without an explicit close the checked-out connection/socket leaks until GC
    finalizes the response. This is the single terminal sink for every non-
    redirect-follow exit path, so closing here covers all of them.
    """
    try:
        result["status"] = getattr(resp, "status_code", 0) or 0
        result["headers"] = dict(getattr(resp, "headers", {}) or {})
        result["final_url"] = getattr(resp, "url", final_url) or final_url
        raw = _read_capped(resp, max_body)
        result["bytes"] = len(raw)
        ct = result["headers"].get("Content-Type") or result["headers"].get("content-type") or ""
        result["content_type"] = ct
        if _is_binary_content_type(ct) or _looks_binary_bytes(raw[:1024]):
            result["is_binary"] = True
            result["body"] = f"<binary {result['bytes']} bytes, content-type={ct or 'unknown'}>"
            return result
        text = raw.decode("utf-8", "ignore")
        if len(text) > max_body:
            result["truncated"] = True
            result["body"] = text[:max_body] + f"\n…[truncated {len(text) - max_body}+ chars]"
        else:
            result["body"] = text
        return result
    finally:
        try:
            resp.close()
        except Exception:
            pass


_REDIRECT_CODES = (301, 302, 303, 307, 308)


def probe(
    method: str,
    url: str,
    headers: dict | None = None,
    body=None,
    json_body=None,
    timeout: int = _DEFAULT_TIMEOUT,
    max_body: int = _DEFAULT_MAX_BODY,
    follow_redirects: bool = True,
    verify: bool | None = None,
    allow_url=None,
    max_redirects: int = 5,
) -> dict:
    """Issue one HTTP request and return a structured, LLM-safe result dict.

    Redirects are followed MANUALLY (never delegated to requests), so each hop's
    target can be re-validated by ``allow_url`` before it is fetched. This stops an
    in-scope open-redirect from bouncing the probe to loopback / out-of-scope hosts
    (SSRF), and surfaces the redirect to the caller via ``redirect_blocked`` instead.
    ``allow_url(next_url) -> bool``; when None, redirects follow freely (bounded by
    ``max_redirects``).
    """
    m = (method or "").strip().upper()
    result = {
        "status": 0, "headers": {}, "body": "", "bytes": 0, "truncated": False,
        "is_binary": False, "content_type": "", "elapsed_ms": 0,
        "url": url, "final_url": url, "method": m, "error": "",
    }
    if m not in _ALLOWED_METHODS:
        result["error"] = f"unsupported HTTP method: {method!r} (allowed: {sorted(_ALLOWED_METHODS)})"
        return result

    try:
        t = int(timeout)
    except Exception:
        t = _DEFAULT_TIMEOUT
    t = max(1, min(t, _MAX_TIMEOUT))

    hdrs = _normalize_headers(headers)
    if verify is None:
        verify = VERIFY_TLS

    cur_url, cur_method = url, m
    cur_body, cur_json = body, json_body
    redirects_done = 0
    start = time.monotonic()
    try:
        while True:
            resp = requests.request(
                cur_method, cur_url, headers=hdrs, data=cur_body, json=cur_json,
                timeout=t, allow_redirects=False, verify=verify, stream=True,
            )
            status = getattr(resp, "status_code", 0) or 0
            if follow_redirects and status in _REDIRECT_CODES and redirects_done < max_redirects:
                rhdrs = getattr(resp, "headers", {}) or {}
                loc = rhdrs.get("Location") or rhdrs.get("location")
                if loc:
                    nxt = urljoin(cur_url, loc)
                    if allow_url is not None and not allow_url(nxt):
                        # Open-redirect to an off-limits host: surface it, do NOT follow.
                        _finalize(result, resp, cur_url, max_body)
                        result["redirect_blocked"] = nxt
                        break
                    try:
                        resp.close()
                    except Exception:
                        pass
                    cur_url = nxt
                    if status in (301, 302, 303):  # drop method/body like a browser
                        cur_method, cur_body, cur_json = "GET", None, None
                    redirects_done += 1
                    continue
            _finalize(result, resp, cur_url, max_body)
            break
    except Exception as exc:  # noqa: BLE001 — transport guard; never crash the loop
        result["error"] = str(exc) or type(exc).__name__

    result["elapsed_ms"] = int((time.monotonic() - start) * 1000)
    return result
