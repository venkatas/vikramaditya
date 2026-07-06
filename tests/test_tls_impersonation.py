"""tls_impersonation — JA3/JA4 + HTTP/2 fingerprint-impersonating HTTP client.

Infrastructure module, not a finding-producing phase: a real bot-management block
(Cloudflare/Akamai/F5) is not itself a client vuln, so it never escalates past an
info-severity coverage lead ([WAF-BLOCK-DETECTED]) — see record_waf_block.
"""
import os
from unittest.mock import MagicMock

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


def test_get_client_curl_cffi_path_disables_redirects(monkeypatch):
    """Regression test for Critical #1: curl_cffi's Session defaults
    allow_redirects=True, which would silently auto-follow 3xx responses
    unlike the httpx fallback (follow_redirects=False). curl_cffi is not
    installed in this dev environment, so we fake its presence: flip the
    availability flag and swap in a fake module whose Session records the
    kwargs it was constructed with, then assert get_client() explicitly
    passes allow_redirects=False."""
    monkeypatch.setattr(ti, "_CURL_CFFI_AVAILABLE", True)

    fake_session_cls = MagicMock()
    fake_curl_cffi_requests = MagicMock()
    fake_curl_cffi_requests.Session = fake_session_cls
    monkeypatch.setattr(ti, "_curl_cffi_requests", fake_curl_cffi_requests, raising=False)

    client = ti.get_client(fingerprint="chrome124", proxy="http://proxy:8080", timeout=7.5)

    assert client is fake_session_cls.return_value
    fake_session_cls.assert_called_once_with(
        impersonate="chrome124",
        proxies={"https": "http://proxy:8080", "http": "http://proxy:8080"},
        timeout=7.5,
        verify=False,
        allow_redirects=False,
    )


def test_get_client_curl_cffi_path_no_proxy(monkeypatch):
    """Same regression coverage as above, but exercises the no-proxy branch
    (proxies=None) to make sure allow_redirects=False holds regardless of
    the proxy kwarg path taken."""
    monkeypatch.setattr(ti, "_CURL_CFFI_AVAILABLE", True)

    fake_session_cls = MagicMock()
    fake_curl_cffi_requests = MagicMock()
    fake_curl_cffi_requests.Session = fake_session_cls
    monkeypatch.setattr(ti, "_curl_cffi_requests", fake_curl_cffi_requests, raising=False)

    ti.get_client(fingerprint="firefox133")

    fake_session_cls.assert_called_once_with(
        impersonate="firefox133",
        proxies=None,
        timeout=15.0,
        verify=False,
        allow_redirects=False,
    )
