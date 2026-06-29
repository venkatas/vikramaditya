"""Regression tests for ``har_vapt_engine.py``.

Covers:
- ``_is_success_response`` — the false-positive fix for
  ``Authentication Bypass`` (v7.1.2). Previous implementation matched
  any substring ``"success"`` and flagged error payloads like
  ``{"success":false,"error":true,"code":440,"message":"invalid session."}``
  as HIGH bypass findings. These tests pin the correct behaviour.
- ``_log`` deduplication — file-upload tests probe the same (url, field)
  with multiple shell extensions; only the first emission per
  ``(type, endpoint, parameter)`` should be kept.
"""

from __future__ import annotations

import os
import sys
import types
from urllib.parse import urlparse

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from har_vapt_engine import HARVAPTEngine


# ---------------------------------------------------------------------------
# Tiny stubs
# ---------------------------------------------------------------------------


class _StubResponse:
    """Minimal requests-like response for the success-detector tests."""

    def __init__(self, text: str = "", status_code: int = 200) -> None:
        self.text = text
        self.status_code = status_code


def _engine_skeleton() -> HARVAPTEngine:
    """Return an engine instance without running __init__ (which needs a HAR).

    The methods under test don't touch HAR state — they inspect responses
    and append to ``self.vulnerabilities`` / ``self._emitted_keys``.
    """
    eng = HARVAPTEngine.__new__(HARVAPTEngine)
    eng.vulnerabilities = []
    eng._emitted_keys = set()
    return eng


# ---------------------------------------------------------------------------
# _is_success_response  — the v7.1.2 fix
# ---------------------------------------------------------------------------


class TestIsSuccessResponse:
    def test_invalid_session_payload_is_not_success(self) -> None:
        """Regression: the payload that caused all 3 HIGH FPs on test.har."""
        r = _StubResponse(
            '{"success":false,"error":true,"code":440,"message":"invalid session."}',
            status_code=200,
        )
        assert HARVAPTEngine._is_success_response(r) is False

    def test_genuine_success_payload(self) -> None:
        r = _StubResponse('{"success":true,"data":{"id":1}}', status_code=200)
        assert HARVAPTEngine._is_success_response(r) is True

    def test_success_true_but_http_401_rejected(self) -> None:
        # Shouldn't happen on a well-behaved API but guard against it anyway.
        r = _StubResponse('{"success":true}', status_code=401)
        assert HARVAPTEngine._is_success_response(r) is False

    def test_status_false_rejected(self) -> None:
        r = _StubResponse('{"status":false,"error":"nope"}', status_code=200)
        assert HARVAPTEngine._is_success_response(r) is False

    def test_status_error_string_rejected(self) -> None:
        r = _StubResponse('{"status":"error","message":"x"}', status_code=200)
        assert HARVAPTEngine._is_success_response(r) is False

    def test_code_440_rejected(self) -> None:
        r = _StubResponse('{"code":440,"message":"session"}', status_code=200)
        assert HARVAPTEngine._is_success_response(r) is False

    def test_non_json_html_rejected(self) -> None:
        # The old "substring 'success'" heuristic would still bite here if
        # the HTML happened to contain the word "success" anywhere. New
        # behaviour: fall through to require the exact ``"success":true``
        # token in the body.
        r = _StubResponse("<html>success story landing page</html>", status_code=200)
        assert HARVAPTEngine._is_success_response(r) is False

    def test_quoted_success_field_in_malformed_json_rejected(self) -> None:
        """The word 'Success' appearing in a non-JSON body must NOT pass."""
        r = _StubResponse('"Success": "ok"', status_code=200)  # not valid JSON
        assert HARVAPTEngine._is_success_response(r) is False

    def test_please_login_phrase_rejected(self) -> None:
        r = _StubResponse('<p>please log in to continue</p>', status_code=200)
        assert HARVAPTEngine._is_success_response(r) is False

    def test_empty_body_rejected(self) -> None:
        r = _StubResponse("", status_code=200)
        assert HARVAPTEngine._is_success_response(r) is False

    def test_redirect_rejected(self) -> None:
        r = _StubResponse('{"success":true}', status_code=302)
        assert HARVAPTEngine._is_success_response(r) is False

    def test_non_json_with_explicit_success_true_accepted(self) -> None:
        # Some APIs return text/plain with a JSON-ish fragment; accept the
        # explicit token but only the exact ``"success":true`` spelling.
        r = _StubResponse('"success":true', status_code=200)
        assert HARVAPTEngine._is_success_response(r) is True


# ---------------------------------------------------------------------------
# _log deduplication  — the v7.1.2 fix for file-upload noise
# ---------------------------------------------------------------------------


class TestLogDedup:
    def test_duplicate_type_url_param_emitted_once(self) -> None:
        eng = _engine_skeleton()
        eng._log('medium', 'File Upload (Accepted, Unverified)',
                 'https://target/api/upload?a=1',
                 "Server accepted 'shell.php' via 'file' — cannot verify storage",
                 param='file')
        eng._log('medium', 'File Upload (Accepted, Unverified)',
                 'https://target/api/upload?a=2',   # same endpoint, different qs
                 "Server accepted 'shell.phtml' via 'file' — cannot verify storage",
                 param='file')
        eng._log('medium', 'File Upload (Accepted, Unverified)',
                 'https://target/api/upload',
                 "Server accepted 'shell.jsp' via 'file' — cannot verify storage",
                 param='file')
        # Three emissions collapse to one because (type, endpoint_path, param) is identical.
        assert len(eng.vulnerabilities) == 1
        assert eng.vulnerabilities[0]['parameter'] == 'file'

    def test_different_params_emit_separately(self) -> None:
        eng = _engine_skeleton()
        for field in ('file', 'upfile', 'upfile1'):
            eng._log('medium', 'File Upload (Accepted, Unverified)',
                     'https://target/api/upload',
                     f"Server accepted shell via '{field}'",
                     param=field)
        assert len(eng.vulnerabilities) == 3

    def test_different_types_emit_separately(self) -> None:
        eng = _engine_skeleton()
        eng._log('medium', 'File Upload (Accepted, Unverified)',
                 'https://target/', "x", param='f')
        eng._log('low', 'Missing Security Header',
                 'https://target/', "y", param='f')
        assert len(eng.vulnerabilities) == 2

    def test_endpoint_key_strips_query_string(self) -> None:
        eng = _engine_skeleton()
        eng._log('medium', 'HTTP TRACE Enabled',
                 'https://target/?x=1', 'y', param='')
        eng._log('medium', 'HTTP TRACE Enabled',
                 'https://target/?x=2', 'z', param='')
        # Dedup collapses both to one since query-string is stripped from the key.
        assert len(eng.vulnerabilities) == 1


# ---------------------------------------------------------------------------
# Engagement-scope allowlist — third-party HAR hosts must NOT be attacked
# ---------------------------------------------------------------------------


def _analysis(endpoints, target_domain="app.acme.invalid", domains=None):
    """Build a synthetic har_analysis dict with NO real client data."""
    return {
        "session_data": {},
        "endpoints": endpoints,
        "attack_surface": {"domains": domains or []},
        "config": {"target_domain": target_domain},
    }


class TestScopeAllowlist:
    def test_fail_closed_to_target_domain(self) -> None:
        # No explicit allowlist → only the first-seen target host is in scope.
        eng = HARVAPTEngine(_analysis([]))
        assert eng.allowed_hosts == {"app.acme.invalid"}

    def test_explicit_allowlist_used(self) -> None:
        eng = HARVAPTEngine(_analysis([]),
                            allowed_hosts=["app.acme.invalid", "API.ACME.invalid:8443"])
        # Normalised: lowercased, port stripped.
        assert eng.allowed_hosts == {"app.acme.invalid", "api.acme.invalid"}

    def test_in_scope_predicate(self) -> None:
        eng = HARVAPTEngine(_analysis([]))
        assert eng._in_scope("https://app.acme.invalid/login") is True
        assert eng._in_scope("https://app.acme.invalid:443/login") is True
        # Third-party hosts that routinely appear in real HARs.
        assert eng._in_scope("https://analytics.tracker.invalid/collect") is False
        assert eng._in_scope("https://cdn.jsdelivr.invalid/lib.js") is False

    def test_empty_allowlist_fails_closed(self) -> None:
        # No target_domain and no explicit hosts → nothing is in scope.
        eng = HARVAPTEngine(_analysis([], target_domain=""))
        assert eng.allowed_hosts == set()
        assert eng._in_scope("https://anything.invalid/x") is False

    def test_fuzzable_endpoints_drops_out_of_scope_host(self) -> None:
        eps = [
            {"url": "https://app.acme.invalid/api?id=1", "path": "/api",
             "method": "GET", "status_code": 200,
             "query_params": {"id": ["1"]}, "post_params": {}},
            {"url": "https://analytics.tracker.invalid/c?uid=9", "path": "/c",
             "method": "GET", "status_code": 200,
             "query_params": {"uid": ["9"]}, "post_params": {}},
        ]
        eng = HARVAPTEngine(_analysis(eps))
        kept = eng._fuzzable_endpoints()
        hosts = {urlparse(e["url"]).netloc for e in kept}
        assert hosts == {"app.acme.invalid"}
        assert "analytics.tracker.invalid" in eng._dropped_hosts

    def test_auth_endpoints_scope_filtered(self) -> None:
        eps = [
            {"url": "https://app.acme.invalid/login", "path": "/login",
             "method": "POST", "status_code": 200, "content_type": "application/json"},
            {"url": "https://sso.idp.invalid/token", "path": "/token",
             "method": "POST", "status_code": 200, "content_type": "application/json"},
        ]
        eng = HARVAPTEngine(_analysis(eps))
        kept = eng._auth_endpoints()
        assert {urlparse(e["url"]).netloc for e in kept} == {"app.acme.invalid"}

    def test_upload_endpoints_scope_filtered(self) -> None:
        eps = [
            {"url": "https://app.acme.invalid/up", "path": "/up", "method": "POST",
             "has_file_upload": True},
            {"url": "https://files.thirdparty.invalid/up", "path": "/up",
             "method": "POST", "has_file_upload": True},
        ]
        eng = HARVAPTEngine(_analysis(eps))
        kept = eng._real_upload_endpoints()
        assert {urlparse(e["url"]).netloc for e in kept} == {"app.acme.invalid"}


# ---------------------------------------------------------------------------
# Time-based SQLi confirmation — must re-run the LONG payload, not reuse it
# ---------------------------------------------------------------------------


class _ScriptedSession:
    """Session stub whose request latency is driven by a queue of sleeps."""

    def __init__(self, latencies):
        # latencies: list of seconds the *next* requests should appear to take
        self._latencies = list(latencies)
        self.calls = 0

    def _do(self, *a, **k):
        import time as _t
        self.calls += 1
        dur = self._latencies.pop(0) if self._latencies else 0.0
        if dur:
            _t.sleep(dur)
        return _StubResponse("", status_code=200)

    post = _do
    get = _do


def _sqli_engine(latencies):
    eng = HARVAPTEngine.__new__(HARVAPTEngine)
    eng.vulnerabilities = []
    eng._emitted_keys = set()
    eng.test_results = {}
    eng.allowed_hosts = {"app.acme.invalid"}
    eng._dropped_hosts = set()
    eng.session = _ScriptedSession(latencies)
    one_ep = {
        "url": "https://app.acme.invalid/api", "path": "/api", "method": "GET",
        "status_code": 200, "query_params": {"id": ["1"]}, "post_params": {},
        "_fuzz_params": {"id": "1"},
    }
    eng.endpoints = [one_ep]
    return eng


# ---------------------------------------------------------------------------
# IDOR detector — must use the schema-aware success parser + content identity,
# not a hard-coded '"Success"' substring + size-only delta.
# ---------------------------------------------------------------------------


class _SeqSession:
    """Session stub returning a queued sequence of response bodies."""

    def __init__(self, bodies):
        self._bodies = list(bodies)

    def _do(self, *a, **k):
        body = self._bodies.pop(0) if self._bodies else ""
        return _StubResponse(body, status_code=200)

    post = _do
    get = _do


def _idor_engine(bodies):
    eng = HARVAPTEngine.__new__(HARVAPTEngine)
    eng.vulnerabilities = []
    eng._emitted_keys = set()
    eng.test_results = {}
    eng.allowed_hosts = {"app.acme.invalid"}
    eng._dropped_hosts = set()
    eng.session = _SeqSession(bodies)
    ep = {
        "url": "https://app.acme.invalid/api/profile", "path": "/api/profile",
        "method": "GET", "status_code": 200,
        "query_params": {"userid": ["1"]}, "post_params": {},
        "_fuzz_params": {"userid": "1"},
    }
    eng.endpoints = [ep]
    return eng


class TestIDORDetection:
    def test_lowercase_success_other_record_is_flagged(self) -> None:
        # Old code keyed on the literal '"Success"' (capital S) so a lower-case
        # JSON success body would be a false negative. New code uses the
        # schema-aware parser → lower-case {"success":true} for a DIFFERENT
        # record must be flagged.
        big_other = '{"success":true,"data":{"name":"' + "X" * 400 + '"}}'
        baseline = '{"success":true,"data":{"name":"self"}}'
        # baseline GET, then 6 test_vals; first test_val returns the other record.
        bodies = [baseline, big_other]
        eng = _idor_engine(bodies)
        eng.test_idor()
        idor = [v for v in eng.vulnerabilities if v["type"] == "IDOR"]
        assert len(idor) == 1

    def test_same_record_refetch_not_flagged(self) -> None:
        # Re-fetching the operator's OWN record (same content identity) must
        # NOT be reported even though it is a genuine success — content
        # identity is equal, so no cross-record disclosure.
        baseline = '{"success":true,"data":{"name":"self"}}'
        bodies = [baseline] + [baseline] * 6
        eng = _idor_engine(bodies)
        eng.test_idor()
        idor = [v for v in eng.vulnerabilities if v["type"] == "IDOR"]
        assert idor == []

    def test_error_response_not_flagged(self) -> None:
        # A server that correctly denies the cross-user request returns an
        # error body — even if large/different, it is not a success so no IDOR.
        baseline = '{"success":true,"data":{"name":"self"}}'
        denied = '{"success":false,"error":true,"message":"' + "n" * 400 + '"}'
        bodies = [baseline] + [denied] * 6
        eng = _idor_engine(bodies)
        eng.test_idor()
        idor = [v for v in eng.vulnerabilities if v["type"] == "IDOR"]
        assert idor == []


# ---------------------------------------------------------------------------
# Brain opt-in — autonomous LLM-executes-code path defaults OFF
# ---------------------------------------------------------------------------


class TestBrainOptIn:
    def test_brain_disabled_by_default(self) -> None:
        eng = HARVAPTEngine(_analysis([]))
        assert eng.enable_brain is False

    def test_brain_enabled_when_requested(self) -> None:
        eng = HARVAPTEngine(_analysis([]), enable_brain=True)
        assert eng.enable_brain is True


class TestTimeBasedSQLiConfirmation:
    def test_single_jitter_spike_is_not_confirmed(self) -> None:
        # Error-based loop fires first (7 SQLI_ERROR payloads, all fast=0s),
        # then the time-based loop runs 3 templates. We make ONLY the very
        # first long-payload request slow (a one-off 5s jitter spike); every
        # subsequent request — including the confirmation re-run of the long
        # payload — is fast. The old code reused the first `elapsed` and would
        # FALSELY confirm. The fixed code re-runs the long payload and must NOT.
        # 7 error requests (fast) + [slow first long, fast long-confirm, fast short] + ...
        latencies = [0.0] * 7 + [5.0, 0.0, 0.0]
        eng = _sqli_engine(latencies)
        eng.test_sql_injection()
        tb = [v for v in eng.vulnerabilities if v["type"] == "SQL Injection (Time-Based)"]
        assert tb == [], "one-off jitter spike must not be reported as time-based SQLi"

    def test_reproducible_delay_is_confirmed(self) -> None:
        # Genuine injection: BOTH long-payload hits are slow, short is fast.
        latencies = [0.0] * 7 + [5.0, 5.0, 0.0]
        eng = _sqli_engine(latencies)
        eng.test_sql_injection()
        tb = [v for v in eng.vulnerabilities if v["type"] == "SQL Injection (Time-Based)"]
        assert len(tb) == 1
        assert tb[0]["severity"] == "critical"
