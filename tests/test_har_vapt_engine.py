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
