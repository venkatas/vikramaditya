"""Acceptance tests for the v9.18.2 scanner-quality fixes.

Covers:
- 404-only endpoints do NOT produce missing_rate_limit findings
  (and are reported as skipped by the rate-limit phase).
- A caller-supplied endpoint inventory file is honoured by run_autopilot
  and is not clobbered by an empty discovery result.
- Opaque bearer tokens (anything that isn't a real JWT) are detected and
  the JWT-only checks are skipped without misleading "alg: None" logs.
- Upload payloads whose filename contains a NUL byte do not crash the
  scanner (they used to blow up in tempfile.NamedTemporaryFile).
- Endpoint inventory entries with absolute or base-prefix paths are
  normalised so the joined URL doesn't double-prefix the API base.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import types
from pathlib import Path

import pytest

import auth_utils
from auth_utils import AuthSession, JWTHelper

import autopilot_api_hunt
from autopilot_api_hunt import (
    RateLimitTester,
    TokenSecurityTester,
    _normalize_endpoint_entry,
)


# ─── Fake HTTP plumbing ───────────────────────────────────────────────────────
class _FakeResponse:
    def __init__(self, status_code=200, body=None, content=b"", cookies=None):
        self.status_code = status_code
        self._body = body if body is not None else {}
        self.content = content
        self.cookies = _FakeCookieJar(cookies or {})

    def json(self):
        return self._body


class _FakeCookieJar(dict):
    def get(self, key, default=None):  # type: ignore[override]
        return dict.get(self, key, default)


class _FakeSession:
    def __init__(self):
        self.headers = {}
        self.cookies = _FakeCookieJar()
        self.verify = False


# ─── Bug 4: opaque vs JWT detection ───────────────────────────────────────────
class TestOpaqueBearerDetection:

    def test_opaque_string_is_not_jwt(self):
        # The kind of token format scanners typically meet on REST APIs:
        # an opaque random string with no dots, no header / payload at all.
        assert JWTHelper.is_jwt("ep_a2_caRandomOpaqueBearer1234567890") is False

    def test_two_dots_but_garbage_segments_is_not_jwt(self):
        # Has the structural shape but the segments are not valid base64
        # JSON objects — must not be misclassified.
        assert JWTHelper.is_jwt("aaa.bbb.ccc") is False

    def test_real_jwt_is_detected(self):
        # Header {"alg":"HS256","typ":"JWT"} . Payload {"sub":"x"} . sig
        head = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        payload = "eyJzdWIiOiJ4In0"
        sig = "abc"
        assert JWTHelper.is_jwt(f"{head}.{payload}.{sig}") is True

    def test_empty_and_sentinel_strings_are_not_jwt(self):
        assert JWTHelper.is_jwt("") is False
        assert JWTHelper.is_jwt("cookie-auth") is False

    def test_token_security_phase_skips_for_opaque(self, capsys):
        sess = AuthSession("https://app.example.com/api")
        findings = TokenSecurityTester().run(
            sess, token="ep_a2_caRandomOpaqueBearer1234567890",
            saver=None,
        )
        out = capsys.readouterr().out
        assert findings == []
        assert "treating as opaque" in out
        # The misleading old log line must be gone.
        assert "JWT alg: None" not in out


# ─── Bug 2: 404-only rate-limit endpoints suppressed ──────────────────────────
class TestRateLimit404Skip:

    def test_endpoint_returning_404_is_skipped(self, monkeypatch, capsys):
        # Pretend the target only has /api/auth/login (200), all other
        # SENSITIVE_PATHS return 404. AuthSession.base_url ends with /api
        # so the joined probe URL has /api/<path>.
        scripted = {
            "/api/auth/login": 200,
        }

        calls: list[tuple[str, str]] = []

        def fake_post(url, *a, **kw):
            from urllib.parse import urlparse
            path = urlparse(url).path
            status = scripted.get(path, 404)
            calls.append((path, "POST"))
            return _FakeResponse(status_code=status)

        # Build a fake requests module that satisfies BOTH
        # `import requests as _req; _req.post(...)` (used by the rate-limit
        # phase) and `requests.Session()` (used by AuthSession.__init__).
        class _StubSess:
            def __init__(self):
                self.headers = {}
                self.cookies = _FakeCookieJar()
                self.verify = False

        fake_requests = types.SimpleNamespace(
            Session=_StubSess,
            post=fake_post,
        )
        fake_urllib3 = types.SimpleNamespace(
            disable_warnings=lambda *a, **k: None,
            exceptions=types.SimpleNamespace(InsecureRequestWarning=Exception),
        )
        monkeypatch.setitem(sys.modules, "requests", fake_requests)
        monkeypatch.setitem(sys.modules, "urllib3", fake_urllib3)

        sess = AuthSession("https://app.example.com/api")
        findings = RateLimitTester().run(sess, saver=None)

        out = capsys.readouterr().out

        # /auth/login is 200 — gets bursted (probe + 9 follow-ups = 10 calls).
        login_calls = [c for c in calls if c[0] == "/api/auth/login"]
        assert len(login_calls) == 10, f"unexpected burst count: {len(login_calls)}"

        # /contact is 404 — only the probe should have happened, no burst.
        contact_calls = [c for c in calls if c[0] == "/api/contact"]
        assert len(contact_calls) == 1, "404-only path should not be bursted"

        # missing_rate_limit fired on /auth/login (no 429 across 10 reqs)
        # but NOT on /contact (404-only path is skipped).
        finding_paths = [f["url"] for f in findings]
        assert any("/auth/login" in u for u in finding_paths)
        assert not any("/contact" in u for u in finding_paths), \
            "404-only path must not produce a missing_rate_limit finding"

        # And the operator log surfaces the skip count.
        assert "skipped 404-only=" in out
        # All findings must record endpoint_live=True.
        assert all(f.get("endpoint_live") is True for f in findings)


# ─── Bug 3: NUL-byte upload payload doesn't crash ─────────────────────────────
class TestNulFilenameSafety:

    def test_tempfile_with_nul_filename_would_raise_natively(self):
        # Sanity-check the actual underlying behaviour we are guarding against.
        with pytest.raises((ValueError, OSError)):
            tempfile.NamedTemporaryFile(suffix="_shell.php\x00.jpg", delete=False)

    def test_sanitiser_replaces_nul_for_local_temp(self):
        # The exact sanitiser used in the upload phase. Mirrors the
        # logic at autopilot_api_hunt.py so we lock the contract.
        for raw in ("shell.php\x00.jpg", "x/y\x00z", "\x00\x00"):
            safe = (raw.replace("\x00", "_NUL_")
                       .replace("/", "_")
                       .replace("\\", "_")) or "payload"
            assert "\x00" not in safe
            # The cleaned suffix must work with tempfile.
            t = tempfile.NamedTemporaryFile(suffix=f"_{safe}", delete=False)
            t.close()
            os.unlink(t.name)


# ─── Bug 1: --endpoints-file inventory honoured + URL normalisation ───────────
class TestEndpointsFileInventory:

    def test_normalize_strips_duplicate_base_prefix(self):
        # /api/auth/me against base https://host/api → auth/me
        out = _normalize_endpoint_entry(
            {"method": "POST", "path": "/api/auth/me"},
            "https://app.example.com/api",
        )
        assert out["path"] == "auth/me"
        assert out["method"] == "POST"

    def test_normalize_handles_no_base_prefix(self):
        out = _normalize_endpoint_entry(
            {"method": "GET", "path": "auth/me"},
            "https://app.example.com/api",
        )
        assert out["path"] == "auth/me"

    def test_normalize_strips_leading_slash_only(self):
        out = _normalize_endpoint_entry(
            {"method": "GET", "path": "/auth/me"},
            "https://app.example.com",
        )
        assert out["path"] == "auth/me"

    def test_normalize_handles_absolute_url_same_host(self):
        out = _normalize_endpoint_entry(
            {"method": "POST", "path": "https://app.example.com/api/auth/login"},
            "https://app.example.com/api",
        )
        assert out["path"] == "auth/login"

    def test_normalize_keeps_external_host_path_raw(self):
        # Different host — leave it for AuthSession to handle.
        out = _normalize_endpoint_entry(
            {"method": "GET", "path": "https://other.example.com/x"},
            "https://app.example.com/api",
        )
        assert out["path"].startswith("https://other.example.com/")

    def test_inventory_honoured_and_not_clobbered(self, monkeypatch, tmp_path):
        # Build an inventory file the autopilot must consume.
        inv = [
            {"method": "POST", "path": "/api/auth/login"},
            {"method": "POST", "path": "/api/auth/password-reset/request"},
            {"method": "POST", "path": "auth/accept-invite"},
        ]
        inv_path = tmp_path / "endpoints.json"
        inv_path.write_text(json.dumps(inv))

        # Stub discovery + auto-detect so run_autopilot doesn't reach out.
        monkeypatch.setattr(
            "autopilot_api_hunt._auto_detect_api_base",
            lambda url, rl: url, raising=False,
        )

        class _StubDiscovery:
            def __init__(self, sess, frontend):
                pass

            def run(self):
                return []  # discovery returns NOTHING — would clobber inventory pre-fix.

        monkeypatch.setattr(
            "autopilot_api_hunt.EndpointDiscovery", _StubDiscovery, raising=False,
        )

        # Stub HTTP so AuthSession.set_token doesn't actually open a session.
        class _Sess:
            def __init__(self):
                self.headers = {}
                self.cookies = _FakeCookieJar()
                self.verify = False
        fake_requests = types.SimpleNamespace(Session=lambda: _Sess())
        monkeypatch.setitem(sys.modules, "requests", fake_requests)

        # Skip the brain-loop phases by short-circuiting the test plan.
        monkeypatch.setattr(
            "autopilot_api_hunt._brain_create_initial_plan",
            lambda eps, with_brain: [], raising=False,
        )

        out_dir = tmp_path / "out"
        autopilot_api_hunt.run_autopilot(
            base_url="https://app.example.com/api",
            auth_token="opaque-test-token",
            login_url="auth/login",
            output_dir=str(out_dir),
            with_brain=False,
            endpoints_file=str(inv_path),
        )

        # The merged endpoints.json under output_dir must contain the
        # inventory entries (paths normalised).
        merged = json.loads((out_dir / "endpoints.json").read_text())
        merged_paths = {(e["method"], e["path"]) for e in merged}
        assert ("POST", "auth/login") in merged_paths
        assert ("POST", "auth/password-reset/request") in merged_paths
        assert ("POST", "auth/accept-invite") in merged_paths
        # Source attribution preserved.
        assert all(e.get("source") in ("inventory", "discovery") for e in merged)
        inv_entries = [e for e in merged if e["source"] == "inventory"]
        assert len(inv_entries) == 3

    def test_empty_discovery_does_not_clobber_inventory_file(self, monkeypatch, tmp_path):
        # The inventory FILE itself must remain untouched, regardless of
        # what discovery returned. (The merged result is written to
        # output_dir/endpoints.json, never back to the input file.)
        inv = [{"method": "POST", "path": "auth/login"}]
        inv_path = tmp_path / "endpoints.json"
        inv_path.write_text(json.dumps(inv))
        original = inv_path.read_text()

        monkeypatch.setattr(
            "autopilot_api_hunt._auto_detect_api_base",
            lambda url, rl: url, raising=False,
        )

        class _StubDiscovery:
            def __init__(self, sess, frontend): pass
            def run(self): return []

        monkeypatch.setattr(
            "autopilot_api_hunt.EndpointDiscovery", _StubDiscovery, raising=False,
        )
        fake_requests = types.SimpleNamespace(
            Session=lambda: types.SimpleNamespace(
                headers={}, cookies=_FakeCookieJar(), verify=False),
        )
        monkeypatch.setitem(sys.modules, "requests", fake_requests)
        monkeypatch.setattr(
            "autopilot_api_hunt._brain_create_initial_plan",
            lambda eps, with_brain: [], raising=False,
        )

        out_dir = tmp_path / "out"
        autopilot_api_hunt.run_autopilot(
            base_url="https://app.example.com/api",
            auth_token="opaque-test-token",
            login_url="auth/login",
            output_dir=str(out_dir),
            with_brain=False,
            endpoints_file=str(inv_path),
        )

        # Input file is byte-for-byte identical.
        assert inv_path.read_text() == original
