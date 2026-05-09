"""Acceptance tests for the generic TOTP / MFA login support.

Covers:
- ``auth_utils.totp_code()`` against RFC 6238 vectors and edge cases.
- ``AuthSession.auto_login`` injects TOTP into the standard candidate
  body shapes (email-JSON, email-form, username-JSON).
- ``extra_fields`` is merged into every JSON-shaped login attempt.
- ``requiresTotp=true`` is surfaced as a clear ``RuntimeError`` when
  no code was supplied — no silent password-only fallback.
- A token returned in the response body is captured.
- ``autopilot_api_hunt`` token-only mode bypasses the login URL entirely.
- ``autopilot_api_hunt`` credential + TOTP mode submits the JSON body
  with the TOTP code and any ``--login-extra-json`` fields merged in.
- Logs do not echo password / token / TOTP secret.
"""

from __future__ import annotations

import base64
import types

import pytest

import auth_utils
from auth_utils import AuthSession, totp_code


# ─── Fake requests Session capturing every POST ───────────────────────────────
class _FakeResponse:
    def __init__(self, status_code=200, body=None, cookies=None):
        self.status_code = status_code
        self._body = body if body is not None else {}
        self.cookies = _FakeCookieJar(cookies or {})

    def json(self):
        return self._body


class _FakeCookieJar(dict):
    def get(self, key, default=None):  # type: ignore[override]
        return dict.get(self, key, default)


class _FakeSession:
    """Captures POSTs and replays scripted responses."""

    def __init__(self, scripted: list[_FakeResponse]):
        self.headers: dict = {}
        self.cookies = _FakeCookieJar()
        self.verify = False
        self.calls: list[dict] = []
        self._scripted = list(scripted)

    def post(self, url, timeout=15, **kwargs):
        self.calls.append({"url": url, **kwargs})
        if not self._scripted:
            return _FakeResponse(500, {})
        return self._scripted.pop(0)


def _patch_requests(monkeypatch, scripted: list[_FakeResponse]) -> _FakeSession:
    fake = _FakeSession(scripted)
    fake_module = types.SimpleNamespace(Session=lambda: fake)

    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__

    def _import(name, *args, **kwargs):
        if name == "requests":
            return fake_module
        if name == "urllib3":
            return types.SimpleNamespace(
                disable_warnings=lambda *a, **k: None,
                exceptions=types.SimpleNamespace(InsecureRequestWarning=Exception),
            )
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", _import)
    return fake


# ─── totp_code ────────────────────────────────────────────────────────────────
class TestTotpCode:
    SECRET_BYTES = b"12345678901234567890"
    SECRET_B32 = base64.b32encode(SECRET_BYTES).decode()

    def test_returns_six_digit_string(self):
        code = totp_code(self.SECRET_B32)
        assert isinstance(code, str)
        assert len(code) == 6
        assert code.isdigit()

    def test_zero_padded(self):
        for step in range(0, 200):
            code = totp_code(self.SECRET_B32, step=step)
            assert len(code) == 6, f"step={step} returned {code!r}"

    def test_rfc6238_vector_t59(self):
        # RFC 6238 Appendix B: T=59, key='12345678901234567890', SHA1 → 287082
        assert totp_code(self.SECRET_B32, step=59 // 30) == "287082"

    def test_rfc6238_vector_t1111111109(self):
        # RFC 6238 Appendix B: T=1111111109 → 081804
        assert totp_code(self.SECRET_B32, step=1111111109 // 30) == "081804"

    def test_secret_with_spaces_is_accepted(self):
        spaced = "  ".join(self.SECRET_B32[i:i + 4] for i in range(0, len(self.SECRET_B32), 4))
        assert totp_code(spaced, step=59 // 30) == "287082"

    def test_secret_lowercase_is_accepted(self):
        assert totp_code(self.SECRET_B32.lower(), step=59 // 30) == "287082"

    def test_empty_secret_raises(self):
        with pytest.raises(ValueError, match="secret is required"):
            totp_code("")

    def test_invalid_base32_raises(self):
        with pytest.raises(ValueError, match="not valid base32"):
            totp_code("!!!notbase32!!!")


# ─── AuthSession.auto_login — TOTP injection + extra_fields ───────────────────
class TestMfaAutoLogin:

    BASE = "https://app.example.com/api"

    def test_login_with_totp_secret_returns_token(self, monkeypatch):
        scripted = [_FakeResponse(200, {"token": "ey.primary.token"})]
        fake = _patch_requests(monkeypatch, scripted)

        sess = AuthSession(self.BASE)
        secret = base64.b32encode(b"12345678901234567890").decode()

        token = sess.auto_login(
            "auth/login", "vapt-admin@example.com", "PasswordHere",
            totp_secret=secret,
        )

        assert token == "ey.primary.token"
        assert sess.token == "ey.primary.token"
        assert sess._session.headers.get("Authorization") == "Bearer ey.primary.token"

        body = fake.calls[0]["json"]
        assert body["email"] == "vapt-admin@example.com"
        assert body["password"] == "PasswordHere"
        assert body["totp"].isdigit() and len(body["totp"]) == 6

    def test_login_with_pre_minted_code_uses_it(self, monkeypatch):
        scripted = [_FakeResponse(200, {"token": "ey.preminted.token"})]
        fake = _patch_requests(monkeypatch, scripted)

        sess = AuthSession(self.BASE)
        token = sess.auto_login(
            "auth/login", "u@x", "p",
            totp_code_value="654321",
        )
        assert token == "ey.preminted.token"
        assert fake.calls[0]["json"]["totp"] == "654321"

    def test_extra_fields_merged_into_login_body(self, monkeypatch):
        scripted = [_FakeResponse(200, {"token": "ey.workspace.token"})]
        fake = _patch_requests(monkeypatch, scripted)

        sess = AuthSession(self.BASE)
        sess.auto_login(
            "auth/login", "u@x", "p",
            totp_code_value="123456",
            extra_fields={"loginSurface": "workspace"},
        )
        body = fake.calls[0]["json"]
        assert body["loginSurface"] == "workspace"
        assert body["totp"] == "123456"

    def test_extra_fields_admin_path_only_when_caller_supplies(self, monkeypatch):
        # The autopilot ships no per-target hardcoded fields — admin-style
        # metadata only travels when the operator explicitly merges it in.
        scripted = [_FakeResponse(200, {"token": "ey.admin.token"})]
        fake = _patch_requests(monkeypatch, scripted)
        sess = AuthSession(self.BASE)
        sess.auto_login(
            "auth/login", "su@x", "p",
            totp_code_value="123456",
            extra_fields={"loginSurface": "admin", "adminPath": "/private-path"},
        )
        body = fake.calls[0]["json"]
        assert body["loginSurface"] == "admin"
        assert body["adminPath"] == "/private-path"

    def test_default_login_omits_extra_fields(self, monkeypatch):
        # Without extra_fields the body must not carry loginSurface / adminPath.
        scripted = [_FakeResponse(200, {"token": "ey.plain.token"})]
        fake = _patch_requests(monkeypatch, scripted)
        sess = AuthSession(self.BASE)
        sess.auto_login("auth/login", "u@x", "p", totp_code_value="123456")
        body = fake.calls[0]["json"]
        assert "loginSurface" not in body
        assert "adminPath" not in body

    def test_requires_totp_without_secret_raises(self, monkeypatch):
        scripted = [_FakeResponse(200, {"requiresTotp": True, "message": "TOTP code required."})] * 4
        _patch_requests(monkeypatch, scripted)

        sess = AuthSession(self.BASE)
        with pytest.raises(RuntimeError, match="requires TOTP"):
            sess.auto_login("auth/login", "u@x", "p")

    def test_token_in_data_field_is_extracted(self, monkeypatch):
        scripted = [_FakeResponse(200, {"data": {"token": "ey.nested.token"}})]
        _patch_requests(monkeypatch, scripted)
        sess = AuthSession(self.BASE)
        token = sess.auto_login("auth/login", "u@x", "p", totp_code_value="111111")
        assert token == "ey.nested.token"

    def test_legacy_login_paths_still_work_without_totp(self, monkeypatch):
        # Non-MFA target: server replies on the second attempt (form-data).
        scripted = [
            _FakeResponse(401, {}),
            _FakeResponse(200, {"access_token": "legacy.token"}),
        ]
        fake = _patch_requests(monkeypatch, scripted)
        sess = AuthSession("https://api.legacy.example.com")
        token = sess.auto_login("login-view/", "u@x", "p")
        assert token == "legacy.token"
        # First call should NOT include TOTP and no extra fields.
        first_body = fake.calls[0].get("json", {})
        assert "totp" not in first_body
        assert "loginSurface" not in first_body


# ─── autopilot CLI integration — token-first + TOTP creds ─────────────────────
class TestAutopilotCli:
    """Drive ``run_autopilot`` through monkeypatched HTTP and verify the auth
    wiring without spinning up the full 12-phase pipeline."""

    BASE = "https://app.example.com/api"

    def _stub_phases(self, monkeypatch):
        monkeypatch.setattr(
            "autopilot_api_hunt._discover_endpoints",
            lambda *a, **k: [],
            raising=False,
        )
        monkeypatch.setattr(
            "autopilot_api_hunt._auto_detect_api_base",
            lambda url, rl: url,
            raising=False,
        )

    def test_auth_token_skips_login(self, monkeypatch, capsys):
        """When --auth-token is passed, no POST is made to the login URL."""
        fake = _patch_requests(monkeypatch, [])
        self._stub_phases(monkeypatch)
        from autopilot_api_hunt import run_autopilot

        run_autopilot(
            base_url=self.BASE,
            auth_token="ORG-ADMIN-TOKEN-123",
            auth_token_b="ORG-USER-TOKEN-456",
            login_url="auth/login",
            output_dir=None,
            with_brain=False,
        )
        login_calls = [c for c in fake.calls if "auth/login" in c["url"]]
        assert login_calls == []

        out = capsys.readouterr().out
        assert "ORG-ADMIN-TOKEN-123" not in out
        assert "ORG-USER-TOKEN-456" not in out
        assert "supplied bearer token" in out.lower()

    def test_auth_creds_with_totp_secret_submits_mfa_body(self, monkeypatch, capsys):
        secret = base64.b32encode(b"12345678901234567890").decode()
        scripted = [
            _FakeResponse(200, {"token": "primary.token"}),
            _FakeResponse(200, {"token": "secondary.token"}),
        ]
        fake = _patch_requests(monkeypatch, scripted)
        self._stub_phases(monkeypatch)
        from autopilot_api_hunt import run_autopilot

        run_autopilot(
            base_url=self.BASE,
            auth_creds="vapt-admin@example.com:PrimarySecret",
            auth_creds_b="vapt-user@example.com:SecondarySecret",
            totp_secret=secret,
            totp_secret_b=secret,
            login_url="auth/login",
            output_dir=None,
        )

        bodies = [c["json"] for c in fake.calls if "auth/login" in c["url"] and "json" in c]
        assert len(bodies) >= 2
        for b in bodies[:2]:
            assert b["email"].startswith("vapt-")
            assert b["totp"].isdigit() and len(b["totp"]) == 6

        out = capsys.readouterr().out
        assert "PrimarySecret" not in out
        assert "SecondarySecret" not in out
        assert secret not in out
        assert "primary.token" not in out
        assert "secondary.token" not in out

    def test_auth_creds_with_extra_login_fields(self, monkeypatch):
        """--login-extra-json fields land in the JSON login body."""
        scripted = [_FakeResponse(200, {"token": "primary.token"})]
        fake = _patch_requests(monkeypatch, scripted)
        self._stub_phases(monkeypatch)
        from autopilot_api_hunt import run_autopilot

        run_autopilot(
            base_url=self.BASE,
            auth_creds="vapt-admin@example.com:PasswordHere",
            totp_code="123456",
            login_url="auth/login",
            extra_login_fields={"loginSurface": "workspace", "tenantId": "t1"},
            output_dir=None,
        )

        json_call = next(c for c in fake.calls if "json" in c)
        assert json_call["json"]["loginSurface"] == "workspace"
        assert json_call["json"]["tenantId"] == "t1"
        assert json_call["json"]["totp"] == "123456"

    def test_requires_totp_without_secret_aborts_cleanly(self, monkeypatch, capsys):
        scripted = [_FakeResponse(200, {"requiresTotp": True})] * 4
        _patch_requests(monkeypatch, scripted)
        self._stub_phases(monkeypatch)
        from autopilot_api_hunt import run_autopilot

        out_dict = run_autopilot(
            base_url=self.BASE,
            auth_creds="vapt-admin@example.com:PrimarySecret",
            login_url="auth/login",
            output_dir=None,
        )
        assert out_dict == {}
        captured = capsys.readouterr().out
        assert "requires TOTP" in captured
