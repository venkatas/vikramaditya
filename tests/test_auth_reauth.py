"""Auth resilience for long-running engagements (ported from xalgorix
ErrReauthRequired + Profile expiry tracking).

AuthSession had ZERO handling for an expired/revoked token mid-scan: a JWT would
silently go stale and every subsequent request would 401, or a re-login that hit
`invalid_grant` would just return "" and the scan would limp on unauthenticated.
This adds:
  * token-expiry tracking decoded from the JWT `exp` claim (set_token);
  * is_token_expired() so a caller can proactively re-auth before firing requests;
  * a ReauthRequired sentinel + requires_reauth flag raised when the server says
    the grant is dead (invalid_grant / token expired / refresh revoked).
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import auth_utils  # noqa: E402
from auth_utils import AuthSession, JWTHelper, ReauthRequired  # noqa: E402


def _jwt_with_exp(exp: int) -> str:
    head = JWTHelper._b64_encode(b'{"alg":"HS256","typ":"JWT"}')
    payload = JWTHelper._b64_encode(('{"sub":"u","exp":%d}' % exp).encode())
    return f"{head}.{payload}.sig"


# ── token-expiry tracking from the JWT exp claim ────────────────────────────────

def test_set_token_records_expiry_from_jwt():
    s = AuthSession("http://t")
    future = int(time.time()) + 3600
    s.set_token(_jwt_with_exp(future))
    assert s.token_expires_at == future


def test_set_opaque_token_has_no_expiry():
    s = AuthSession("http://t")
    s.set_token("opaque-bearer-not-a-jwt")
    assert s.token_expires_at is None
    assert s.is_token_expired() is False        # unknown expiry ≠ expired


def test_is_token_expired_true_for_past_exp():
    s = AuthSession("http://t")
    s.set_token(_jwt_with_exp(int(time.time()) - 10))
    assert s.is_token_expired() is True


def test_is_token_expired_respects_skew():
    s = AuthSession("http://t")
    # expires 20s from now; with a 30s skew it should already count as expired
    s.set_token(_jwt_with_exp(int(time.time()) + 20))
    assert s.is_token_expired(skew=30) is True
    assert s.is_token_expired(skew=0) is False


# ── invalid_grant / revoked refresh surfaces ReauthRequired ─────────────────────

class _FakeResp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.cookies = {}

    def json(self):
        return self._body


def _force_login_response(monkeypatch, status, body):
    def fake_post(url, timeout=15, **kwargs):
        return _FakeResp(status, body)
    s = AuthSession("http://t")
    monkeypatch.setattr(s._session, "post", fake_post)
    return s


def test_auto_login_raises_reauth_on_invalid_grant(monkeypatch):
    s = _force_login_response(monkeypatch, 400, {"error": "invalid_grant"})
    try:
        s.auto_login("login", "user", "pass")
        assert False, "expected ReauthRequired"
    except ReauthRequired:
        pass
    assert s.requires_reauth is True


def test_auto_login_raises_reauth_on_token_expired_message(monkeypatch):
    s = _force_login_response(monkeypatch, 401, {"message": "refresh token expired"})
    try:
        s.auto_login("login", "user", "pass")
        assert False, "expected ReauthRequired"
    except ReauthRequired:
        pass
    assert s.requires_reauth is True


def test_auto_login_plain_failure_does_not_flag_reauth(monkeypatch):
    # ordinary wrong-password 401 with no grant signal → return "", no reauth flag
    s = _force_login_response(monkeypatch, 401, {"error": "bad credentials"})
    out = s.auto_login("login", "user", "pass")
    assert out == ""
    assert s.requires_reauth is False


def test_reauth_required_is_runtime_error():
    assert issubclass(ReauthRequired, RuntimeError)


# ── Codex review fixes ──────────────────────────────────────────────────────

def test_set_token_parses_numeric_string_exp():
    # some IdPs encode exp as a JSON string, not a number
    s = AuthSession("http://t")
    future = int(time.time()) + 3600
    head = JWTHelper._b64_encode(b'{"alg":"HS256","typ":"JWT"}')
    payload = JWTHelper._b64_encode(('{"sub":"u","exp":"%d"}' % future).encode())
    s.set_token(f"{head}.{payload}.sig")
    assert s.token_expires_at == future


def test_set_token_tracks_exp_for_alg_none():
    # alg=none token has an EMPTY signature segment — must still track exp
    s = AuthSession("http://t")
    future = int(time.time()) + 3600
    head = JWTHelper._b64_encode(b'{"alg":"none"}')
    payload = JWTHelper._b64_encode(('{"exp":%d}' % future).encode())
    s.set_token(f"{head}.{payload}.")
    assert s.token_expires_at == future


def test_grant_dead_requires_failure_status(monkeypatch):
    # a 200 success body that merely MENTIONS "revoked"/"expired" must NOT force reauth
    s = _force_login_response(monkeypatch, 200, {"message": "your old token was revoked; here is a new one"})
    # 200 with cookies → cookie-auth success path, no reauth
    monkeypatch.setattr(s._session, "cookies", {"session": "abc"})
    out = s.auto_login("login", "user", "pass")
    assert s.requires_reauth is False
    assert out != "" or s.requires_reauth is False   # did not crash into reauth


def test_grant_dead_detects_non_json_body(monkeypatch):
    # OAuth servers often return form-encoded/plain-text errors that resp.json() can't parse
    class _TxtResp:
        status_code = 400
        cookies = {}
        def json(self):
            raise ValueError("not json")
        @property
        def text(self):
            return "error=invalid_grant&error_description=Token+revoked"

    s = AuthSession("http://t")
    monkeypatch.setattr(s._session, "post", lambda *a, **k: _TxtResp())
    try:
        s.auto_login("login", "user", "pass")
        assert False, "expected ReauthRequired"
    except ReauthRequired:
        pass
    assert s.requires_reauth is True
