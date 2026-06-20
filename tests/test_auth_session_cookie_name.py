"""auth_utils.AuthSession — explicit-token requests must carry the token under the
cookie name the server actually uses, not a hardcoded 'cf_at'.

Cookie-only (non-Bearer) apps that authenticate via e.g. an 'access_token' cookie were
falsely 401'd because request(token=<jwt>) always set cookies['cf_at'] regardless of the
real cookie name. auto_login() now records the matched cookie name in
self._auth_cookie_name (default 'cf_at') and request() honours it.

Pure offline test — no network. Uses *.example.invalid only.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import auth_utils  # noqa: E402


def _new_session():
    return auth_utils.AuthSession("https://app.example.invalid")


def test_default_auth_cookie_name_is_cf_at():
    s = _new_session()
    assert s._auth_cookie_name == "cf_at"


def test_request_uses_recorded_cookie_name_for_explicit_token(monkeypatch):
    s = _new_session()
    # Simulate auto_login having observed the server set the JWT in 'access_token'.
    s._auth_cookie_name = "access_token"

    captured = {}

    class _Resp:
        status_code = 200
        headers = {}

        def json(self):
            return {"ok": True}

    def _fake_request(method, url, **kwargs):
        captured["cookies"] = kwargs.get("cookies")
        return _Resp()

    import requests as _req
    monkeypatch.setattr(_req, "request", _fake_request)

    jwt = "aaa.bbb.ccc"
    s.request("GET", "/me", token=jwt)

    assert captured["cookies"] == {"access_token": jwt}, (
        "explicit-token request must send the token under the recorded cookie name"
    )


def test_request_defaults_to_cf_at_when_unset(monkeypatch):
    s = _new_session()  # never logged in -> default cf_at

    captured = {}

    class _Resp:
        status_code = 200
        headers = {}

        def json(self):
            return {"ok": True}

    def _fake_request(method, url, **kwargs):
        captured["cookies"] = kwargs.get("cookies")
        return _Resp()

    import requests as _req
    monkeypatch.setattr(_req, "request", _fake_request)

    s.request("GET", "/me", token="aaa.bbb.ccc")
    assert captured["cookies"] == {"cf_at": "aaa.bbb.ccc"}
