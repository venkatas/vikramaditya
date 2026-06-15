"""_auto_detect_login_url must not crash on a username WITHOUT an '@'.

Live-monitoring 2026-06-15 caught: authenticated Web App VAPT on client-spa.example crashed with
`UnboundLocalError: cannot access local variable 'domain_part'`. domain_part was assigned only
inside `if "@" in username:` but referenced when building CGI_LOGIN_PAGES, before its later safe
re-assignment. A plain login name (no '@') left it unbound. Fix: define it unconditionally up front.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import requests  # noqa: E402

import autopilot_api_hunt as ah  # noqa: E402


class _FakeSession:
    """Minimal AuthSession stand-in: no login ever succeeds, so the function exercises every
    login-discovery branch (incl. the CGI_LOGIN_PAGES build where domain_part was referenced).
    Uses a real requests.Session() for ._session so cookies/headers behave like the real thing."""
    base_url = "http://127.0.0.1:1"

    def __init__(self):
        self._session = requests.Session()

    def auto_login(self, *a, **k):
        return ""           # no token → keep trying other paths

    def set_token(self, *a, **k):
        pass


def _offline(monkeypatch):
    def _raise(*a, **k):
        raise ConnectionError("offline test")
    monkeypatch.setattr("requests.get", _raise)
    monkeypatch.setattr("requests.post", _raise)


def test_auto_detect_login_no_at_username_does_not_crash(monkeypatch):
    _offline(monkeypatch)
    # username WITHOUT '@' previously hit UnboundLocalError when building CGI_LOGIN_PAGES
    tok, path = ah._auto_detect_login_url(_FakeSession(), "adminuser", "pw")
    assert (tok, path) == ("", "")


def test_auto_detect_login_email_username_also_ok(monkeypatch):
    _offline(monkeypatch)
    tok, path = ah._auto_detect_login_url(_FakeSession(), "dpo@acme.example", "pw")
    assert (tok, path) == ("", "")
