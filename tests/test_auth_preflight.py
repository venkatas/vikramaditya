"""hunt.py::_verify_authenticated — pre-flight a --cookie web-app scan.

A --cookie that isn't actually logged in (expired/wrong, or lost behind an AWS-ALB
without session stickiness) otherwise scans the UNAUTHENTICATED surface and reports a
false-negative "0 findings" for the whole protected app. The pre-flight detects that and
flags it (the run then marks authenticated coverage UNRELIABLE rather than "clean").

Cases below are the codex+grok review/test set: IdP/SSO redirects, JSON/API unauth,
WWW-Authenticate, meta-refresh, classic login forms — all must be caught — while a
genuinely authenticated page (incl. one that merely contains a change-password widget)
must NOT be flagged. CONSERVATIVE: never blocks a real authed scan (flag-only).
"""
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import hunt  # noqa: E402


class _Hdrs(dict):
    def get(self, k, d=""):
        for kk, vv in self.items():
            if kk.lower() == k.lower():
                return vv
        return d


def _resp(status=200, text="", ctype="text/html", url="https://t/x", headers=None, history=None):
    m = MagicMock()
    m.status_code = status
    m.text = text
    m.url = url
    h = {"Content-Type": ctype}
    if headers:
        h.update(headers)
    m.headers = _Hdrs(h)
    m.cookies = []
    m.history = history or []
    return m


def _check(resp):
    with patch("requests.get", return_value=resp):
        return hunt._verify_authenticated("t.example.com", "sid=abc")[0]


def test_no_cookie_is_not_flagged():
    assert hunt._verify_authenticated("t.example.com", "")[0] is True


def test_unauthenticated_signals_are_caught():
    assert _check(_resp(401)) is False
    assert _check(_resp(403)) is False
    assert _check(_resp(200, headers={"WWW-Authenticate": "Bearer"})) is False
    assert _check(_resp(200, '{"error":"unauthorized"}', ctype="application/json")) is False
    assert _check(_resp(200, '{"authenticated":false}', ctype="application/json")) is False
    # IdP / SSO redirect anywhere in the chain
    assert _check(_resp(200, "<html>x</html>",
                  url="https://login.microsoftonline.com/x/oauth2/authorize",
                  history=[MagicMock(url="https://t/x")])) is False
    assert _check(_resp(200, '<meta http-equiv="refresh" content="0;url=/login">')) is False
    assert _check(_resp(200, '<input name="txtUserName"><input type="password" name="txtPassword">')) is False
    assert _check(_resp(200, "Your session has expired. Please log in.")) is False


def test_authenticated_pages_are_not_false_flagged():
    # normal dashboard
    assert _check(_resp(200, '<h1>Welcome</h1><a href="/logout">Sign out</a>')) is True
    # authed page that merely contains a change-password widget (password input + logout link)
    assert _check(_resp(200, '<input type="password" name="newpwd"><a href="/logout">Logout</a>')) is True


def test_url_without_scheme_is_not_treated_as_schemed():
    # 'httpbin.org' starts with 'http' but is NOT a full URL — must get https:// prefixed
    captured = {}

    def fake_get(url, **kw):
        captured["url"] = url
        return _resp(200, '<h1>ok</h1>')
    with patch("requests.get", side_effect=fake_get):
        hunt._verify_authenticated("httpbin.org", "sid=abc")
    assert captured["url"].startswith("https://httpbin.org")
