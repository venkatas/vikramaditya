"""hunt._run_authz_audit — best-effort authz/IDOR/PII audit over the authenticated
session, writing <findings_dir>/authz/findings.json for reporter Method 1i.

Uses a synthetic injected fetcher (no network). SYNTHETIC data only.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import hunt  # noqa: E402


def _fake_fetcher_factory():
    # low-priv (authed) session reaches an admin page; unauthenticated is gated => confirmed BFLA
    admin = {"/AdminQueue": (200, "<h1>Approval Queue</h1><table>r</table><a href='/logout'>Logout</a>", "")}

    def cookie_fetcher(base, cookie, **kw):
        if cookie:
            return lambda p: admin.get(p, (404, "", ""))
        return lambda p: (302, "", "/login")
    return cookie_fetcher


def test_run_authz_audit_writes_findings_json(tmp_path, monkeypatch):
    import authz_audit_run
    monkeypatch.setattr(authz_audit_run, "cookie_fetcher", _fake_fetcher_factory())
    fd = str(tmp_path / "findings")
    os.makedirs(fd)
    n = hunt._run_authz_audit("app.invalid", fd, "ASP.NET_SessionId=x")
    p = os.path.join(fd, "authz", "findings.json")
    assert os.path.exists(p), "authz/findings.json must be written"
    rows = json.load(open(p))
    assert any(r["source"] == "authz_audit" for r in rows)
    assert any(r["type"] == "auth_bypass" for r in rows)   # the confirmed BFLA
    assert n >= 1


def test_run_authz_audit_noop_without_cookie(tmp_path):
    fd = str(tmp_path)
    assert hunt._run_authz_audit("app.invalid", fd, "") == 0
    assert not os.path.exists(os.path.join(fd, "authz", "findings.json"))


def test_run_authz_audit_respects_env_optout(tmp_path, monkeypatch):
    monkeypatch.setenv("VIK_NO_AUTHZ_AUDIT", "1")
    assert hunt._run_authz_audit("app.invalid", str(tmp_path), "c") == 0


def test_run_authz_audit_never_raises_on_bad_target(tmp_path, monkeypatch):
    # a fetcher that explodes must be swallowed (best-effort; never breaks the pipeline)
    import authz_audit_run

    def boom(base, cookie, **kw):
        def g(p):
            raise RuntimeError("network down")
        return g
    monkeypatch.setattr(authz_audit_run, "cookie_fetcher", boom)
    assert hunt._run_authz_audit("app.invalid", str(tmp_path), "c") == 0
