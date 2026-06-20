#!/usr/bin/env python3
"""Regression tests for oauth_tester.py audit-fix hardening.

Covers (SYNTHETIC data only):
  - command-injection guard: run_cmd refuses shell strings; argv list is inert
  - _netloc_is_safe rejects shell metacharacters in the host
  - run_oauth_audit skips unsafe hosts (fail-closed) and records a marker
  - coverage cap is explicit (--max-hosts) and emits a degradation marker
  - redirect_uri bypass keys off the Location host, not a bare status code
  - missing-state CSRF is flagged when an OAuth redirect omits 'state'
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import oauth_tester  # noqa: E402


def test_run_cmd_rejects_shell_string():
    with pytest.raises(TypeError):
        oauth_tester.run_cmd("curl http://127.0.0.1")


def test_netloc_safe_accepts_plain_host():
    assert oauth_tester._netloc_is_safe("https://acme.example.invalid/oauth/authorize")
    assert oauth_tester._netloc_is_safe("http://127.0.0.1:8080/login")


def test_netloc_safe_rejects_command_substitution():
    # $(...) and backticks must never reach a probe.
    assert not oauth_tester._netloc_is_safe("https://x$(id).example.invalid/oauth/authorize")
    assert not oauth_tester._netloc_is_safe("https://x`id`.example.invalid/login")
    assert not oauth_tester._netloc_is_safe("https://a;b.example.invalid/")
    assert not oauth_tester._netloc_is_safe("https://a b.example.invalid/")


def test_argv_is_inert_under_run_cmd(monkeypatch):
    """The URL is passed as a single argv element; no shell interprets it."""
    captured = {}

    def fake_run_capture(spec, timeout=None, shell=False, merge_stderr=False, **kw):
        captured["spec"] = spec
        captured["shell"] = shell
        return {"stdout": "", "stderr": "", "returncode": 0, "timed_out": False}

    monkeypatch.setattr(oauth_tester.procutil, "run_capture", fake_run_capture)
    payload = "https://x$(touch /tmp/should_not_exist).example.invalid/cb"
    oauth_tester.run_cmd(["curl", "-sk", payload])
    assert captured["shell"] is False
    # The dangerous string survives verbatim as ONE inert argv element.
    assert payload in captured["spec"]
    assert captured["spec"][0] == "curl"


def test_unsafe_host_is_skipped_and_marked(monkeypatch):
    called = {"n": 0}
    monkeypatch.setattr(oauth_tester, "run_cmd",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1) or (False, "", ""))
    findings = oauth_tester.run_oauth_audit("x$(id).example.invalid")
    # No probe ever fired against the metachar host.
    assert called["n"] == 0
    assert any(f["type"] == "unsafe_host_skipped" for f in findings)


def test_coverage_cap_is_explicit_with_marker(tmp_path, monkeypatch):
    live_dir = tmp_path / "live"
    live_dir.mkdir()
    hosts = [f"https://h{i}.example.invalid" for i in range(8)]
    (live_dir / "urls.txt").write_text("\n".join(hosts) + "\n")

    tested = []
    monkeypatch.setattr(oauth_tester, "check_cors_on_auth_endpoints",
                        lambda u: tested.append(u) or [])
    monkeypatch.setattr(oauth_tester, "check_oauth_state_entropy", lambda u: [])
    monkeypatch.setattr(oauth_tester, "check_redirect_uri_bypass", lambda u: [])
    monkeypatch.setattr(oauth_tester, "check_password_reset_host_injection", lambda u: [])

    findings = oauth_tester.run_oauth_audit(
        "acme.example.invalid", recon_dir=str(tmp_path), max_hosts=3)
    assert len(tested) == 3
    marker = [f for f in findings if f["type"] == "coverage_degraded"]
    assert marker and "5 live hosts untested" in marker[0]["detail"]


def test_no_cap_tests_all_hosts(tmp_path, monkeypatch):
    live_dir = tmp_path / "live"
    live_dir.mkdir()
    hosts = [f"https://h{i}.example.invalid" for i in range(8)]
    (live_dir / "urls.txt").write_text("\n".join(hosts) + "\n")

    tested = []
    monkeypatch.setattr(oauth_tester, "check_cors_on_auth_endpoints",
                        lambda u: tested.append(u) or [])
    monkeypatch.setattr(oauth_tester, "check_oauth_state_entropy", lambda u: [])
    monkeypatch.setattr(oauth_tester, "check_redirect_uri_bypass", lambda u: [])
    monkeypatch.setattr(oauth_tester, "check_password_reset_host_injection", lambda u: [])

    findings = oauth_tester.run_oauth_audit("acme.example.invalid", recon_dir=str(tmp_path))
    assert len(tested) == 8  # default max_hosts=0 -> unlimited
    assert not any(f["type"] == "coverage_degraded" for f in findings)


def test_redirect_bypass_requires_evil_location(monkeypatch):
    # Server redirects to a LEGIT/login page -> not a bypass.
    def legit_redirect(cmd, timeout=15):
        return True, "HTTP/1.1 302 Found\r\nLocation: https://acme.example.invalid/login\r\n", ""

    monkeypatch.setattr(oauth_tester, "run_cmd", legit_redirect)
    findings = oauth_tester.check_redirect_uri_bypass("https://acme.example.invalid")
    assert findings == []


def test_redirect_bypass_flags_evil_location(monkeypatch):
    def evil_redirect(cmd, timeout=15):
        return True, "HTTP/1.1 302 Found\r\nLocation: https://evil.com/cb?code=x\r\n", ""

    monkeypatch.setattr(oauth_tester, "run_cmd", evil_redirect)
    findings = oauth_tester.check_redirect_uri_bypass("https://acme.example.invalid")
    assert findings, "true bypass (redirect to evil.com) must be reported"
    assert all(f["type"] == "redirect_uri_bypass" for f in findings)


def test_missing_state_csrf_flagged(monkeypatch):
    # OAuth redirect issued (302 + Location) but NO state param -> CSRF finding.
    def no_state(cmd, timeout=15):
        return True, ("HTTP/1.1 302 Found\r\n"
                      "Location: https://acme.example.invalid/cb?code=abc\r\n"), ""

    monkeypatch.setattr(oauth_tester, "run_cmd", no_state)
    findings = oauth_tester.check_oauth_state_entropy("https://acme.example.invalid")
    assert any(f["type"] == "missing_oauth_state" for f in findings)


def test_non_oauth_404_not_flagged_as_missing_state(monkeypatch):
    def not_found(cmd, timeout=15):
        return True, "HTTP/1.1 404 Not Found\r\n", ""

    monkeypatch.setattr(oauth_tester, "run_cmd", not_found)
    findings = oauth_tester.check_oauth_state_entropy("https://acme.example.invalid")
    assert findings == []


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
