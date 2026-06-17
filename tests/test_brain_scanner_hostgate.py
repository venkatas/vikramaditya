"""brain_scanner.execute_script must REFUSE LLM-authored code that targets the operator's
own machine/listener — never execute it (v10.6.0 host-gating).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import brain_scanner  # noqa: E402


def test_execute_script_blocks_loopback_target():
    r = brain_scanner.execute_script("bash", "curl -s http://127.0.0.1:8137/admin")
    assert r.get("scope_blocked") is True
    assert r["returncode"] == 3
    assert "127.0.0.1" in r["stderr"]


def test_execute_script_blocks_localhost():
    r = brain_scanner.execute_script("bash", "sqlmap -u http://localhost/login --batch")
    assert r.get("scope_blocked") is True


def test_execute_script_allows_external_target():
    # a harmless external echo must run normally (no scope block)
    r = brain_scanner.execute_script("bash", "echo scanning https://example.com/api")
    assert not r.get("scope_blocked")
    assert r["returncode"] == 0
    assert "example.com" in r["stdout"]


def test_execute_script_allows_cloud_metadata_ssrf(monkeypatch):
    # 169.254.169.254 is a legitimate SSRF target — must NOT be blocked
    r = brain_scanner.execute_script("bash", "echo curl http://169.254.169.254/latest/meta-data/")
    assert not r.get("scope_blocked")
