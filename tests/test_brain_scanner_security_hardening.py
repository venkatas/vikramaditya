"""Security-hardening tests for brain_scanner.py.

Covers:
  * execute_script FAILS CLOSED when the scopeguard module is unavailable (was
    fail-open: it would run LLM-authored code with no host-scope enforcement).
  * _is_grounded_run rejects a tool's USAGE/HELP banner as grounding.
  * _FILE_PROOF_RE accepts realistic LFI/file-read proofs (leading prefix, PHP
    source, private keys) while still rejecting a passwd-shaped shell error.

All hosts are *.example.invalid / synthetic.
"""
import pytest

import brain_scanner
from brain_scanner import _is_grounded_run, _FILE_PROOF_RE, execute_script


# ── fail-closed when scopeguard is missing ────────────────────────────────────
def test_execute_script_fails_closed_without_scopeguard(monkeypatch):
    monkeypatch.setattr(brain_scanner, "_scopeguard", None)
    monkeypatch.delenv("BRAIN_SCANNER_NO_SCOPEGUARD", raising=False)
    res = execute_script("bash", "curl http://x.example.invalid/")
    assert res.get("scope_blocked") is True
    assert res["returncode"] == 3
    assert "scopeguard" in res["stderr"].lower()


def test_execute_script_override_runs_without_scopeguard(monkeypatch):
    monkeypatch.setattr(brain_scanner, "_scopeguard", None)
    monkeypatch.setenv("BRAIN_SCANNER_NO_SCOPEGUARD", "1")
    res = execute_script("python", "print('ran')")
    assert not res.get("scope_blocked")
    assert "ran" in res["stdout"]


# ── usage/help banner is NOT grounding ────────────────────────────────────────
@pytest.mark.parametrize("stdout", [
    "Usage: curl [options...] <url>\nOptions:\n -d, --data <data>",
    "usage: sqlmap [-h] [--version] ...",
    "Try 'curl --help' for more information.",
])
def test_usage_banner_not_grounded(stdout):
    assert _is_grounded_run({"returncode": 0, "stdout": stdout, "stderr": ""}) is False


def test_real_target_output_is_grounded():
    # Real evidence (passwd content) must still ground a verdict.
    assert _is_grounded_run(
        {"returncode": 0, "stdout": "root:x:0:0:root:/root:/bin/bash\n", "stderr": ""}) is True


def test_help_with_url_still_grounded():
    # A help-shaped word but with a real URL/status is target signal, not a banner.
    out = "Options: redirected to http://x.example.invalid/login HTTP/1.1 200"
    assert _is_grounded_run({"returncode": 0, "stdout": out, "stderr": ""}) is True


# ── file-proof regex coverage ─────────────────────────────────────────────────
@pytest.mark.parametrize("stdout", [
    "root:x:0:0:root:/root:/bin/bash",
    "  root:x:0:0:root:/root:/bin/bash",            # leading whitespace
    "> root:x:0:0:root:/root:/bin/bash",            # quoted body
    '"root:x:0:0:root:/root:/bin/bash"',            # JSON value
    "<?php echo 'db_pass'; ?>",                      # PHP source disclosure
    "<?= $secret ?>",
    "-----BEGIN RSA PRIVATE KEY-----",       # example PEM header (detection fixture, not a real key)
    "-----BEGIN OPENSSH PRIVATE KEY-----",   # example PEM header (detection fixture, not a real key)
    "DB_PASSWORD=hunter2",
])
def test_file_proof_accepts(stdout):
    assert _FILE_PROOF_RE.search(stdout)


@pytest.mark.parametrize("stdout", [
    "bash: line 3: root:x:0:0:...: No such file or directory",   # shell error
    "404 Not Found",
    "connection refused",
])
def test_file_proof_rejects_non_proof(stdout):
    assert not _FILE_PROOF_RE.search(stdout)
