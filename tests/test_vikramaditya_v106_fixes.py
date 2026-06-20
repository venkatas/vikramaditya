"""Regression tests for the v10.6.0 vikramaditya.py audit fixes.

All data here is SYNTHETIC (example.invalid / placeholder tokens).

Covers:
  1. run_hunt / run_report route through the fork-safe streaming helper
     (procutil posix_spawn) instead of raw subprocess.run — avoids the macOS
     Network.framework fork()+exec SIGSEGV after in-process HTTP fingerprinting.
  2. _run_streaming uses procutil's _fork_safe_spawn with capture=False/shell=False.
  3. config.lock.json redaction masks --llm-auth and sensitive --header values.
  4. _mark_fallback_degraded records a coverage-degradation marker so a crashed
     sqlmap/nuclei fallback is never silently reported as a clean "No findings".
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import vikramaditya  # noqa: E402


# ── 1 & 2: fork-safe launch routing ───────────────────────────────────────────

def test_run_hunt_uses_fork_safe_streaming(monkeypatch):
    seen = {}
    monkeypatch.setattr(vikramaditya, "_run_streaming",
                        lambda cmd, **kw: seen.setdefault("cmd", cmd) or 0)
    vikramaditya.run_hunt("example.invalid", full=True)
    assert "cmd" in seen, "run_hunt must launch via _run_streaming (fork-safe)"
    assert "hunt.py" in " ".join(seen["cmd"])


def test_run_report_uses_fork_safe_streaming(monkeypatch):
    seen = {}
    monkeypatch.setattr(vikramaditya, "_run_streaming",
                        lambda cmd, **kw: seen.setdefault("cmd", cmd) or 0)
    vikramaditya.run_report("/tmp/findings_does_not_matter", client="acme")
    assert "cmd" in seen
    assert "reporter.py" in " ".join(seen["cmd"])
    assert "--client" in seen["cmd"] and "acme" in seen["cmd"]


def test_run_streaming_spawns_fork_safe_no_shell(monkeypatch):
    """_run_streaming must use procutil._fork_safe_spawn with shell=False and
    capture=False (so output streams), NOT a raw fork()+exec subprocess.run."""
    captured = {}

    class _FakeProc:
        def wait(self):
            return 0

    def _fake_spawn(cmd, env=None, cwd=None, capture=True, shell=True, **kw):
        captured.update(cmd=cmd, capture=capture, shell=shell)
        return _FakeProc()

    monkeypatch.setattr(vikramaditya, "_fork_safe_spawn", _fake_spawn)
    rc = vikramaditya._run_streaming(["echo", "hi"])
    assert rc == 0
    assert captured["shell"] is False
    assert captured["capture"] is False
    assert captured["cmd"] == ["echo", "hi"]


# ── 3: config.lock.json redaction ─────────────────────────────────────────────

def _redacted_argv(monkeypatch, argv, tmp_path):
    """Run make_output_dir with a synthetic argv and return the persisted argv."""
    written = {}

    def _fake_write(out_dir, args=None):
        written["argv"] = args["argv"]

    # Stub the config-lock writer so we inspect the redacted argv without disk I/O.
    import whitebox.config_lock as cl
    monkeypatch.setattr(cl, "write_session_lock", _fake_write)
    monkeypatch.setattr(vikramaditya, "SCRIPT_DIR", str(tmp_path))
    monkeypatch.setattr(vikramaditya.sys, "argv", ["vikramaditya.py"] + argv)
    vikramaditya.make_output_dir("example.invalid")
    return written.get("argv", [])


def test_llm_auth_token_redacted(monkeypatch, tmp_path):
    argv = ["example.invalid", "--llm-auth", "Authorization: Bearer PLACEHOLDER_TOKEN_XYZ"]
    out = _redacted_argv(monkeypatch, argv, tmp_path)
    assert "PLACEHOLDER_TOKEN_XYZ" not in " ".join(out)
    assert "***" in out


def test_llm_auth_equals_form_redacted(monkeypatch, tmp_path):
    argv = ["example.invalid", "--llm-auth=Authorization: Bearer PLACEHOLDER_TOKEN_XYZ"]
    out = _redacted_argv(monkeypatch, argv, tmp_path)
    assert "PLACEHOLDER_TOKEN_XYZ" not in " ".join(out)
    assert any(a.startswith("--llm-auth=***") for a in out)


def test_header_authorization_value_redacted(monkeypatch, tmp_path):
    argv = ["example.invalid", "--header", "Authorization: Bearer PLACEHOLDER_TOKEN_XYZ"]
    out = _redacted_argv(monkeypatch, argv, tmp_path)
    joined = " ".join(out)
    assert "PLACEHOLDER_TOKEN_XYZ" not in joined
    # Header NAME stays visible (it is not itself a secret), value masked.
    assert "Authorization: ***" in out


def test_header_cookie_value_redacted(monkeypatch, tmp_path):
    argv = ["example.invalid", "--header", "Cookie: session=PLACEHOLDER_SESSION"]
    out = _redacted_argv(monkeypatch, argv, tmp_path)
    assert "PLACEHOLDER_SESSION" not in " ".join(out)
    assert "Cookie: ***" in out


def test_header_nonsensitive_value_preserved(monkeypatch, tmp_path):
    argv = ["example.invalid", "--header", "Accept: application/json"]
    out = _redacted_argv(monkeypatch, argv, tmp_path)
    # A non-credential header must NOT be redacted (would lose config-drift signal).
    assert "Accept: application/json" in out


# ── 4: degradation marker ──────────────────────────────────────────────────────

def test_mark_fallback_degraded_writes_marker(tmp_path):
    vikramaditya._mark_fallback_degraded(str(tmp_path), "nuclei", "rc=-11")
    marker = os.path.join(str(tmp_path), "coverage_degraded.json")
    assert os.path.isfile(marker)
    data = json.load(open(marker))
    assert data and data[0]["tool"] == "nuclei"
    assert "rc=-11" in data[0]["reason"]
    assert data[0]["phase"] == "autopilot_fallback"


def test_mark_fallback_degraded_dedupes_and_appends(tmp_path):
    vikramaditya._mark_fallback_degraded(str(tmp_path), "sqlmap", "timeout")
    vikramaditya._mark_fallback_degraded(str(tmp_path), "sqlmap", "timeout")  # dup
    vikramaditya._mark_fallback_degraded(str(tmp_path), "nuclei", "rc=-9")
    data = json.load(open(os.path.join(str(tmp_path), "coverage_degraded.json")))
    tools = sorted(d["tool"] for d in data)
    assert tools == ["nuclei", "sqlmap"]  # sqlmap deduped, nuclei appended
