"""Codex-review fixes for the posix_spawn routing (commit 83aa87e):

#2 (FP-discipline regression): execute_script must keep stdout/stderr SEPARATE.
   The fork-safe spawner merged stderr->stdout, but brain_scanner's tooling-error
   detector scans `stderr` for Python tracebacks / ModuleNotFoundError / command-not-
   found. Merged, a CRASHED exploit script (zero target evidence) was silently counted
   as a successful run — letting the model issue a verdict after no real testing. A
   *target* returning a traceback (a real info-disclosure finding) lands in stdout, so
   the two must stay distinct.

#1: run_capture must reap the child on timeout (no zombies).

#3: a `bash -n` syntax-check TIMEOUT must not be misreported as a syntax error.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import procutil  # noqa: E402
import brain_scanner  # noqa: E402


# ── procutil.run_capture stream handling ──────────────────────────────────────

def test_run_capture_separates_stderr_when_requested():
    r = procutil.run_capture(["bash", "-c", "echo OUT; echo ERRLINE >&2"],
                             timeout=10, shell=False, merge_stderr=False)
    assert r["returncode"] == 0
    assert "OUT" in r["stdout"] and "ERRLINE" not in r["stdout"]
    assert "ERRLINE" in r["stderr"]


def test_run_capture_merges_stderr_by_default():
    # hunt.py relies on the merged single-stream behavior — must stay the default.
    r = procutil.run_capture(["bash", "-c", "echo OUT; echo ERRLINE >&2"],
                             timeout=10, shell=False)
    assert "OUT" in r["stdout"] and "ERRLINE" in r["stdout"]
    assert r["stderr"] == ""


def test_run_capture_timeout_reports_and_reaps():
    r = procutil.run_capture(["bash", "-c", "sleep 30"], timeout=0.3, shell=False)
    assert r["timed_out"] is True
    assert r["returncode"] == -9


# ── brain_scanner.execute_script regression: crash → stderr (detectable) ───────

def test_execute_script_python_crash_lands_in_stderr():
    r = brain_scanner.execute_script("python", "import nonexistent_module_xyz_123")
    assert r["returncode"] != 0
    up = (r["stderr"] or "").upper()
    assert "MODULENOTFOUNDERROR" in up or "TRACEBACK (MOST RECENT CALL LAST)" in up, (
        "a crashed script's traceback must be in stderr so the tooling-error detector "
        f"catches it; got stderr={r['stderr']!r} stdout={r['stdout'][:200]!r}"
    )


def test_execute_script_stdout_and_stderr_are_separate():
    r = brain_scanner.execute_script("bash", "echo real_target_output; echo my_script_warning >&2")
    assert "real_target_output" in r["stdout"]
    assert "real_target_output" not in (r["stderr"] or "")
    assert "my_script_warning" in (r["stderr"] or "")


# ── #3: bash -n syntax-check TIMEOUT must not be reported as a syntax error ─────

def test_execute_script_syntax_check_timeout_not_misreported(monkeypatch):
    calls = {"n": 0}

    def fake_run_capture(spec, timeout=None, env=None, cwd=None, shell=True, merge_stderr=True):
        calls["n"] += 1
        if calls["n"] == 1:  # the `bash -n` syntax pre-check times out
            return {"stdout": "", "stderr": "TIMEOUT after 15s", "returncode": -9, "timed_out": True}
        return {"stdout": "ran", "stderr": "", "returncode": 0, "timed_out": False}  # main exec

    monkeypatch.setattr(brain_scanner.procutil, "run_capture", fake_run_capture)
    r = brain_scanner.execute_script("bash", "echo hi")
    assert not r.get("syntax_error"), "a syntax-check TIMEOUT must not be flagged as a script syntax error"


# ── ask_brain must request a LARGE num_ctx (else multi-iteration verify overflows
#    the default ~4096 ctx → empty responses → the engine ABORTS mid-PoC = "backs off")

def test_ask_brain_requests_large_num_ctx(monkeypatch):
    import ollama
    monkeypatch.setenv("BRAIN_PROVIDER", "ollama")
    captured = {}

    def fake_chat(model=None, messages=None, options=None, **kw):
        captured["options"] = options or {}
        return {"message": {"content": "ok"}}

    monkeypatch.setattr(ollama, "chat", fake_chat)
    brain_scanner.ask_brain("ravenx-cyberagent:latest", [{"role": "user", "content": "hi"}])
    assert captured["options"].get("num_ctx", 0) >= 8192, (
        "brain_scanner.ask_brain omitted num_ctx → the exploit-verification loop overflows the "
        "model's tiny default context after iteration 1 and the brain returns empty responses, "
        f"aborting the PoC. Got options={captured['options']}"
    )
