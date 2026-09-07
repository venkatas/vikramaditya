"""P1 — Ctrl-C / signal must tear down the whole child process tree, not orphan it.

Regression: SIGINT during a phase raised KeyboardInterrupt in the Python parent, whose
`finally` only stopped the watchdog thread. The setsid-detached bash recon tree (nmap,
curl, subfinder, httpx, sqlmap, …) kept running orphaned; no phase was marked aborted;
coverage.json was never flushed — a resume could mistake partial output for completion.

Covers: procutil._terminate_group (real group kill + poll-first no-op), the KeyboardInterrupt
teardown in run_live / run_cmd / run_cmd_args / run_capture, the PHASE_STATUS_ABORTED marker,
and the process-wide _ACTIVE_PROCS backstop.
"""
import os
import signal
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
import sys
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import procutil  # noqa: E402
import hunt  # noqa: E402


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


# ── _terminate_group: real process-group teardown ────────────────────────────
def test_terminate_group_kills_whole_tree(tmp_path):
    marker = tmp_path / "gc.pid"
    # bash (session leader) backgrounds a grandchild sleeper, records its pid, then waits
    proc = procutil._fork_safe_spawn(
        f"sleep 300 & echo $! > {marker}; wait", shell=True, capture=False)
    for _ in range(50):
        if marker.exists() and marker.read_text().strip():
            break
        time.sleep(0.1)
    gc_pid = int(marker.read_text().strip())
    assert _pid_alive(gc_pid), "grandchild never started"

    procutil._terminate_group(proc)
    time.sleep(0.4)
    assert not _pid_alive(gc_pid), "grandchild survived group termination (orphaned)"
    assert proc.poll() is not None, "parent not reaped"


def test_terminate_group_noop_on_exited(monkeypatch):
    proc = procutil._fork_safe_spawn("true", shell=True, capture=False)
    proc.wait(timeout=5)
    called = []
    monkeypatch.setattr(procutil.os, "killpg", lambda *a: called.append(a))
    procutil._terminate_group(proc)      # poll-first: must NOT signal an exited PID
    assert called == [], "killpg called on an already-exited process (PID-reuse hazard)"


def test_terminate_group_none_is_safe():
    procutil._terminate_group(None)      # must not raise


# ── launcher interrupt paths: kill group + re-raise ──────────────────────────
class _KIProc:
    """Fake proc whose blocking call raises KeyboardInterrupt (simulates Ctrl-C)."""
    pid = 999321
    returncode = None

    def wait(self, timeout=None):
        raise KeyboardInterrupt()

    def communicate(self, timeout=None):
        raise KeyboardInterrupt()

    def poll(self):
        return None


def _stub_watchdog(*a, **k):
    return type("W", (), {"stop": lambda self: None, "killed": False, "blocked": False})()


def test_run_live_kills_group_on_sigint(monkeypatch):
    hunt._reset_degraded()
    killed = {}
    monkeypatch.setattr(hunt, "_fork_safe_spawn", lambda *a, **k: _KIProc())
    monkeypatch.setattr(hunt, "_terminate_group", lambda proc, **k: killed.setdefault("p", proc))
    monkeypatch.setattr(hunt, "ProcessWatchdog", _stub_watchdog)
    with pytest.raises(KeyboardInterrupt):
        hunt.run_live("sleep 1", watch_file=None, watch_phase="RECON")
    assert killed.get("p") is not None, "_terminate_group not called from run_live on SIGINT"
    assert any(d["reason"].startswith("ABORTED —") for d in hunt._DEGRADED_CAPABILITIES), \
        "run_live did not mark the phase aborted"


def test_run_cmd_simple_path_kills_group_on_sigint(monkeypatch):
    hunt._reset_degraded()
    killed = {}
    monkeypatch.setattr(hunt, "_fork_safe_spawn", lambda *a, **k: _KIProc())
    monkeypatch.setattr(hunt, "_terminate_group", lambda proc, **k: killed.setdefault("p", proc))
    with pytest.raises(KeyboardInterrupt):
        hunt.run_cmd("sleep 1")            # watch_file=None → simple communicate path
    assert killed.get("p") is not None, "_terminate_group not called from run_cmd on SIGINT"


def test_run_capture_kills_group_on_sigint(monkeypatch):
    killed = {}
    monkeypatch.setattr(procutil, "_fork_safe_spawn", lambda *a, **k: _KIProc())
    monkeypatch.setattr(procutil, "_terminate_group", lambda proc, **k: killed.setdefault("p", proc))
    with pytest.raises(KeyboardInterrupt):
        procutil.run_capture("sleep 1")
    assert killed.get("p") is not None, "_terminate_group not called from run_capture on SIGINT"


# ── aborted phase status + coverage marker ───────────────────────────────────
def test_phase_status_aborted_defined():
    assert hunt.PHASE_STATUS_ABORTED == "aborted"
    assert hunt._PHASE_STATUS_GLYPH.get(hunt.PHASE_STATUS_ABORTED), "no glyph for aborted status"


def test_mark_aborted_records_coverage():
    hunt._reset_degraded()
    hunt._mark_aborted("recon", "user interrupt (SIGINT)")
    assert any(d["tool"] == "recon" and d["reason"].startswith("ABORTED —")
               for d in hunt._DEGRADED_CAPABILITIES)


# ── process-wide backstop: registry + terminate-all ──────────────────────────
def test_active_procs_registry_terminates_live_group():
    hunt._ACTIVE_PROCS.clear()
    proc = hunt._fork_safe_spawn("sleep 300", shell=True, capture=False)
    assert proc in hunt._ACTIVE_PROCS, "spawned proc not registered in _ACTIVE_PROCS"
    assert proc.poll() is None
    hunt._terminate_all_active_groups()
    time.sleep(0.3)
    assert proc.poll() is not None, "registered live group not terminated by backstop"
    assert hunt._ACTIVE_PROCS == [], "registry not cleared after terminate-all"


# ── source-assertions: every launcher tears down + re-raises ─────────────────
def test_all_launchers_have_sigint_teardown():
    h = (REPO / "hunt.py").read_text()
    p = (REPO / "procutil.py").read_text()
    # every launcher catches KeyboardInterrupt and calls _terminate_group then re-raises
    assert h.count("except KeyboardInterrupt:") >= 4, "not all hunt.py launchers handle SIGINT"
    assert "_terminate_group" in h and "raise" in h
    assert "except KeyboardInterrupt:" in p and "_terminate_group(proc)" in p
    # the __main__ net installs the backstop and exits non-zero (130), never 0
    assert "_terminate_all_active_groups" in h and "sys.exit(130)" in h
    assert "signal.SIGTERM, _sigterm_abort_handler" in h
