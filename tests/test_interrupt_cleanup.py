"""P1 — Ctrl-C / signal must tear down the whole child process tree, not orphan it.

Regression: SIGINT during a phase raised KeyboardInterrupt in the Python parent, whose
`finally` only stopped the watchdog thread. The setsid-detached bash recon tree (nmap,
curl, subfinder, httpx, sqlmap, …) kept running orphaned; no phase was marked aborted;
coverage.json was never flushed — a resume could mistake partial output for completion.

Covers: procutil._terminate_group (real group kill + empty-group no-op), the KeyboardInterrupt
teardown in run_live / run_cmd / run_cmd_args / run_capture, the PHASE_STATUS_ABORTED marker,
and the process-wide _ACTIVE_PROCS backstop.
"""
import os
import shlex
import signal
import subprocess
import threading
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
    real_killpg = procutil.os.killpg

    def record_killpg(*args):
        called.append(args)
        return real_killpg(*args)

    monkeypatch.setattr(procutil.os, "killpg", record_killpg)
    procutil._terminate_group(proc)
    assert all(sig == 0 for _, sig in called), "an empty exited group received a signal"


def test_terminate_group_does_not_signal_observed_reused_leader_pid(monkeypatch):
    class ExitedOwnedProc:
        pid = 999321
        _vik_pgid = pid

        def poll(self):
            return 0

        def wait(self, timeout=None):
            return 0

    calls = []
    # A reaped session leader cannot remain addressable by PID. A process now
    # occupying that PID is not ours, even if it created a group with the same ID.
    monkeypatch.setattr(procutil.os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(procutil.os, "killpg", lambda pgid, sig: calls.append((pgid, sig)))
    procutil._terminate_group(ExitedOwnedProc(), grace=0)
    assert all(sig == 0 for _, sig in calls), "a reused PID/group was signalled"


def test_owned_group_absence_retires_identity_before_later_id_reuse(monkeypatch):
    class ExitedOwnedProc:
        pid = 999321
        _vik_pgid = pid

        def poll(self):
            return 0

    proc = ExitedOwnedProc()
    calls = []

    def missing(*args):
        raise ProcessLookupError()

    monkeypatch.setattr(procutil.os, "getpgid", missing)
    monkeypatch.setattr(procutil.os, "killpg", missing)
    assert not procutil._owned_group_alive(proc)
    assert proc._vik_group_gone
    monkeypatch.setattr(procutil.os, "killpg", lambda *args: calls.append(args))
    assert not procutil._owned_group_alive(proc)
    assert calls == [], "retired ownership probed a later group with the same ID"


def test_fallback_spawn_pins_owned_group(monkeypatch):
    class FallbackProc:
        pid = 999321

    captured = {}

    def fake_popen(*args, **kwargs):
        captured.update(kwargs)
        return FallbackProc()

    monkeypatch.setattr(procutil, "_POSIX_SPAWN_OK", False)
    monkeypatch.setattr(procutil.subprocess, "Popen", fake_popen)
    proc = procutil._fork_safe_spawn(["true"], shell=False, capture=False)
    assert captured["start_new_session"] is True
    assert proc._vik_pgid == proc.pid and not proc._vik_group_gone


def test_terminate_group_kills_resistant_child_after_parent_exits(tmp_path):
    marker = tmp_path / "resistant-child.pid"
    code = (
        "import os,signal,time; from pathlib import Path; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"Path({str(marker)!r}).write_text(str(os.getpid())); time.sleep(300)"
    )
    # The shell exits on SIGTERM, but its child deliberately ignores the signal.
    # Checking only the shell's poll() used to skip the required group SIGKILL.
    proc = procutil._fork_safe_spawn(
        f"{shlex.quote(sys.executable)} -c {shlex.quote(code)} & wait",
        shell=True, capture=False,
    )
    pgid = os.getpgid(proc.pid)
    child_pid = None
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if marker.exists() and marker.read_text().strip():
                child_pid = int(marker.read_text())
                break
            time.sleep(0.02)
        assert child_pid is not None, "resistant child did not become ready"
        procutil._terminate_group(proc, grace=0.2)
        assert proc.poll() is not None, "shell was not reaped"
        deadline = time.monotonic() + 3
        while _pid_alive(child_pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not _pid_alive(child_pid), "SIGTERM-resistant descendant survived parent exit"
    finally:
        # Always clean this exact test group, including on a regression failure.
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=5)


@pytest.mark.parametrize("parent_already_exited", [False, True])
def test_terminate_group_is_bounded_with_blocked_capture_reader(tmp_path, parent_already_exited):
    marker = tmp_path / "captured-child.pid"
    code = (
        "import os,signal,time; from pathlib import Path; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"Path({str(marker)!r}).write_text(str(os.getpid())); time.sleep(300)"
    )
    command = f"{shlex.quote(sys.executable)} -c {shlex.quote(code)} &"
    if not parent_already_exited:
        command += " wait"
    proc = procutil._fork_safe_spawn(command, shell=True, capture=True, merge_stderr=False)
    pgid = os.getpgid(proc.pid)
    readers_finished = threading.Event()
    teardown_finished = threading.Event()
    child_pid = None

    def communicate():
        try:
            proc.communicate(timeout=10)
        finally:
            readers_finished.set()

    def terminate():
        try:
            procutil._terminate_group(proc, grace=0.2)
        finally:
            teardown_finished.set()

    reader = threading.Thread(target=communicate, daemon=True)
    teardown = threading.Thread(target=terminate, daemon=True)
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if marker.exists() and marker.read_text().strip():
                child_pid = int(marker.read_text())
                break
            time.sleep(0.02)
        assert child_pid is not None
        if parent_already_exited:
            # Observe exit without closing the pipes: the child still owns their writers.
            os.waitpid(proc.pid, 0)
        reader.start()
        time.sleep(0.1)  # let communicate's readers block on the child's inherited pipe fds
        assert not readers_finished.is_set()
        teardown.start()
        assert teardown_finished.wait(2), "teardown deadlocked closing a pipe before group escalation"
        deadline = time.monotonic() + 3
        while _pid_alive(child_pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not _pid_alive(child_pid), "captured TERM-resistant child survived"
        assert readers_finished.wait(2), "captured readers remained blocked after group teardown"
    finally:
        # Release blocked readers even when the old teardown deadlocks, so pytest stays bounded.
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if reader.ident is not None:
            reader.join(timeout=5)
        if teardown.ident is not None:
            teardown.join(timeout=5)
        proc.wait(timeout=5)
    assert proc.stdout is None and proc.stderr is None, "captured pipe fds were not closed"


def test_terminate_group_none_is_safe():
    procutil._terminate_group(None)      # must not raise


@pytest.mark.skipif(not procutil._POSIX_SPAWN_OK, reason="posix_spawn communicate self-cleanup")
def test_communicate_timeout_kills_owned_group_after_leader_was_reaped(tmp_path):
    marker = tmp_path / "timeout-child.pid"
    code = (
        "import os,signal,time; from pathlib import Path; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"Path({str(marker)!r}).write_text(str(os.getpid())); time.sleep(300)"
    )
    proc = procutil._fork_safe_spawn(
        f"{shlex.quote(sys.executable)} -c {shlex.quote(code)} &",
        shell=True, capture=True, merge_stderr=False)
    pgid = proc.pid
    finished = threading.Event()
    outcome = []

    def communicate():
        try:
            proc.communicate(timeout=0.2)
        except subprocess.TimeoutExpired:
            outcome.append("timeout")
        finally:
            finished.set()

    reader = threading.Thread(target=communicate, daemon=True)
    try:
        os.waitpid(proc.pid, 0)
        deadline = time.monotonic() + 5
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        child_pid = int(marker.read_text().strip())
        assert _pid_alive(child_pid)
        # Registry liveness is allowed to reap a leader without closing its
        # capture pipes before the owning communicate() reaches its deadline.
        assert procutil._owned_group_alive(proc)
        reader.start()
        assert finished.wait(2), "timeout cleanup deadlocked after leader reap"
        assert outcome == ["timeout"]
        deadline = time.monotonic() + 3
        while _pid_alive(child_pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not _pid_alive(child_pid), "timeout left an owned descendant running"
        assert proc.stdout is None and proc.stderr is None
    finally:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if reader.ident is not None:
            reader.join(timeout=5)
        proc.wait(timeout=5)


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


def test_active_procs_registry_retains_group_after_leader_exit(tmp_path):
    marker = tmp_path / "registry-child.pid"
    hunt._ACTIVE_PROCS.clear()
    proc = hunt._fork_safe_spawn(
        f"sleep 300 & echo $! > {shlex.quote(str(marker))}", shell=True, capture=False)
    pgid = proc.pid
    second = None
    try:
        os.waitpid(proc.pid, 0)
        deadline = time.monotonic() + 5
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        child_pid = int(marker.read_text().strip())
        assert _pid_alive(child_pid)
        second = hunt._fork_safe_spawn("sleep 300", shell=True, capture=False)
        assert proc in hunt._ACTIVE_PROCS, "registry pruned an exited leader's live group"
        hunt._terminate_all_active_groups()
        deadline = time.monotonic() + 3
        while _pid_alive(child_pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not _pid_alive(child_pid), "backstop skipped an exited leader's live group"
        assert second.poll() is not None
        assert hunt._ACTIVE_PROCS == []
    finally:
        for group in (pgid, getattr(second, "pid", None)):
            if group is not None:
                try:
                    os.killpg(group, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        proc.wait(timeout=5)
        if second is not None:
            second.wait(timeout=5)
        hunt._ACTIVE_PROCS.clear()


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
