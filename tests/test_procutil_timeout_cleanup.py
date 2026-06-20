"""procutil._PosixSpawnProc — timeout/__del__ self-cleanup regressions.

Two latent-leak fixes:
  1. communicate(timeout=...) must kill+reap the child and close pty/read fds on
     timeout, so a future direct caller (catching TimeoutExpired the way one does with
     real subprocess.Popen.communicate()) does not leak the still-running child plus the
     daemon reader threads' read-pipe fds plus the pty master.
  2. __del__ must force-kill+reap a STILL-RUNNING child (single WNOHANG returning (0,0)
     previously left a terminate()-only background child as a lingering zombie).

These tests only run where the posix_spawn fast path is active. Synthetic shell
commands only — no client identifiers.
"""
import errno
import os
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import procutil  # noqa: E402

requires_posix_spawn = pytest.mark.skipif(
    not (hasattr(os, "posix_spawn") and hasattr(os, "POSIX_SPAWN_DUP2")),
    reason="posix_spawn fast path inactive on this interpreter",
)


def _alive(pid):
    """True if pid is still a live (non-reaped, non-zombie) process we can signal."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


@requires_posix_spawn
def test_communicate_timeout_kills_child_and_closes_fds():
    # Child sleeps far longer than the timeout and writes nothing -> reader threads block.
    p = procutil._fork_safe_spawn("sleep 30", capture=True, shell=True,
                                  merge_stderr=False)
    pid = p.pid
    assert p.stdout is not None
    with pytest.raises(subprocess.TimeoutExpired):
        p.communicate(timeout=0.3)
    # Read-pipe fds closed (attrs cleared) so the blocked daemon readers were unblocked.
    assert p.stdout is None, "stdout read-pipe fd should be closed on timeout"
    assert p.stderr is None, "stderr read-pipe fd should be closed on timeout"
    # Child (and its session group) was SIGKILLed — give the reaper a beat, then confirm
    # it is gone (reaped, not a lingering process).
    deadline = time.time() + 5
    while _alive(pid) and time.time() < deadline:
        # Best-effort reap in case the test harness is the parent of a not-yet-waited pid.
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            break
        except OSError as e:
            if e.errno == errno.ECHILD:
                break
        time.sleep(0.05)
    assert not _alive(pid), "child should be force-killed on communicate() timeout"


@requires_posix_spawn
def test_communicate_timeout_pty_master_closed():
    p = procutil._fork_safe_spawn("sleep 30", capture=True, shell=True,
                                  pty_stdin=True)
    assert p._pty_master is not None
    with pytest.raises(subprocess.TimeoutExpired):
        p.communicate(timeout=0.3)
    assert p._pty_master is None, "pty master fd should be closed on timeout"


@requires_posix_spawn
def test_del_force_kills_and_reaps_still_running_child():
    # Mirror the hunt.py interactsh path: terminate() (SIGTERM only) then drop the ref.
    # SIGTERM is ignored here so the child is still running at __del__ time, exercising
    # the WNOHANG==(0,0) -> SIGKILL+reap escalation.
    p = procutil._fork_safe_spawn(
        "trap '' TERM; sleep 30", capture=True, shell=True)
    pid = p.pid
    # Let the trap install.
    time.sleep(0.2)
    p.terminate()  # SIGTERM, ignored by the trap; child keeps running
    time.sleep(0.1)
    assert _alive(pid), "precondition: child should still be running after ignored SIGTERM"
    # Drop the only reference -> __del__ must SIGKILL + blocking-reap.
    del p
    import gc
    gc.collect()
    deadline = time.time() + 5
    while _alive(pid) and time.time() < deadline:
        time.sleep(0.05)
    assert not _alive(pid), "__del__ should force-kill+reap a still-running child"
