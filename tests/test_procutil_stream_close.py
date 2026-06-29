"""procutil._PosixSpawnProc — captured stdout/stderr read-pipe fds must be closed once
the child is reaped (poll/kill/__del__) and on a run_capture timeout, so a long-lived
parent (the brain runs many commands per session) does not accumulate open fds.

These tests only run where the posix_spawn fast path is active (matches the existing
fork-safety suite's gate). No client identifiers — synthetic shell commands only.
"""
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import procutil  # noqa: E402

requires_posix_spawn = pytest.mark.skipif(
    not (hasattr(os, "posix_spawn") and hasattr(os, "POSIX_SPAWN_DUP2")),
    reason="posix_spawn fast path inactive on this interpreter",
)


@requires_posix_spawn
def test_poll_closes_captured_streams_after_reap():
    p = procutil._fork_safe_spawn("printf hi", capture=True, shell=True,
                                  merge_stderr=False)
    out, err = p.communicate(timeout=10)
    assert out.strip() == "hi"
    # communicate() ends by poll()/wait() which now reaps AND closes the streams.
    assert p.returncode == 0
    assert p.stdout is None, "stdout read-pipe fd should be closed (attr cleared) after reap"
    assert p.stderr is None, "stderr read-pipe fd should be closed (attr cleared) after reap"


@requires_posix_spawn
def test_kill_closes_captured_streams():
    p = procutil._fork_safe_spawn("sleep 5", capture=True, shell=True)
    assert p.stdout is not None
    p.kill()
    assert p.stdout is None, "kill() must close the captured stdout read-pipe fd"


@requires_posix_spawn
def test_close_streams_is_idempotent():
    p = procutil._fork_safe_spawn("printf x", capture=True, shell=True)
    p.communicate(timeout=10)
    # Already closed via communicate's poll; a second call must not raise.
    p._close_streams()
    p._close_streams()
    assert p.stdout is None


@requires_posix_spawn
def test_run_capture_timeout_does_not_leak_fds():
    # A child that redirects its own stdout then sleeps forces communicate() to raise
    # TimeoutExpired; the timeout handler must reap AND close the read-pipe fds.
    fd_before = len(os.listdir(f"/dev/fd")) if os.path.isdir("/dev/fd") else None
    r = procutil.run_capture("exec >/dev/null 2>&1; sleep 5", timeout=1)
    assert r["timed_out"] is True
    assert r["returncode"] == -9
    if fd_before is not None:
        fd_after = len(os.listdir("/dev/fd"))
        # Allow a small slack for transient fds, but a leaked read pipe per call would
        # grow this; without the fix two pipe fds (stdout+stderr) leak per run.
        assert fd_after <= fd_before + 1, (
            f"run_capture timeout leaked fds: before={fd_before} after={fd_after}"
        )
