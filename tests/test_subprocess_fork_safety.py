"""Regression guard: never launch subprocesses with preexec_fn=os.setsid, and keep
the legacy launchers' killpg-able process group.

`preexec_fn` runs arbitrary Python in the child AFTER fork() but BEFORE exec() and is
unsafe with threads, so it must never be reintroduced. NOTE, however, that switching
preexec_fn -> start_new_session was NOT what cured the observed `rc=-11 / SIGSEGV at
0.0s` crashes (sqlmap, cve.py, AND reporter.py): both flags force CPython's fork()+exec
path, and the real culprit is Apple's Network.framework registering a non-fork-safe
pthread_atfork CHILD handler that SIGSEGVs in the forked child before exec. The actual
fix is to launch via os.posix_spawn (which does not run atfork handlers) — guarded by
tests/test_posix_spawn_fork_safety.py. These checks remain valid: preexec_fn=os.setsid
must stay gone, and the fallback launchers still create their own session for killpg.
"""
import os
import signal
import subprocess
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
# Modules that spawn external scan tools with a watchdog process-group kill.
LAUNCHER_FILES = ["hunt.py", "cve.py", "fuzzer.py", "oauth_tester.py"]


def _py_sources():
    for p in REPO.glob("*.py"):
        yield p
    for p in (REPO / "whitebox").rglob("*.py"):
        yield p


def test_no_unsafe_preexec_setsid_anywhere():
    offenders = []
    for p in _py_sources():
        if "/tests/" in str(p):
            continue
        txt = p.read_text(encoding="utf-8", errors="replace")
        if "preexec_fn=os.setsid" in txt or "preexec_fn = os.setsid" in txt:
            offenders.append(p.name)
    assert offenders == [], f"unsafe preexec_fn=os.setsid (fork-segfault risk) in: {offenders}"


def test_launchers_use_start_new_session():
    for fname in LAUNCHER_FILES:
        txt = (REPO / fname).read_text(encoding="utf-8", errors="replace")
        assert "start_new_session=True" in txt, f"{fname} no longer sets start_new_session=True"


def test_start_new_session_yields_killable_process_group():
    # The behaviour the watchdog relies on: the child is its own session/group
    # leader, so os.killpg(getpgid(pid)) kills the whole tree.
    p = subprocess.Popen("sleep 30", shell=True, start_new_session=True)
    try:
        assert os.getpgid(p.pid) == p.pid  # child is the process-group leader
        os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        for _ in range(50):
            if p.poll() is not None:
                break
            time.sleep(0.05)
        assert p.poll() is not None  # killpg terminated it
    finally:
        if p.poll() is None:
            p.kill()
