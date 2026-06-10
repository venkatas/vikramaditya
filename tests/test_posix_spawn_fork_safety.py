"""Regression guard: hunt.py's process launchers must not run pthread_atfork
child handlers.

ROOT CAUSE THIS GUARDS AGAINST
------------------------------
On macOS, hunt.py's parent loads Apple's Network.framework (via in-process HTTP/TLS
and, on hosts with a VPN/endpoint-filter NetworkExtension, NEFlowDirector). That
framework registers a NON-fork-safe ``pthread_atfork`` *child* handler
(``nw_settings_child_has_forked`` -> ``os_log`` -> ``_os_log_preferences_refresh``).
Any ``subprocess.Popen`` that takes the ``fork()+exec`` path runs that handler in the
forked child *before* exec and SIGSEGVs at 0.0s. Observed: SQLMAP, CVE HUNT and the
final REPORTS phase all died ``rc=-11 duration=0.0s`` (the run produced 0 reports).

``preexec_fn=os.setsid`` and ``start_new_session=True`` BOTH force the fork() path, so
the earlier "fork-safety" change was a non-fix. ``os.posix_spawn`` does NOT run
``pthread_atfork`` handlers, so launching via posix_spawn eliminates the entire class
of "Apple framework not fork-safe" crashes while keeping ``setsid`` for killpg.

HOW THE TEST WORKS
------------------
We can't reproduce the Network.framework trigger in CI (it depends on host
NetworkExtension state), but we can reproduce the *mechanism* deterministically: we
register our own hostile child atfork handler that ``abort()``s. If a launcher uses
fork(), the child runs the handler and dies with SIGABRT (-6). If it uses posix_spawn,
no atfork handlers run and the child exits 0. The handler is registered in an isolated
subprocess so it can't poison the rest of the test session.
"""
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

# Match hunt._POSIX_SPAWN_OK exactly: the production fork-safe path activates only when
# BOTH os.posix_spawn and os.POSIX_SPAWN_DUP2 exist. If we skipped on posix_spawn alone,
# a platform with posix_spawn but no POSIX_SPAWN_DUP2 would exercise the fallback fork
# path and these tests would fail for the wrong reason.
requires_posix_spawn = pytest.mark.skipif(
    not (hasattr(os, "posix_spawn") and hasattr(os, "POSIX_SPAWN_DUP2")),
    reason="hunt._POSIX_SPAWN_OK is False on this interpreter (no posix_spawn fast path)",
)


def _run_with_hostile_atfork(call_src: str) -> subprocess.CompletedProcess:
    """Run `call_src` in a fresh interpreter that has a hostile abort() atfork child
    handler registered AFTER importing hunt. Returns the CompletedProcess.

    The snippet must set `ok` truthy on success. We assert on its stdout marker so a
    crash inside the launched child (SIGABRT/SIGSEGV) surfaces as a missing marker.
    """
    src = textwrap.dedent(
        f"""
        import os, sys, ctypes, tempfile
        sys.path.insert(0, {str(REPO)!r})
        import hunt  # import BEFORE registering the handler (import must stay clean)

        # Hostile, non-fork-safe child atfork handler: abort() in the forked child.
        # Models Apple Network.framework's nw_settings_child_has_forked (which SIGSEGVs).
        libc = ctypes.CDLL(None)
        assert libc.pthread_atfork(None, None, libc.abort) == 0

        {call_src}

        print("ATFORK_RESULT", "OK" if ok else "FAIL", flush=True)
        """
    )
    return subprocess.run(
        [sys.executable, "-c", src],
        capture_output=True,
        text=True,
        timeout=180,
    )


@requires_posix_spawn
def test_run_cmd_nonwatch_is_fork_safe():
    r = _run_with_hostile_atfork('ok, out = hunt.run_cmd("exit 0")')
    assert "ATFORK_RESULT OK" in r.stdout, (
        "run_cmd (non-watch) ran an atfork child handler -> it still uses fork()+exec. "
        f"rc={r.returncode} stdout={r.stdout!r} stderr={r.stderr[-500:]!r}"
    )


@requires_posix_spawn
def test_run_cmd_watch_branch_is_fork_safe():
    # This is the branch SQLMAP / CVE HUNT / REPORTS use (watch_file + watch_phase).
    r = _run_with_hostile_atfork(
        'd = tempfile.mkdtemp(); '
        'ok, out = hunt.run_cmd("exit 0", watch_file=d, watch_phase="TEST", '
        'watch_interval=1, watch_max_stale=1)'
    )
    assert "ATFORK_RESULT OK" in r.stdout, (
        "run_cmd (watch branch -> SQLMAP/CVE/REPORTS) ran an atfork child handler. "
        f"rc={r.returncode} stdout={r.stdout!r} stderr={r.stderr[-500:]!r}"
    )


@requires_posix_spawn
def test_run_live_is_fork_safe():
    r = _run_with_hostile_atfork('ok = hunt.run_live("exit 0", timeout=30)')
    assert "ATFORK_RESULT OK" in r.stdout, (
        "run_live ran an atfork child handler -> still forks. "
        f"rc={r.returncode} stdout={r.stdout!r} stderr={r.stderr[-500:]!r}"
    )


@requires_posix_spawn
def test_run_cmd_watch_honors_timeout_with_backgrounded_child():
    """The watch-branch capture loop must never block on a blocking read: if the shell
    exits but a backgrounded descendant keeps the inherited stdout open, run_cmd must
    still return near the deadline, not wait for the descendant to finish."""
    import re
    src = textwrap.dedent(
        f"""
        import os, sys, time, tempfile
        sys.path.insert(0, {str(REPO)!r})
        import hunt
        d = tempfile.mkdtemp()
        t0 = time.time()
        ok, out = hunt.run_cmd("sleep 8 & exit 0", watch_file=d, watch_phase="BG",
                               watch_interval=1, watch_max_stale=30, timeout=3)
        print("DT", round(time.time() - t0, 2), flush=True)
        """
    )
    r = subprocess.run([sys.executable, "-c", src], capture_output=True, text=True, timeout=60)
    m = re.search(r"DT ([0-9.]+)", r.stdout)
    assert m, f"no DT marker: stdout={r.stdout!r} stderr={r.stderr[-400:]!r}"
    dt = float(m.group(1))
    # Pre-fix (blocking read of the inherited pipe) this was ~8s; fixed it tracks timeout.
    assert dt < 6.0, f"run_cmd watch branch blocked {dt}s on a backgrounded child (timeout=3s)"


@requires_posix_spawn
def test_communicate_honors_timeout_when_child_redirects_stdout():
    """stdout EOF must NOT be treated as 'process exited': a child can redirect its own
    stdout and keep running. communicate(timeout) must still raise near the deadline."""
    import re
    src = textwrap.dedent(
        f"""
        import sys, os, time, signal, subprocess
        sys.path.insert(0, {str(REPO)!r})
        import hunt
        # Child closes stdout immediately (exec >/dev/null) but runs for 2s.
        p = hunt._fork_safe_spawn("exec >/dev/null 2>&1; sleep 2", capture=True, shell=True)
        t0 = time.time()
        try:
            p.communicate(timeout=0.3)
            print("RESULT returned", round(time.time() - t0, 2), flush=True)
        except subprocess.TimeoutExpired:
            print("RESULT timeout", round(time.time() - t0, 2), flush=True)
        finally:
            try: os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except Exception: pass
        """
    )
    r = subprocess.run([sys.executable, "-c", src], capture_output=True, text=True, timeout=60)
    m = re.search(r"RESULT (\w+) ([0-9.]+)", r.stdout)
    assert m, f"no RESULT marker: stdout={r.stdout!r} stderr={r.stderr[-400:]!r}"
    kind, dt = m.group(1), float(m.group(2))
    assert kind == "timeout", f"communicate did not honor timeout (returned after {dt}s; the 5s grace masked it)"
    assert dt < 1.5, f"communicate raised but {dt}s late"


@requires_posix_spawn
def test_run_cmd_watch_no_busyspin_when_child_closes_stdout():
    """If the child closes stdout/stderr but keeps running, the capture loop must not
    busy-spin on the EOF-ready fd. Detect via CPU time: a spin burns ~1 CPU-second for a
    ~1s wall wait; the fixed loop sleeps and uses near-zero CPU."""
    import re
    src = textwrap.dedent(
        f"""
        import sys, os, time, tempfile
        sys.path.insert(0, {str(REPO)!r})
        import hunt
        d = tempfile.mkdtemp()
        c0, t0 = time.process_time(), time.time()
        ok, out = hunt.run_cmd("exec >/dev/null 2>&1; sleep 1", watch_file=d,
                               watch_phase="SPIN", watch_interval=5, watch_max_stale=30, timeout=10)
        print("CPU", round(time.process_time() - c0, 3), "WALL", round(time.time() - t0, 2), flush=True)
        """
    )
    r = subprocess.run([sys.executable, "-c", src], capture_output=True, text=True, timeout=60)
    m = re.search(r"CPU ([0-9.]+) WALL ([0-9.]+)", r.stdout)
    assert m, f"no CPU/WALL marker: stdout={r.stdout!r} stderr={r.stderr[-400:]!r}"
    cpu, wall = float(m.group(1)), float(m.group(2))
    assert wall < 4.0, f"watch loop did not return near child exit (wall={wall}s)"
    assert cpu < 0.5, f"watch loop busy-spun: burned {cpu} CPU-seconds over {wall}s wall (EOF-ready fd not dropped)"


@requires_posix_spawn
def test_fork_safe_launch_is_setsid_group_leader():
    """The watchdog kills via os.killpg(os.getpgid(pid)); the launched child must be
    its own session/group leader for that to reach the whole tree."""
    src = textwrap.dedent(
        f"""
        import os, sys, time
        sys.path.insert(0, {str(REPO)!r})
        import hunt
        proc = hunt._fork_safe_spawn("sleep 5", env=dict(os.environ), capture=False)
        time.sleep(0.3)
        leader = (os.getpgid(proc.pid) == proc.pid)
        proc.kill()
        print("LEADER", leader, flush=True)
        """
    )
    r = subprocess.run([sys.executable, "-c", src], capture_output=True, text=True, timeout=60)
    assert "LEADER True" in r.stdout, (
        f"launched child is not a setsid group leader -> killpg would miss it. "
        f"stdout={r.stdout!r} stderr={r.stderr[-500:]!r}"
    )
