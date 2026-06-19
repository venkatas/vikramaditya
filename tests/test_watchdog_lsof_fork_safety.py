"""Regression guard: ProcessWatchdog's TCP-socket sampler must use the fork-safe
posix_spawn helper (procutil.run_capture), NOT subprocess fork()+exec.

ROOT CAUSE THIS GUARDS AGAINST
------------------------------
ProcessWatchdog._socket_status() samples `lsof` every `interval`s while hunt.py's
parent process holds live Apple Network.framework state (in-process HTTP/TLS, Ollama
brain calls, NetworkExtension on filtered hosts). A `subprocess.check_output(["lsof", ...])`
there takes the fork()+exec path, which runs Network.framework's NON-fork-safe
pthread_atfork *child* handler (`nw_settings_child_has_forked` -> os_log) in the forked
child and SIGSEGVs it at 0.0s — observed in the field as a Python crash report (and a
macOS crash popup) every ~60s for the whole scan. os.posix_spawn runs no atfork handlers,
so run_capture eliminates the crash while still sampling lsof. See hunt.py:_socket_status.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import hunt  # noqa: E402

_FAKE_LSOF = (
    "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
    "python   1234  u      7u  IPv4    0t0      TCP 10.0.0.1:54321->1.2.3.4:443 (ESTABLISHED)\n"
)


def _watchdog():
    # Bypass __init__ (no real proc / no daemon thread); _socket_status only needs these.
    wd = object.__new__(hunt.ProcessWatchdog)
    wd._last_socket_signature = ""
    wd._last_socket_summary = ""
    return wd


def test_socket_status_routes_through_fork_safe_run_capture(monkeypatch):
    seen = {}

    def fake_run_capture(spec, **kw):
        seen["spec"] = list(spec)
        seen["kw"] = kw
        return {"stdout": _FAKE_LSOF, "stderr": "", "returncode": 0, "timed_out": False}

    monkeypatch.setattr(hunt, "run_capture", fake_run_capture)

    # the fork()+exec path must NOT be used
    def _boom(*a, **k):
        raise AssertionError("watchdog used subprocess.check_output (fork path) — must use run_capture")
    monkeypatch.setattr(hunt.subprocess, "check_output", _boom)

    active, _changed, summary = _watchdog()._socket_status({1234})

    assert seen["spec"][0] == "lsof"                  # still samples lsof
    assert seen["kw"].get("shell") is False           # argv mode (no /bin/sh fork wrapper)
    assert seen["kw"].get("merge_stderr") is False    # lsof stderr warnings kept out of the parse
    assert active is True                             # ESTABLISHED -> active socket
    assert "ESTABLISHED" in summary


def test_socket_status_handles_timeout_gracefully(monkeypatch):
    monkeypatch.setattr(
        hunt, "run_capture",
        lambda *a, **k: {"stdout": "", "stderr": "", "returncode": -9, "timed_out": True})
    active, changed, _summary = _watchdog()._socket_status({1234})
    assert active is False and changed is False        # degrades, never raises


def test_socket_status_empty_pids_is_noop():
    assert _watchdog()._socket_status(set()) == (False, False, "(no tracked pids)")


def test_descendant_status_routes_through_fork_safe_run_capture(monkeypatch):
    # The process-tree sampler (ps) is the OTHER per-tick fork() site; it must also use
    # run_capture. This exercises ps AND the nested lsof call via _socket_status.
    import types
    seen = []

    def fake_run_capture(spec, **kw):
        seen.append((spec[0], kw))
        out = ("1234 1 9.0 R 01:00 00:30.00 nuclei -l targets.txt\n"
               if spec[0] == "ps" else _FAKE_LSOF)
        return {"stdout": out, "stderr": "", "returncode": 0, "timed_out": False}

    monkeypatch.setattr(hunt, "run_capture", fake_run_capture)

    def _boom(*a, **k):
        raise AssertionError("watchdog used subprocess.check_output (fork path) — must use run_capture")
    monkeypatch.setattr(hunt.subprocess, "check_output", _boom)

    wd = _watchdog()
    wd.proc = types.SimpleNamespace(pid=1234)
    wd._last_proc_signature = ""
    wd._last_cpu_times = {}

    busy, _pc, _summ, _cpu, sock_active, _sc, _ss = wd._descendant_status()

    cmds = [c for c, _ in seen]
    assert "ps" in cmds                                   # process-tree sample via run_capture
    assert "lsof" in cmds                                 # nested socket sample too
    assert all(kw.get("shell") is False for _, kw in seen)
    assert busy is True                                  # state=R -> busy
    assert sock_active is True                            # ESTABLISHED via nested _socket_status
