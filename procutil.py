#!/usr/bin/env python3
"""procutil.py — fork-safe subprocess launching shared across the toolkit.

This is the CANONICAL home of the macOS fork()-SIGSEGV fix (originally v10.3.3 in
hunt.py). hunt.py imports the names from here; brain_scanner uses ``run_capture`` so the
brain's exploit-verification commands launch the same fork-safe way.

WHY THIS MATTERS — on macOS the parent loads Apple's Network.framework (in-process
HTTP/TLS; with a VPN/endpoint-filter NetworkExtension it also pulls in NEFlowDirector),
which registers a NON-fork-safe ``pthread_atfork`` child handler that SIGSEGVs any
``fork()+exec`` child *before* exec (``rc=-11`` at 0.0s). ``os.posix_spawn`` does not run
``pthread_atfork`` handlers, so launching via posix_spawn eliminates the whole class of
"Apple framework not fork-safe" crashes while ``setsid=True`` keeps the child a
session/group leader for ``killpg`` teardown.
"""
from __future__ import annotations

import os
import shlex
import signal
import subprocess
import threading
import time

_POSIX_SPAWN_OK = hasattr(os, "posix_spawn") and hasattr(os, "POSIX_SPAWN_DUP2")


class _PosixSpawnProc:
    """A small ``subprocess.Popen`` work-alike that launches via ``os.posix_spawn``
    instead of ``fork()+exec``.

    WHY THIS EXISTS — macOS fork() is not safe here (see module docstring): Apple's
    Network.framework registers a NON-fork-safe ``pthread_atfork`` *child* handler
    (``nw_settings_child_has_forked`` -> ``os_log`` -> ``_os_log_preferences_refresh``).
    Any ``subprocess.Popen`` that takes the fork()+exec path runs that handler in the
    forked child *before* exec and SIGSEGVs at 0.0s — observed killing the SQLMAP,
    CVE HUNT and REPORTS phases (``rc=-11 duration=0.0s``; 0 reports produced) and, in
    brain_scanner, every exploit-verification curl/wget (so real findings were wrongly
    ruled false positives).

    Both ``preexec_fn`` (set to ``os.setsid``) AND ``start_new_session=True`` force the
    fork() path, so neither "fixes" it. ``posix_spawn`` does not run ``pthread_atfork``
    handlers, and ``setsid=True`` keeps the child a session/group leader so the
    watchdog's ``os.killpg(os.getpgid(pid))`` still tears down the whole tree.

    Implements only the Popen surface callers use: ``.pid``, ``.stdout``, ``.poll()``,
    ``.returncode``, ``.wait()``, ``.communicate()``, ``.kill()``.
    """

    def __init__(self, spec, env=None, cwd=None, capture=True, shell=True):
        self._lock = threading.Lock()
        self.returncode = None
        self.stdout = None

        # Normalise (argv, cwd) into a fork-safe posix_spawn invocation. We have no
        # POSIX_SPAWN_CHDIR on every build, so cwd is applied via a `cd ... &&` shell
        # wrapper (which also covers argv-mode commands that need a cwd).
        if shell:
            cmd = spec
            if cwd:
                cmd = f"cd {shlex.quote(cwd)} && ({cmd})"
            program, argv, use_path = "/bin/sh", ["/bin/sh", "-c", cmd], False
        else:
            argv = list(spec)
            if cwd:
                inner = " ".join(shlex.quote(a) for a in argv)
                program, argv, use_path = "/bin/sh", [
                    "/bin/sh", "-c", f"cd {shlex.quote(cwd)} && exec {inner}"], False
            else:
                program, use_path = argv[0], True

        file_actions = [(os.POSIX_SPAWN_OPEN, 0, os.devnull, os.O_RDONLY, 0)]
        r = w = None
        if capture:
            r, w = os.pipe()
            file_actions += [
                (os.POSIX_SPAWN_DUP2, w, 1),
                (os.POSIX_SPAWN_DUP2, w, 2),
                (os.POSIX_SPAWN_CLOSE, r),
                (os.POSIX_SPAWN_CLOSE, w),
            ]

        spawn = os.posix_spawnp if use_path else os.posix_spawn
        try:
            self.pid = spawn(program, argv, env if env is not None else os.environ,
                             file_actions=file_actions, setsid=True)
        except Exception:
            if capture:
                os.close(r); os.close(w)
            raise
        if capture:
            os.close(w)
            self.stdout = os.fdopen(r, "r", errors="replace")

    def poll(self):
        with self._lock:
            if self.returncode is not None:
                return self.returncode
            try:
                pid, status = os.waitpid(self.pid, os.WNOHANG)
            except ChildProcessError:
                self.returncode = 0  # already reaped elsewhere; status unknowable
                return self.returncode
            if pid == 0:
                return None
            self.returncode = -os.WTERMSIG(status) if os.WIFSIGNALED(status) \
                else os.WEXITSTATUS(status)
            return self.returncode

    def wait(self, timeout=None):
        deadline = None if timeout is None else time.time() + timeout
        while True:
            rc = self.poll()
            if rc is not None:
                return rc
            if deadline is not None and time.time() > deadline:
                raise subprocess.TimeoutExpired("posix_spawn", timeout)
            time.sleep(0.02)

    def communicate(self, timeout=None):
        # Single absolute deadline shared by the read and the reap, so total runtime
        # cannot exceed `timeout` (a separate timeout on each step would allow ~2x).
        deadline = None if timeout is None else time.time() + timeout
        out = ""
        if self.stdout is not None:
            buf = []
            reader = threading.Thread(target=lambda: buf.append(self.stdout.read()),
                                      daemon=True)
            reader.start()
            reader.join(None if deadline is None else max(0.0, deadline - time.time()))
            if reader.is_alive():
                raise subprocess.TimeoutExpired("posix_spawn", timeout)
            out = buf[0] if buf else ""
        # stdout EOF does NOT imply the process exited — it may have closed/redirected its
        # own stdout and kept running. poll() first so a genuinely-finished process is
        # never a spurious timeout; otherwise reap within the REMAINING deadline only, so
        # communicate() never outlives the caller's timeout.
        if self.poll() is None:
            self.wait(None if deadline is None else max(0.0, deadline - time.time()))
        return out, ""

    def kill(self):
        try:
            os.kill(self.pid, signal.SIGKILL)
        except Exception:
            pass

    def __del__(self):
        # Backstop: reap if a caller path never waited, so we don't leak a zombie.
        # Non-blocking (WNOHANG) — __del__ must never hang.
        try:
            if getattr(self, "returncode", 0) is None:
                os.waitpid(self.pid, os.WNOHANG)
        except Exception:
            pass


def _fork_safe_spawn(spec, env=None, cwd=None, capture=True, shell=True):
    """Launch a subprocess WITHOUT fork() when possible (macOS Network.framework
    atfork handlers SIGSEGV the forked child — see ``_PosixSpawnProc``).

    Uses ``os.posix_spawn`` (no atfork handlers) on interpreters that support it;
    otherwise falls back to the original fork-based ``subprocess.Popen`` so Linux/CI
    and old interpreters are unchanged. Returns a Popen-or-Popen-like object."""
    if _POSIX_SPAWN_OK:
        return _PosixSpawnProc(spec, env=env, cwd=cwd, capture=capture, shell=shell)
    # Fallback (no posix_spawn): original behaviour.
    if shell:
        return subprocess.Popen(
            spec, shell=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.STDOUT if capture else None,
            stdin=subprocess.DEVNULL, cwd=cwd, env=env, text=True,
            start_new_session=True,
        )
    return subprocess.Popen(
        spec,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
        stdin=subprocess.DEVNULL, cwd=cwd, env=env, text=True,
        start_new_session=True,
    )


def run_capture(spec, timeout=None, env=None, cwd=None, shell=True) -> dict:
    """Fork-safe drop-in replacement for ``subprocess.run(..., capture_output=True)``.

    Returns ``{"stdout", "stderr", "returncode", "timed_out"}``. stdout and stderr are
    merged into ``stdout`` (the fork-safe spawner captures one combined stream); stderr
    is kept as "" so callers that read both keys still work. On timeout the child (and
    its session group) is killed and ``timed_out`` is True with returncode -9.
    """
    proc = _fork_safe_spawn(spec, env=env, cwd=cwd, capture=True, shell=shell)
    try:
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        return {"stdout": "", "stderr": f"TIMEOUT after {timeout}s",
                "returncode": -9, "timed_out": True}
    rc = proc.returncode
    if rc is None:
        rc = proc.poll()
    return {"stdout": out or "", "stderr": "",
            "returncode": rc if rc is not None else 0, "timed_out": False}
