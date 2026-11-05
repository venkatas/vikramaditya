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
import re
import shlex
import signal
import subprocess
import threading
import time

_POSIX_SPAWN_OK = hasattr(os, "posix_spawn") and hasattr(os, "POSIX_SPAWN_DUP2")

# sqlmap reads its targets from STDIN (ignoring -r/-m/-l) whenever stdin is not a
# tty — its _setStdinPipeTargets() only early-returns on conf.url. So any sqlmap
# invocation that takes a request/bulk/log file MUST be launched with pty_stdin=True
# or it silently tests nothing under non-interactive stdin (nohup/cron/subprocess).
_SQLMAP_FILE_FLAG = re.compile(r"(?:^|\s)sqlmap(?:\.py)?\b.*?(?:\s-r\b|\s-m\b|\s-l\b|\s--bulk\b)")


def sqlmap_needs_pty(cmd) -> bool:
    """True when ``cmd`` is a sqlmap request/bulk/log-file run that needs a tty stdin."""
    if not isinstance(cmd, str):
        cmd = " ".join(str(a) for a in cmd)
    return bool(_SQLMAP_FILE_FLAG.search(cmd))


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

    def __init__(self, spec, env=None, cwd=None, capture=True, shell=True, merge_stderr=True,
                 pty_stdin=False):
        self._lock = threading.Lock()
        # Dedicated lock for the pty master fd: poll() calls _close_pty() while
        # holding self._lock, so _close_pty() must NOT reuse self._lock (the Lock
        # is non-reentrant). kill()/__del__ call it lock-free; a separate lock makes
        # the close atomic and prevents a double-close of a possibly-reused fd.
        self._pty_lock = threading.Lock()
        self.returncode = None
        self.stdout = None
        self.stderr = None
        # PTY master fd kept open in the PARENT for the child's lifetime when
        # pty_stdin=True, so the child's fd-0 pty slave stays a live tty
        # (os.isatty(0) -> True). Closed on reap. See `pty_stdin` below.
        self._pty_master = None

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

        # ── stdin ────────────────────────────────────────────────────────────
        # Default: fd 0 -> /dev/null (non-tty). pty_stdin=True instead gives the
        # child a PSEUDO-TERMINAL on fd 0 so os.isatty(0) is True. Needed because
        # sqlmap's `-r`/`-m`/`-l` modes fall into "using 'STDIN' for parsing
        # targets list" (and test NOTHING) whenever stdin is not a tty — its
        # _setStdinPipeTargets() only early-returns on conf.url, never conf.requestFile.
        # os.openpty() does NOT fork(), so this stays clear of the macOS
        # Network.framework atfork SIGSEGV that motivated posix_spawn here.
        # CAVEAT: the parent holds the pty master open for the child's lifetime, so
        # a child that BLOCKS reading stdin never gets EOF. Only use pty_stdin with
        # commands that don't read stdin (e.g. sqlmap --batch) OR under a finite
        # timeout (communicate()/wait() are deadline-bounded and kill on timeout).
        pty_master = pty_slave = None
        if pty_stdin:
            pty_master, pty_slave = os.openpty()
            file_actions = [
                (os.POSIX_SPAWN_DUP2, pty_slave, 0),  # child stdin = pty slave (a tty)
                (os.POSIX_SPAWN_CLOSE, pty_slave),     # child keeps only the fd-0 dup
                (os.POSIX_SPAWN_CLOSE, pty_master),    # child never needs the master
            ]
        else:
            file_actions = [(os.POSIX_SPAWN_OPEN, 0, os.devnull, os.O_RDONLY, 0)]
        r_out = w_out = r_err = w_err = None
        if capture:
            r_out, w_out = os.pipe()
            file_actions.append((os.POSIX_SPAWN_DUP2, w_out, 1))
            if merge_stderr:
                file_actions.append((os.POSIX_SPAWN_DUP2, w_out, 2))  # both streams -> one pipe
            else:
                r_err, w_err = os.pipe()
                file_actions.append((os.POSIX_SPAWN_DUP2, w_err, 2))  # stderr kept separate
            for _fd in (r_out, w_out, r_err, w_err):
                if _fd is not None:
                    file_actions.append((os.POSIX_SPAWN_CLOSE, _fd))

        spawn = os.posix_spawnp if use_path else os.posix_spawn
        try:
            self.pid = spawn(program, argv, env if env is not None else os.environ,
                             file_actions=file_actions, setsid=True)
            # setsid makes this PID the group ID. Retain ownership before any
            # poll/wait can reap the leader: descendants may outlive it.
            self._vik_pgid = self.pid
            self._vik_group_gone = False
        except Exception:
            for _fd in (r_out, w_out, r_err, w_err, pty_master, pty_slave):
                if _fd is not None:
                    try:
                        os.close(_fd)
                    except Exception:
                        pass
            raise
        if pty_slave is not None:
            os.close(pty_slave)              # parent never uses the slave
            self._pty_master = pty_master    # hold master open until the child is reaped
        if capture:
            os.close(w_out)
            self.stdout = os.fdopen(r_out, "r", errors="replace")
            if not merge_stderr:
                os.close(w_err)
                self.stderr = os.fdopen(r_err, "r", errors="replace")

    def _close_pty(self):
        """Close the held PTY master fd once (idempotent, thread-safe). Called when
        the child is reaped so a long-lived parent (the brain runs many commands per
        session) never accumulates open pty masters. The _pty_lock atomic swap
        guarantees exactly one os.close() even if poll() and kill()/__del__ race."""
        with self._pty_lock:
            m = self._pty_master
            self._pty_master = None
        if m is not None:
            try:
                os.close(m)
            except Exception:
                pass

    def _close_streams(self):
        """Close the captured stdout/stderr READ-pipe fds once the child is reaped, so a
        long-lived parent (the brain runs many commands per session) never accumulates
        open read-pipe fds. Idempotent and tolerant: a reader thread that raises on the
        concurrent close already falls back to "" in communicate(). Mirrors _close_pty()."""
        for _attr in ("stdout", "stderr"):
            s = getattr(self, _attr, None)
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
                setattr(self, _attr, None)

    def poll(self, *, close_streams=True):
        """Reap without blocking on pipe-reader locks when teardown defers closing.

        A descendant may retain a captured pipe after the immediate child exits.
        Group teardown must be able to observe that exit and kill the descendant
        before closing the pipe that another thread is still reading.
        """
        with self._lock:
            if self.returncode is None:
                try:
                    pid, status = os.waitpid(self.pid, os.WNOHANG)
                except ChildProcessError:
                    self.returncode = 0  # already reaped elsewhere; status unknowable
                else:
                    if pid == 0:
                        return None
                    self.returncode = -os.WTERMSIG(status) if os.WIFSIGNALED(status) \
                        else os.WEXITSTATUS(status)
            rc = self.returncode
        # Closing a TextIO pipe can wait for a reader's lock. Never hold the
        # process-status lock during that wait: teardown must still be able to
        # poll without closing and escalate the child's process group.
        self._close_pty()
        if close_streams:
            self._close_streams()
        return rc

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
        # Single absolute deadline shared by the reads and the reap, so total runtime
        # cannot exceed `timeout` (a separate timeout on each step would allow ~2x).
        # stdout and stderr (when separate) are drained CONCURRENTLY — reading one while
        # the child fills the other pipe to capacity would deadlock.
        deadline = None if timeout is None else time.time() + timeout
        bufs = {}
        threads = []
        for _name, _stream in (("out", self.stdout), ("err", self.stderr)):
            if _stream is not None:
                def _read(n=_name, s=_stream):
                    try:
                        bufs[n] = s.read()
                    except Exception:
                        bufs[n] = ""
                t = threading.Thread(target=_read, daemon=True)
                t.start()
                threads.append(t)
        for t in threads:
            t.join(None if deadline is None else max(0.0, deadline - time.time()))
            if t.is_alive():
                # Self-clean on timeout so this Popen-like surface is safe for ANY
                # caller (a caller catching TimeoutExpired the way one does with real
                # subprocess.Popen.communicate() would otherwise leak the still-running
                # child + the daemon reader threads' read-pipe fds + the pty master).
                # Kill the whole session group, then close the pty/read fds — closing the
                # read fds unblocks the daemon reader threads still parked in s.read().
                _terminate_group(self, grace=0)
                self._close_pty()
                self._close_streams()
                raise subprocess.TimeoutExpired("posix_spawn", timeout)
        out = bufs.get("out", "") or ""
        err = bufs.get("err", "") or ""
        # stdout EOF does NOT imply the process exited — it may have closed/redirected its
        # own stdout and kept running. poll() first so a genuinely-finished process is
        # never a spurious timeout; otherwise reap within the REMAINING deadline only, so
        # communicate() never outlives the caller's timeout.
        if self.poll() is None:
            self.wait(None if deadline is None else max(0.0, deadline - time.time()))
        return out, err

    def kill(self):
        try:
            os.kill(self.pid, signal.SIGKILL)
        except Exception:
            pass
        self._close_pty()
        self._close_streams()

    def terminate(self):
        # SIGTERM (graceful) — subprocess.Popen-API parity so a caller that started a
        # long-running background child via _fork_safe_spawn (e.g. interactsh-client) can
        # .terminate() it. Reaping happens via the caller's later poll()/wait().
        try:
            os.kill(self.pid, signal.SIGTERM)
        except Exception:
            pass

    def __del__(self):
        # Backstop: reap if a caller path never waited, so we don't leak a zombie.
        # A still-running child (e.g. a terminate()-only background child whose SIGTERM
        # hasn't landed yet) is force-killed then reaped — otherwise the single WNOHANG
        # would return (0, 0) and the child would linger as a zombie until the long-lived
        # parent exits. The blocking waitpid after SIGKILL returns essentially immediately,
        # so __del__ still never hangs.
        try:
            if getattr(self, "returncode", 0) is None:
                pid, _ = os.waitpid(self.pid, os.WNOHANG)
                if pid == 0:  # still running
                    try:
                        os.kill(self.pid, signal.SIGKILL)
                    except Exception:
                        pass
                    try:
                        os.waitpid(self.pid, 0)  # SIGKILLed child reaps promptly
                    except Exception:
                        pass
        except Exception:
            pass
        try:
            self._close_pty()
        except Exception:
            pass
        try:
            self._close_streams()
        except Exception:
            pass


def _fork_safe_spawn(spec, env=None, cwd=None, capture=True, shell=True, merge_stderr=True,
                     pty_stdin=False):
    """Launch a subprocess WITHOUT fork() when possible (macOS Network.framework
    atfork handlers SIGSEGV the forked child — see ``_PosixSpawnProc``).

    Uses ``os.posix_spawn`` (no atfork handlers) on interpreters that support it;
    otherwise falls back to the original fork-based ``subprocess.Popen`` so Linux/CI
    and old interpreters are unchanged. ``merge_stderr`` (default True) folds stderr into
    stdout; pass False to capture them separately. ``pty_stdin=True`` gives the child a
    pseudo-terminal on fd 0 (os.isatty(0) -> True) so tools like sqlmap ``-r`` don't
    fall into stdin-targets mode under non-tty stdin. Returns a Popen-or-Popen-like object."""
    if _POSIX_SPAWN_OK:
        return _PosixSpawnProc(spec, env=env, cwd=cwd, capture=capture, shell=shell,
                               merge_stderr=merge_stderr, pty_stdin=pty_stdin)
    # Fallback (no posix_spawn): original fork-based behaviour. pty_stdin is a
    # deliberate NO-OP here — this branch only runs on interpreters WITHOUT
    # os.posix_spawn (pre-3.8), unreachable on any supported runtime (CPython >=3.8
    # always has it). Allocating a pty would leak the master fd (a raw Popen has no
    # reap hook to close it), so we keep the historical /dev/null stdin; sqlmap -r on
    # such an ancient interpreter would just retain the old non-tty behaviour.
    _err = subprocess.STDOUT if merge_stderr else subprocess.PIPE
    proc = subprocess.Popen(
        spec, shell=bool(shell),
        stdout=subprocess.PIPE if capture else None,
        stderr=(_err if capture else None),
        stdin=subprocess.DEVNULL, cwd=cwd, env=env, text=True,
        start_new_session=True,
    )
    proc._vik_pgid = proc.pid
    proc._vik_group_gone = False
    return proc


def _poll_without_stream_close(proc):
    if isinstance(proc, _PosixSpawnProc):
        return proc.poll(close_streams=False)
    return proc.poll()  # subprocess.Popen.poll does not close captured pipes


def _owned_group_alive(proc) -> bool:
    """Check a spawn-owned group without closing inherited captured pipes.

    A group ID remains allocated while descendants belong to it, even after its
    leader is reaped. Once absence (or a new process occupying the reaped leader
    PID) is observed, retire that ownership so repeated cleanup cannot target a
    later group that reused the numeric ID.
    """
    pgid = getattr(proc, "_vik_pgid", None)
    if not isinstance(pgid, int) or pgid <= 0 or getattr(proc, "_vik_group_gone", False):
        return False
    try:
        exited = _poll_without_stream_close(proc) is not None
        if exited:
            try:
                os.getpgid(proc.pid)
            except ProcessLookupError:
                pass  # Leader is gone; its still-live descendants retain the group.
            else:
                proc._vik_group_gone = True  # Reaped PID now belongs to somebody else.
                return False
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        proc._vik_group_gone = True
        return False
    except PermissionError:
        return True  # Existence is known even when signalling is not permitted.
    except Exception:
        return False


def _terminate_group(proc, grace: float = 5, phase=None) -> None:
    """Graceful SIGTERM → wait(grace) → SIGKILL → reap → verify for a setsid child.

    The child is launched with ``start_new_session=True`` (its own process group), so
    killing the group tears down the WHOLE descendant tree (nmap/curl/sqlmap/…), not
    just the immediate child. Spawn-owned group identity survives leader exit;
    empty/retired groups are not signalled. NEVER raises — teardown must not mask
    the interrupt/exception that triggered it.
    """
    if proc is None:
        return
    pgid = getattr(proc, "_vik_pgid", None)
    if pgid is None:
        # Compatibility for an external Popen: only adopt a live session leader,
        # never reconstruct ownership from an already-reaped, reusable PID.
        try:
            if _poll_without_stream_close(proc) is not None:
                return
            candidate = os.getpgid(proc.pid)
            if candidate == proc.pid:
                pgid = proc._vik_pgid = candidate
                proc._vik_group_gone = False
        except Exception:
            pass

    def _signal_group(sig):
        try:
            if pgid is not None and _owned_group_alive(proc):
                os.killpg(pgid, sig)
                return
        except (ProcessLookupError, OSError):
            pass
        try:
            if _poll_without_stream_close(proc) is None:
                proc.send_signal(sig)   # fallback: signal just the live child
        except Exception:
            pass

    def _group_alive():
        if pgid is not None:
            return _owned_group_alive(proc)
        try:
            return _poll_without_stream_close(proc) is None
        except Exception:
            return False

    if not _group_alive():
        if pgid is not None:
            # No owned writers remain. Reap/close the original capture handles
            # even though there was no group left to signal.
            try:
                proc.wait(timeout=0)
            except Exception:
                pass
        return

    deadline = time.monotonic() + max(0, grace)
    _signal_group(signal.SIGTERM)
    # Reap without closing streams during grace. wait()/ordinary poll() can
    # deadlock here on a reader lock held until a resistant descendant closes
    # its inherited pipe, preventing the SIGKILL that would release that reader.
    while _group_alive() and time.monotonic() < deadline:
        try:
            _poll_without_stream_close(proc)
        except Exception:
            pass
        time.sleep(min(0.02, max(0, deadline - time.monotonic())))
    if _group_alive():
        _signal_group(signal.SIGKILL)
    try:
        proc.wait(timeout=10)   # reap — posix_spawn has no Popen GC to do it
    except Exception:
        pass


def run_capture(spec, timeout=None, env=None, cwd=None, shell=True, merge_stderr=True,
                pty_stdin=False) -> dict:
    """Fork-safe drop-in replacement for ``subprocess.run(..., capture_output=True)``.

    Returns ``{"stdout", "stderr", "returncode", "timed_out"}``. By default stderr is
    merged into ``stdout`` (one combined stream) and ``stderr`` is "". Pass
    ``merge_stderr=False`` to capture them SEPARATELY — required by callers (e.g.
    brain_scanner) that distinguish a script's own crash (stderr) from a target's
    response (stdout). On timeout the child AND its session group are killed, the child
    is reaped (no zombie), and ``timed_out`` is True with returncode -9.
    """
    proc = _fork_safe_spawn(spec, env=env, cwd=cwd, capture=True, shell=shell,
                            merge_stderr=merge_stderr, pty_stdin=pty_stdin)
    try:
        out, err = proc.communicate(timeout=timeout)
    except KeyboardInterrupt:
        # Ctrl-C during a captured child (e.g. brain_scanner) must tear down the
        # whole group and re-raise — never leave an orphaned scanner tree running.
        _terminate_group(proc)
        raise
    except subprocess.TimeoutExpired:
        _terminate_group(proc, grace=0)
        # Reap so a timed-out child never lingers as a zombie (bounded; never hangs).
        try:
            proc.wait(timeout=10)
        except Exception:
            pass
        # Close the captured read-pipe fds after the reap so a timed-out command does
        # not leak stdout/stderr fds (communicate() raised before its poll() ran, and on
        # the fork-based fallback Popen the streams are otherwise never closed here).
        try:
            _cs = getattr(proc, "_close_streams", None)
            if _cs is not None:
                _cs()
            else:  # fork-based subprocess.Popen fallback
                for _s in (getattr(proc, "stdout", None), getattr(proc, "stderr", None)):
                    if _s is not None:
                        try:
                            _s.close()
                        except Exception:
                            pass
        except Exception:
            pass
        return {"stdout": "", "stderr": f"TIMEOUT after {timeout}s",
                "returncode": -9, "timed_out": True}
    rc = proc.returncode
    if rc is None:
        rc = proc.poll()
    return {"stdout": out or "", "stderr": err or "",
            "returncode": rc if rc is not None else 0, "timed_out": False}
