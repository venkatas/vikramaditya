#!/usr/bin/env python3
"""interactsh_client.py — shared out-of-band (OOB) spawn + poll helper.

Extracted so every module that needs blind-confirmation (XXE, SSRF, blind SQLi)
shares ONE interactsh-client lifecycle instead of each hunting module reimplementing
its own spawn/log-poll loop. hunt.py's existing inline Log4Shell OOB step
(run_rce_scan, ~line 5850) is a second caller of the same underlying binary; this
module does not change that call site — it is a new, independent path for new
modules to use.

Launches the listener via ``procutil._fork_safe_spawn`` (posix_spawn) instead of a
bare ``subprocess.Popen``: on macOS, a plain fork()+exec here runs under Apple's
Network.framework ``pthread_atfork`` child handler and SIGSEGVs the child before
exec (see procutil.py's module docstring for the full story) — the exact crash
class hunt.py's own Log4Shell OOB step already works around. ``procutil.run_capture``
is NOT used here because it is a bounded one-shot helper (it waits for the child to
exit and returns its output); interactsh-client is a long-lived background listener
that the caller polls repeatedly and stops explicitly via ``.stop()``.
"""
from __future__ import annotations

import json
import os
import re
import select
import shutil
import time
from dataclasses import dataclass

from procutil import _fork_safe_spawn

# Matches the domain interactsh-client announces on startup, e.g.
# "abc123def456.oast.pro" (public oast.* default servers) or the legacy
# "abc123def456.interact.sh" family.
_DOMAIN_RE = re.compile(rb'([a-z0-9]+\.oast\.[a-z]+|[a-z0-9]+\.interact\.sh)')


def find_interactsh_binary() -> str | None:
    """Locate interactsh-client on PATH or common Go install locations."""
    found = shutil.which("interactsh-client")
    if found:
        return found
    gobin = os.path.expanduser(os.environ.get("GOBIN", "~/go/bin"))
    candidate = os.path.join(gobin, "interactsh-client")
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate
    return None


@dataclass
class InteractshSession:
    url: str
    log_path: str
    token: str
    proc: object | None  # a subprocess.Popen or procutil._PosixSpawnProc, or None

    def poll_callbacks(self, token: str) -> list[dict]:
        """Return every JSONL callback record whose full-id starts with token."""
        if not os.path.isfile(self.log_path):
            return []
        hits = []
        with open(self.log_path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if str(rec.get("full-id", "")).startswith(token):
                    hits.append(rec)
        return hits

    def stop(self) -> None:
        """Terminate the background interactsh-client listener (SIGTERM first,
        escalating to SIGKILL if the process doesn't exit within 5s). Safe to call
        when the process already exited or was never started."""
        if self.proc is None:
            return
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            # wait() timed out (TimeoutExpired) or the process was already gone /
            # ignored SIGTERM — escalate to SIGKILL. Best-effort teardown on a
            # caller's cleanup path: an exception here must never mask whatever
            # the caller was doing, so failures to even SIGKILL are swallowed too
            # (mirrors the same swallow-on-cleanup pattern used elsewhere in this
            # codebase, e.g. procutil._PosixSpawnProc.kill()/__del__).
            try:
                self.proc.kill()
            except Exception:
                pass


def spawn(log_dir: str, timeout_s: int = 10) -> InteractshSession | None:
    """Start interactsh-client in the background, writing JSONL callbacks to
    ``<log_dir>/interactsh_log.jsonl``. Returns None if the binary is unavailable
    (caller must treat blind-OOB confirmation as unavailable, not fabricate one).

    NOTE on ``timeout_s``: this bounds how long ``spawn()`` waits for
    interactsh-client's STARTUP BANNER (which announces the real assigned
    correlation domain) — it is NOT how long the listener process runs. The
    listener itself is long-lived: it keeps appending JSONL callback records to
    the log file until the caller explicitly calls ``session.stop()``. The caller
    polls ``session.poll_callbacks()`` at its own cadence, independent of this
    startup deadline.

    If the banner does not appear within ``timeout_s``, the process is still
    returned running (log lines may still accumulate) but ``session.url`` and
    ``session.token`` are both ``""`` — there is no real correlation ID to build
    a URL from or to filter callbacks by, so callers must check for this and NOT
    treat an empty token as "match everything".
    """
    binary = find_interactsh_binary()
    if binary is None:
        return None

    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "interactsh_log.jsonl")

    # interactsh-client writes structured JSONL callback records directly to
    # `-o log_path` (kept separate from stdout/stderr), and announces the domain
    # it registered with the OOB server in a startup banner on stdout (merged
    # with stderr here since it has been observed on either stream). Capturing
    # that banner is the ONLY reliable way to learn the real correlation
    # ID/domain — it must never be guessed client-side.
    proc = _fork_safe_spawn(
        [binary, "-json", "-o", log_path],
        shell=False, capture=True, merge_stderr=True,
    )

    domain = None
    fd = None
    if proc.stdout is not None:
        try:
            fd = proc.stdout.fileno()
        except Exception:
            fd = None

    if fd is not None:
        # Read the RAW fd via os.read(), NOT a buffered readline(): interactsh
        # prints the banner and the assigned domain in one write, so select()
        # (which polls the fd) + readline() can return the banner line and strand
        # the domain inside a TextIOWrapper's internal buffer — the fd then reads
        # empty, select() says not-ready, and the domain is silently missed.
        # Accumulating raw bytes and regex-scanning the buffer also survives a
        # domain string split across two reads.
        deadline = time.time() + timeout_s
        buf = b""
        while time.time() < deadline and domain is None:
            ready, _, _ = select.select([fd], [], [], 0.5)
            if not ready:
                continue
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break  # EOF — process closed stdout without ever printing a domain
            buf += chunk
            m = _DOMAIN_RE.search(buf)
            if m:
                domain = m.group(1).decode("utf-8", "replace")
                break

    if domain:
        token = domain.split(".", 1)[0]
        url = f"https://{domain}"
    else:
        # No confirmed domain captured within the deadline — do NOT fabricate a
        # token/URL. The process keeps running (and its JSONL log keeps
        # accumulating), but there is no real correlation ID to hand back, so
        # poll_callbacks() must never be called with a made-up token.
        token = ""
        url = ""

    return InteractshSession(url=url, log_path=log_path, token=token, proc=proc)
