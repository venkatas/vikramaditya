#!/usr/bin/env python3
"""interactsh_client.py — shared out-of-band (OOB) spawn + poll helper.

Extracted so every module that needs blind-confirmation (XXE, SSRF, blind SQLi)
shares ONE interactsh-client lifecycle instead of each hunting module reimplementing
its own spawn/log-poll loop. hunt.py's existing inline Log4Shell OOB step
(run_rce_scan, ~line 5850) is a second caller of the same underlying binary; this
module does not change that call site — it is a new, independent path for new
modules to use. Uses procutil.run_capture indirectly via subprocess.Popen for the
long-lived background listener (run_capture is for bounded one-shot commands, not
a listener the caller needs to poll and later stop).
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import time
import uuid
from dataclasses import dataclass


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
    proc: subprocess.Popen | None

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
        if self.proc is None:
            return
        try:
            self.proc.send_signal(signal.SIGTERM)
            self.proc.wait(timeout=5)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass


def spawn(log_dir: str, timeout_s: int = 300) -> InteractshSession | None:
    """Start interactsh-client in the background, writing JSONL callbacks to
    ``<log_dir>/interactsh_log.jsonl``. Returns None if the binary is unavailable
    (caller must treat blind-OOB confirmation as unavailable, not fabricate one)."""
    binary = find_interactsh_binary()
    if binary is None:
        return None

    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "interactsh_log.jsonl")
    token = uuid.uuid4().hex[:12]

    log_file = open(log_path, "a")
    proc = subprocess.Popen(
        [binary, "-v", "-json"],
        stdout=log_file, stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    # interactsh-client prints its assigned domain to stdout on startup; since we
    # redirect stdout to the JSONL log file we cannot read it back synchronously
    # without racing the writer, so give it a moment then read the first line.
    time.sleep(2)
    domain = None
    if os.path.isfile(log_path):
        with open(log_path, "r", errors="ignore") as f:
            for line in f:
                if ".interact.sh" in line and "://" not in line:
                    domain = line.strip()
                    break
    if not domain:
        domain = f"{token}.interact.sh"
    url = f"https://{token}.{domain.split('.', 1)[-1] if '.' in domain else 'interact.sh'}"
    return InteractshSession(url=url, log_path=log_path, token=token, proc=proc)
