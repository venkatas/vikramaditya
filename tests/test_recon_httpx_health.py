"""P1 — a broken httpx must FAIL CLOSED, never be treated as "0 live hosts".

Regression: a segfaulting / hanging / Python `httpx` passed the bare `command -v httpx`
gate, every batch's crash was swallowed by `|| true`, LIVE_COUNT resolved to 0, and
`.probe.done` was written unconditionally — locking in an empty live set that --resume
would never re-probe and downstream phases assessed as authoritative.

Covers: the bounded semantic health check (recon.sh `httpx_healthy` + hunt.py
`_httpx_readiness_reason`), the HTTPX_HEALTHY Phase-3 gate, per-batch crash accounting,
the guarded `.probe.done` write, and the distinct `.probe.failed` marker.
"""
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import hunt  # noqa: E402

RECON = (REPO / "recon.sh").read_text()


# ── helpers ─────────────────────────────────────────────────────────────────
def _fake_bin(tmp_path, name, body):
    p = tmp_path / name
    p.write_text("#!/bin/sh\n" + body + "\n")
    p.chmod(p.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(p)


def _extract_bash_func(src, fname):
    """Extract a brace-balanced `fname() { ... }` definition from bash source."""
    m = re.search(rf"{re.escape(fname)}\(\)\s*\{{", src)
    assert m, f"{fname} not defined in recon.sh"
    i = m.end() - 1
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[m.start():j + 1]
    raise AssertionError("unbalanced braces")


def _run_httpx_healthy(bin_path):
    """Source the real recon.sh httpx_healthy() and run it against bin_path."""
    func = _extract_bash_func(RECON, "httpx_healthy")
    script = func + f'\nif httpx_healthy "{bin_path}"; then echo HEALTHY; else echo UNHEALTHY; fi\n'
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
    return r.stdout.strip()


# ── bash httpx_healthy() — functional, real function extracted from recon.sh ──
def test_bash_healthy_pd_banner(tmp_path):
    b = _fake_bin(tmp_path, "httpx",
                  'echo "Current Version: v1.6.0 https://github.com/projectdiscovery/httpx"')
    assert _run_httpx_healthy(b) == "HEALTHY"


def test_bash_rejects_python_httpx(tmp_path):
    # even with exit 0, the Python httpx must be rejected (no PD banner + python-httpx marker)
    b = _fake_bin(tmp_path, "httpx", 'echo "python-httpx/0.27.0"')
    assert _run_httpx_healthy(b) == "UNHEALTHY"


def test_bash_rejects_segfault_nonzero(tmp_path):
    b = _fake_bin(tmp_path, "httpx", 'echo "boom"; exit 139')
    assert _run_httpx_healthy(b) == "UNHEALTHY"


def test_bash_rejects_missing_banner(tmp_path):
    b = _fake_bin(tmp_path, "httpx", 'echo "some other tool v1"')
    assert _run_httpx_healthy(b) == "UNHEALTHY"


def test_bash_rejects_empty_bin_arg():
    func = _extract_bash_func(RECON, "httpx_healthy")
    script = func + '\nif httpx_healthy ""; then echo HEALTHY; else echo UNHEALTHY; fi\n'
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
    assert r.stdout.strip() == "UNHEALTHY"


# ── python _httpx_readiness_reason() — functional, injectable candidates ──────
def test_py_healthy_returns_none(tmp_path):
    b = _fake_bin(tmp_path, "httpx", 'echo "projectdiscovery httpx v1.6.0"')
    assert hunt._httpx_readiness_reason([b]) is None


def test_py_python_httpx_flagged(tmp_path):
    b = _fake_bin(tmp_path, "httpx", 'echo "python-httpx/0.27"')
    reason = hunt._httpx_readiness_reason([b])
    assert reason and "python" in reason.lower()


def test_py_segfault_flagged(tmp_path):
    b = _fake_bin(tmp_path, "httpx", 'exit 139')
    reason = hunt._httpx_readiness_reason([b])
    assert reason and ("139" in reason or "crash" in reason.lower())


def test_py_no_binary_returns_none(tmp_path):
    # absence is check_tools' job, not a readiness gap
    assert hunt._httpx_readiness_reason([str(tmp_path / "nope")]) is None


def test_py_first_healthy_wins(tmp_path):
    good = _fake_bin(tmp_path, "httpx_good", 'echo "projectdiscovery httpx"')
    bad = _fake_bin(tmp_path, "httpx_bad", 'exit 139')
    # a healthy earlier candidate short-circuits a later broken one
    assert hunt._httpx_readiness_reason([good, bad]) is None


def test_py_timeout_flagged(monkeypatch, tmp_path):
    b = _fake_bin(tmp_path, "httpx", 'echo x')

    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="httpx", timeout=20)

    monkeypatch.setattr(hunt.subprocess, "run", _boom)
    reason = hunt._httpx_readiness_reason([b])
    assert reason and ("timed out" in reason.lower() or "hang" in reason.lower())


def test_check_tool_readiness_surfaces_broken_httpx(tmp_path, monkeypatch):
    b = _fake_bin(tmp_path, "httpx", 'exit 139')
    monkeypatch.setattr(hunt, "_httpx_readiness_reason", lambda *a, **k: f"{b}: crash")
    gaps = hunt.check_tool_readiness(installed=[])
    assert any(g["tool"] == "httpx" for g in gaps), "broken httpx not surfaced as a readiness gap"


# ── recon.sh source-assertions: fail-closed wiring ───────────────────────────
def test_health_check_is_bounded_and_semantic():
    func = _extract_bash_func(RECON, "httpx_healthy")
    assert "timeout 20" in func, "httpx -version probe is not time-bounded"
    assert "python-httpx" in func, "Python httpx not rejected"
    assert "projectdiscovery" in func, "ProjectDiscovery banner not required"


def test_phase3_gate_keys_on_health_not_presence():
    assert '[ "${HTTPX_HEALTHY:-0}" != 1 ]' in RECON, "Phase-3 gate does not key on HTTPX_HEALTHY"
    # the old presence-only gate must be gone from the probe branch
    assert "if ! tool_ok httpx; then" not in RECON, "Phase-3 still gates on bare `tool_ok httpx`"


def test_per_batch_crash_accounting():
    assert "PROBE_CRASHES=" in RECON and "BATCH_RC=$?" in RECON, "no per-batch crash accounting"
    # the primary probe no longer swallows the exit code with `|| true`
    assert ">> \"$RECON_DIR/live/httpx_full.txt\"\n        BATCH_RC=$?" in RECON


def test_probe_done_marker_is_guarded():
    # the literal write must still exist (existing resume tests depend on it) ...
    assert '> "$RECON_DIR/live/.probe.done"' in RECON
    # ... but only inside the all-crashed guard's else-branch
    assert 'PROBE_CRASHES:-0}" -ge "${TOTAL_BATCHES' in RECON, "no all-crashed guard on the marker"


def test_distinct_failure_marker_written():
    assert '.probe.failed' in RECON, "no distinct probe-failure marker"
    # hunt.py must consume it and fail closed
    HUNT = (REPO / "hunt.py").read_text()
    assert '.probe.failed' in HUNT and '_mark_degraded("recon"' in HUNT
