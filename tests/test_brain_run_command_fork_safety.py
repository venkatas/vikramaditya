"""Regression guard: brain.Brain.run_command must launch via posix_spawn, not fork()+exec.

THE BUG THIS GUARDS (found by the mu.ac.in validation run, 2026-06-18):
brain_scanner.execute_script was fixed to use posix_spawn, but the AUTONOMOUS post-scan
exploit path — brain.Brain.exploit_finding -> self.run_command (brain.py:2415) — is a SEPARATE
executor that still used subprocess.Popen(..., start_new_session=True) i.e. fork()+exec. On
macOS that SIGSEGVs (rc=-11) the moment Network.framework is loaded, so EVERY exploit command
the brain ran in the full scan crashed (17× across the run) and it could never land a grounded
PoC — it backed off (correctly, without fabricating, but with no proof).

Same deterministic mechanism as tests/test_brain_scanner_fork_safety.py: register a hostile
abort() atfork child handler. fork()+exec runs it (child dies) -> rc != 0; posix_spawn does
not -> the command runs and returns 0. run_command uses no instance state, so we bypass
Brain.__init__ (which would touch the network) via __new__.
"""
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

requires_posix_spawn = pytest.mark.skipif(
    not (hasattr(os, "posix_spawn") and hasattr(os, "POSIX_SPAWN_DUP2")),
    reason="no posix_spawn fast path on this interpreter",
)


@requires_posix_spawn
def test_brain_run_command_is_fork_safe():
    src = textwrap.dedent(
        f"""
        import os, sys, ctypes
        sys.path.insert(0, {str(REPO)!r})
        import brain
        b = brain.Brain.__new__(brain.Brain)   # bypass __init__ (no network); run_command uses no self state

        libc = ctypes.CDLL(None)               # hostile non-fork-safe atfork child handler
        assert libc.pthread_atfork(None, None, libc.abort) == 0

        rc, out, err = b.run_command("echo brain_run_ok", timeout=30)
        ok = (rc == 0 and "brain_run_ok" in out)
        print("ATFORK_RESULT", "OK" if ok else "FAIL", flush=True)
        """
    )
    r = subprocess.run([sys.executable, "-c", src], capture_output=True, text=True, timeout=180)
    assert "ATFORK_RESULT OK" in r.stdout, (
        "brain.Brain.run_command ran an atfork child handler -> still uses fork()+exec; on macOS "
        f"every autonomous exploit command SIGSEGVs. rc={r.returncode} stdout={r.stdout!r} stderr={r.stderr[-500:]!r}"
    )
