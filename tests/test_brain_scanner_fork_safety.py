"""Regression guard: brain_scanner.execute_script must launch commands via posix_spawn,
NOT fork()+exec.

ROOT CAUSE (observed live on an engagement run, 2026-06-17)
-----------------------------------------------------------
brain_scanner.execute_script ran the brain's exploit-verification commands with plain
``subprocess.run`` (fork()+exec). On macOS the parent has loaded Apple's
Network.framework, whose NON-fork-safe ``pthread_atfork`` child handler SIGSEGVs the
forked child before exec. Result: EVERY curl/wget the brain executed returned
``returncode: -11`` with empty output, and the brain wrongly concluded a REAL exposed
``/db/`` SQL dump was a "false positive: detected the resource but cannot retrieve it".
That is a critical FP-discipline hazard — the tool's own crash silently downgrades real
findings. hunt.py already fixed this class via posix_spawn (v10.3.3); execute_script
must use the same fork-safe spawner.

Same deterministic mechanism as tests/test_posix_spawn_fork_safety.py: register a
hostile abort() atfork child handler. fork()+exec runs it (child dies, SIGABRT) →
returncode != 0; posix_spawn does not → the command runs and returns 0.
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


def _run_with_hostile_atfork(call_src: str) -> subprocess.CompletedProcess:
    src = textwrap.dedent(
        f"""
        import os, sys, ctypes
        sys.path.insert(0, {str(REPO)!r})
        import brain_scanner  # import BEFORE registering the handler (import stays clean)

        # Hostile non-fork-safe child atfork handler — models Apple Network.framework's
        # nw_settings_child_has_forked (which SIGSEGVs the forked child).
        libc = ctypes.CDLL(None)
        assert libc.pthread_atfork(None, None, libc.abort) == 0

        {call_src}

        print("ATFORK_RESULT", "OK" if ok else "FAIL", flush=True)
        """
    )
    return subprocess.run([sys.executable, "-c", src], capture_output=True, text=True, timeout=180)


@requires_posix_spawn
def test_execute_script_bash_is_fork_safe():
    # Covers BOTH the `bash -n` syntax pre-check AND the main exec — both must be fork-safe.
    r = _run_with_hostile_atfork(
        'res = brain_scanner.execute_script("bash", "echo redteam_ok"); '
        'ok = (res["returncode"] == 0 and "redteam_ok" in res["stdout"])'
    )
    assert "ATFORK_RESULT OK" in r.stdout, (
        "execute_script(bash) ran an atfork child handler -> still uses fork()+exec; on macOS "
        f"every brain exploit command would SIGSEGV. rc={r.returncode} "
        f"stdout={r.stdout!r} stderr={r.stderr[-500:]!r}"
    )


@requires_posix_spawn
def test_execute_script_python_is_fork_safe():
    r = _run_with_hostile_atfork(
        'res = brain_scanner.execute_script("python", "print(40 + 2)"); '
        'ok = (res["returncode"] == 0 and "42" in res["stdout"])'
    )
    assert "ATFORK_RESULT OK" in r.stdout, (
        "execute_script(python) ran an atfork child handler -> still forks. "
        f"rc={r.returncode} stdout={r.stdout!r} stderr={r.stderr[-500:]!r}"
    )
