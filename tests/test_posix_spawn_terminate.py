"""_PosixSpawnProc.terminate() — subprocess.Popen-API parity (SIGTERM), so background children
launched fork-safely via _fork_safe_spawn (e.g. interactsh-client) can be stopped gracefully
instead of only SIGKILL'd. Guards the hunt.py interactsh conversion (it calls .terminate())."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import procutil  # noqa: E402


def test_fork_safe_spawn_has_terminate_and_it_stops_the_child():
    p = procutil._fork_safe_spawn(["sleep", "30"], shell=False, capture=False)
    assert hasattr(p, "terminate")        # Popen-API parity for background children
    assert p.poll() is None               # running
    p.terminate()                         # SIGTERM
    rc = p.wait(timeout=10)               # must end promptly, not linger
    assert rc is not None
    # posix_spawn path reports -SIGTERM (-15); the Popen fallback agrees.
    assert rc in (-15, 143) or rc < 0
