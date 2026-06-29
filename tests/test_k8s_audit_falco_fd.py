#!/usr/bin/env python3
"""Regression test: falco_runtime() must not leak the parent-side log fd.

The earlier code passed an anonymous open() object inline as Popen's stdout,
so the parent's copy of the write-end fd was released only at GC. The fix
wraps the open() in a context manager so the parent handle is closed (and
flushed) deterministically once the child has inherited its own dup.

Synthetic only — no real falco binary, no cluster, no network.
"""
import sys
import types
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import k8s_audit  # noqa: E402


class _FakeProc:
    def __init__(self):
        self.terminated = False
        self.waited = False

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        self.waited = True
        return 0

    def kill(self):  # pragma: no cover - only on timeout
        pass


def test_falco_runtime_closes_parent_log_fd(tmp_path):
    captured = {}

    def fake_popen(argv, stdout=None, stderr=None):
        # The file object handed to Popen as stdout must still be open here
        # (the child inherits it), but must be closed once falco_runtime
        # returns.
        captured["stdout"] = stdout
        assert not stdout.closed, "log handle should be open while child runs"
        return _FakeProc()

    with mock.patch.object(k8s_audit, "_which", return_value="/usr/bin/falco"), \
            mock.patch.object(k8s_audit.subprocess, "Popen", side_effect=fake_popen), \
            mock.patch.object(k8s_audit.time, "sleep", return_value=None):
        k8s_audit.falco_runtime("ctx-acme", 1, tmp_path)

    handle = captured["stdout"]
    assert handle is not None, "Popen was never called with a stdout handle"
    assert handle.closed, "parent-side log fd must be closed after return (no fd leak)"
    assert (tmp_path / "falco_runtime.log").exists()


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
