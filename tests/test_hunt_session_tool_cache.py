"""hunt.py consults the session cache only when VIK_SESSION_TOOL_CACHE=1."""

from __future__ import annotations

import os

import hunt
import session_tool_cache as cache


class _Proc:
    def __init__(self, output="fresh"):
        self.returncode = 0
        self.output = output
        self.pid = 4242

    def communicate(self, timeout=None):
        return self.output, ""

    def poll(self):
        return 0

    def kill(self):
        return None

    def wait(self, timeout=None):
        return 0


def test_run_cmd_args_skips_second_run_only_when_cache_enabled(tmp_path, monkeypatch):
    cache.clear_binding()
    monkeypatch.delenv("VIK_SESSION_TOOL_CACHE", raising=False)
    session = tmp_path / "sess"
    session.mkdir()
    os.chmod(session, 0o700)
    calls = []

    def fake_spawn(args, **kwargs):
        calls.append(list(args))
        return _Proc("live-output")

    monkeypatch.setattr(hunt, "_fork_safe_spawn", fake_spawn)
    argv = ["httpx", "-u", "https://app.example.invalid"]
    cache.bind_session("app.example.invalid", str(session), scope_domains=["app.example.invalid"])

    ok, out = hunt.run_cmd_args(argv, timeout=5)
    assert ok is True
    assert out == "live-output"
    assert len(calls) == 1
    # default path: second call still executes
    ok2, out2 = hunt.run_cmd_args(argv, timeout=5)
    assert ok2 is True
    assert out2 == "live-output"
    assert len(calls) == 2

    monkeypatch.setenv("VIK_SESSION_TOOL_CACHE", "1")
    cache.bind_session("app.example.invalid", str(session), scope_domains=["app.example.invalid"])
    calls.clear()
    ok3, out3 = hunt.run_cmd_args(argv, timeout=5)
    assert ok3 is True
    assert out3 == "live-output"
    assert len(calls) == 1
    ok4, out4 = hunt.run_cmd_args(argv, timeout=5)
    assert ok4 is True
    assert out4.startswith("[session-tool-cache hit] ")
    assert "live-output" in out4
    assert len(calls) == 1
    cache.clear_binding()
