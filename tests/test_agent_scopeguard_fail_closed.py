"""agent.ToolDispatcher.dispatch — when scopeguard fails to import, the host-gating
check must FAIL CLOSED: refuse any tool call carrying a free-form network-target arg
(url/command/host/target/request_file/body/headers) rather than silently fail OPEN and
let an LLM aim a probe at the operator's own machine/listener.

Also asserts the uncapped --max-urls contract (default 0 = unlimited).

Offline test. Synthetic targets only (*.example.invalid).
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import agent  # noqa: E402


@pytest.fixture
def dispatcher(monkeypatch):
    # Avoid loading hunt.py: dispatch() calls _h() at the top.
    monkeypatch.setattr(agent, "_h", lambda: object())
    d = agent.ToolDispatcher("app.example.invalid", memory=_FakeMemory())
    return d


class _FakeMemory:
    working_memory = ""

    def save(self):
        pass


def test_max_urls_default_is_uncapped():
    d = agent.ToolDispatcher("app.example.invalid", memory=_FakeMemory())
    assert d.max_urls == 0, "ToolDispatcher max_urls default must be 0 (unlimited)"


def test_fail_closed_blocks_freeform_target_arg_when_scopeguard_missing(dispatcher, monkeypatch):
    monkeypatch.setattr(agent, "_scopeguard", None)
    obs = dispatcher.dispatch("http_request", {"url": "http://app.example.invalid/x"})
    assert obs.startswith("[BLOCKED]"), f"expected fail-closed BLOCKED, got: {obs!r}"
    assert "scopeguard is unavailable" in obs


def test_fail_closed_allows_pure_control_tool(dispatcher, monkeypatch):
    monkeypatch.setattr(agent, "_scopeguard", None)
    # 'finish' carries only a 'verdict' arg (not a network target) -> still runs.
    obs = dispatcher.dispatch("finish", {"verdict": "done"})
    assert obs.startswith("FINISH:"), f"control tool must not be blocked: {obs!r}"


def test_scopeguard_present_still_blocks_loopback(dispatcher, monkeypatch):
    class _SG:
        @staticmethod
        def scan_command(v):
            return "127.0.0.1:8080" if "127.0.0.1" in v else ""

    monkeypatch.setattr(agent, "_scopeguard", _SG)
    obs = dispatcher.dispatch("http_request", {"url": "http://127.0.0.1:8080/"})
    assert obs.startswith("[BLOCKED]")
    assert "operator's" in obs


def test_scopeguard_scans_nested_dict_arg(dispatcher, monkeypatch):
    # A loopback target buried inside a dict arg (e.g. http_request headers /
    # json_body) must be caught by the recursive scopeguard scan, not skipped
    # because it is not a top-level string.
    class _SG:
        @staticmethod
        def scan_command(v):
            return "127.0.0.1:9999" if "127.0.0.1" in v else ""

    monkeypatch.setattr(agent, "_scopeguard", _SG)
    obs = dispatcher.dispatch("http_request", {
        "url": "http://app.example.invalid/x",
        "headers": {"X-Forwarded-Host": "127.0.0.1:9999"},
    })
    assert obs.startswith("[BLOCKED]"), f"nested dict target must be blocked: {obs!r}"
    assert "operator's" in obs


def test_scopeguard_scans_nested_list_arg(dispatcher, monkeypatch):
    class _SG:
        @staticmethod
        def scan_command(v):
            return "127.0.0.1:9999" if "127.0.0.1" in v else ""

    monkeypatch.setattr(agent, "_scopeguard", _SG)
    obs = dispatcher.dispatch("http_request", {
        "url": "http://app.example.invalid/x",
        "json_body": {"targets": ["http://app.example.invalid", "http://127.0.0.1:9999"]},
    })
    assert obs.startswith("[BLOCKED]"), f"nested list target must be blocked: {obs!r}"
