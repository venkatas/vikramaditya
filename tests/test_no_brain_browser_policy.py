"""Tools-only policy must reach browser code, not merely disable hunt._brain."""
from __future__ import annotations

import sys

import pytest

import browser_agent
import hunt


def test_unlocked_browser_never_initializes_model_when_ai_disabled(tmp_path, monkeypatch):
    agent = browser_agent.BrowserAgent("https://example.invalid", tmp_path, enable_ai=False)
    monkeypatch.setattr(browser_agent, "_browser_use_ok", True)

    def forbidden(*args, **kwargs):
        pytest.fail("tools-only browser initialized a model")

    monkeypatch.setattr(browser_agent, "init_browser_llm", forbidden)
    assert agent._init_llm() is False
    assert agent.run() == {}
    assert agent.partial
    assert "AI-driven browser validation disabled" in (
        tmp_path / "manual_review" / "coverage_gaps.txt").read_text()


def test_locked_tools_only_browser_keeps_guarded_non_ai_rendering(tmp_path, monkeypatch):
    agent = browser_agent.BrowserAgent("https://example.invalid", tmp_path,
                                       scope_lock=True, enable_ai=False)
    monkeypatch.setattr(agent, "_run_exact_scope", lambda: {"GuardedRendering": 0})
    monkeypatch.setattr(agent, "_init_llm", lambda: pytest.fail("LLM called"))
    assert agent.run() == {"GuardedRendering": 0}


def test_hunt_browser_wrapper_passes_explicit_policy(tmp_path, monkeypatch):
    seen = []

    class Browser:
        partial = True
        _tasks_completed = 0
        _tasks_errored = 0

        def __init__(self, **kwargs):
            seen.append(kwargs)

        def run(self):
            assert seen[-1]["enable_ai"] is False
            return {}

    monkeypatch.setattr(browser_agent, "BrowserAgent", Browser)
    monkeypatch.setattr(hunt, "_brain", None)
    hunt._reset_degraded()
    try:
        assert hunt.run_browser_scan("example.invalid", str(tmp_path), enable_ai=False) is False
        assert seen[0]["scope_lock"] is False
        assert any(row["tool"] == "browser" for row in hunt._DEGRADED_CAPABILITIES)
    finally:
        hunt._reset_degraded()


@pytest.mark.parametrize("locked", [False, True])
def test_cli_no_brain_reaches_pipeline_policy_before_browser_stage(tmp_path, monkeypatch, locked):
    (tmp_path / "common.txt").write_text("fixture")
    monkeypatch.setattr(hunt, "WORDLIST_DIR", str(tmp_path))
    monkeypatch.setattr(hunt, "_brain", None)
    monkeypatch.setattr(hunt, "check_tools", lambda: ([], []))
    monkeypatch.setattr(hunt, "print_dashboard", lambda *a: None)
    monkeypatch.setattr(hunt, "init_brain", lambda *a, **k: pytest.fail("Brain initialized"))
    seen = []

    def pipeline(*args, **kwargs):
        seen.append(kwargs)
        return {"domain": "example.invalid", "success": True}

    monkeypatch.setattr(hunt, "hunt_target", pipeline)
    argv = ["hunt.py", "--target", "example.invalid", "--full", "--no-brain"]
    if locked:
        argv.append("--scope-lock")
    monkeypatch.setattr(sys, "argv", argv)
    hunt.main()
    assert len(seen) == 1 and seen[0]["enable_ai"] is False
    assert seen[0]["scope_lock"] is locked


def test_no_brain_and_react_agent_are_rejected_before_any_preflight(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["hunt.py", "--agent", "--no-brain",
                                      "--target", "example.invalid"])
    monkeypatch.setattr(hunt, "check_tools", lambda: pytest.fail("preflight started"))
    monkeypatch.setattr(hunt, "init_brain", lambda *a, **k: pytest.fail("Brain initialized"))
    with pytest.raises(SystemExit) as exc:
        hunt.main()
    assert exc.value.code == 2
