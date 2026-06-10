#!/usr/bin/env python3
"""
Regression tests for browser_agent.py vision-capability detection and the
use_vision fallback / degraded-phase reporting.

Root cause being guarded against (audit of clientd.com run):
  The browser phase sent multimodal (screenshot) requests to a text-only
  Ollama model (qwen3-coder:30b), which 400s on every request. The phase
  produced 0 findings yet reported success because run() returned a
  non-empty (all-zero) dict.

Fixes verified here:
  1. _ollama_model_supports_vision() reads `ollama show` capabilities and
     returns False for text-only models, True for vision-capable ones, with a
     name-hint fallback when the capabilities API is unavailable.
  2. _resolve_use_vision() disables vision for a text-only ChatOllama backend
     and honours the BROWSER_USE_VISION override.
  3. run() returns an EMPTY dict (failure signal -> caller's bool(results)
     is False) when every executed browser task errored.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import browser_agent as ba


# ── 1. Capability detection ─────────────────────────────────────────────────

class _FakeShowResp:
    def __init__(self, capabilities):
        self.capabilities = capabilities


class _FakeClient:
    def __init__(self, capabilities):
        self._caps = capabilities

    def show(self, model):
        return _FakeShowResp(self._caps)


def _patch_ollama(monkeypatch, capabilities=None, raise_exc=False):
    """Install a fake `ollama` module so the helper does not hit a real server."""
    import types

    fake = types.ModuleType("ollama")

    def _client(host=None):
        if raise_exc:
            raise RuntimeError("connection refused")
        return _FakeClient(capabilities)

    fake.Client = _client
    monkeypatch.setitem(sys.modules, "ollama", fake)


def test_text_only_model_reports_no_vision(monkeypatch):
    # qwen3-coder:30b advertises only completion + tools (the real regression).
    _patch_ollama(monkeypatch, capabilities=["completion", "tools"])
    assert ba._ollama_model_supports_vision("qwen3-coder:30b") is False


def test_vision_capability_reports_vision(monkeypatch):
    _patch_ollama(monkeypatch, capabilities=["completion", "vision"])
    assert ba._ollama_model_supports_vision("llava:13b") is True


def test_name_hint_fallback_when_caps_missing(monkeypatch):
    # capabilities empty -> fall back to the known-multimodal-name allowlist.
    _patch_ollama(monkeypatch, capabilities=[])
    assert ba._ollama_model_supports_vision("llava:latest") is True
    assert ba._ollama_model_supports_vision("qwen3-coder:30b") is False


def test_unknown_model_conservatively_no_vision_on_api_error(monkeypatch):
    # ollama show blows up -> name heuristic; unknown text model => False.
    _patch_ollama(monkeypatch, raise_exc=True)
    assert ba._ollama_model_supports_vision("some-random-model:7b") is False
    # but a vision-named model still resolves true via the hint list
    assert ba._ollama_model_supports_vision("llama3.2-vision:11b") is True


# ── 2. use_vision resolution on the agent ───────────────────────────────────

class _FakeChatOllama:
    """Mimics langchain_ollama.ChatOllama enough for _resolve_use_vision."""
    __name__ = "ChatOllama"

    def __init__(self, model):
        self.model = model

    # class name must literally be "ChatOllama" for the backend check
    def __init_subclass__(cls, **kw):  # pragma: no cover
        super().__init_subclass__(**kw)


# Rename so __class__.__name__ == "ChatOllama" as the production code checks.
_FakeChatOllama.__name__ = "ChatOllama"
_FakeChatOllama.__qualname__ = "ChatOllama"


def _make_agent(tmp_path):
    return ba.BrowserAgent(target="example.com", findings_dir=str(tmp_path))


def test_resolve_use_vision_disabled_for_text_only_ollama(tmp_path, monkeypatch):
    _patch_ollama(monkeypatch, capabilities=["completion", "tools"])
    agent = _make_agent(tmp_path)
    agent.llm = _FakeChatOllama("qwen3-coder:30b")
    assert agent.llm.__class__.__name__ == "ChatOllama"
    agent._resolve_use_vision()
    assert agent.use_vision is False


def test_resolve_use_vision_enabled_for_vision_ollama(tmp_path, monkeypatch):
    _patch_ollama(monkeypatch, capabilities=["completion", "vision"])
    agent = _make_agent(tmp_path)
    agent.llm = _FakeChatOllama("llava:13b")
    agent._resolve_use_vision()
    assert agent.use_vision is True


def test_resolve_use_vision_default_on_for_non_ollama(tmp_path, monkeypatch):
    # Non-Ollama backend (e.g. Claude) keeps vision enabled.
    class _FakeClaude:
        pass
    _FakeClaude.__name__ = "ChatAnthropic"
    agent = _make_agent(tmp_path)
    agent.llm = _FakeClaude()
    agent._resolve_use_vision()
    assert agent.use_vision is True


def test_browser_use_vision_env_override(tmp_path, monkeypatch):
    _patch_ollama(monkeypatch, capabilities=["completion", "vision"])
    agent = _make_agent(tmp_path)
    agent.llm = _FakeChatOllama("llava:13b")  # would otherwise be True
    monkeypatch.setenv("BROWSER_USE_VISION", "0")
    agent._resolve_use_vision()
    assert agent.use_vision is False

    monkeypatch.setenv("BROWSER_USE_VISION", "1")
    agent2 = _make_agent(tmp_path)
    agent2.llm = _FakeChatOllama("qwen3-coder:30b")  # would otherwise be False
    agent2._resolve_use_vision()
    assert agent2.use_vision is True


# ── 3. run() reports failure when every task errors ─────────────────────────

def test_run_returns_empty_when_all_tasks_error(tmp_path, monkeypatch):
    """All browser requests error -> run() must return {} so the caller's
    bool(results) is False (degraded/failure, not success)."""
    monkeypatch.setattr(ba, "_browser_use_ok", True)

    agent = _make_agent(tmp_path)
    # Pretend an LLM is wired and vision resolved, skipping real init.
    agent.llm = object()
    monkeypatch.setattr(agent, "_init_llm", lambda: True)

    async def _fake_run_task(task):
        # Simulate the multimodal-400 path: every task errors.
        agent._tasks_errored += 1
        return 0

    monkeypatch.setattr(agent, "_run_task", _fake_run_task)
    # Allow every task regardless of HTTP method so the error path is exercised.
    monkeypatch.setattr(agent, "_task_allowed", lambda task: True)

    results = agent.run()
    assert results == {}, "all-errored phase must signal failure via empty dict"
    assert agent._tasks_completed == 0
    assert agent._tasks_errored > 0


def test_run_returns_results_when_a_task_completes(tmp_path, monkeypatch):
    """At least one task completes cleanly (even with 0 findings) -> run()
    returns a non-empty dict so the phase is reported as success."""
    monkeypatch.setattr(ba, "_browser_use_ok", True)

    agent = _make_agent(tmp_path)
    agent.llm = object()
    monkeypatch.setattr(agent, "_init_llm", lambda: True)

    async def _fake_run_task(task):
        agent._tasks_completed += 1
        return 0  # ran fine, just no findings

    monkeypatch.setattr(agent, "_run_task", _fake_run_task)
    monkeypatch.setattr(agent, "_task_allowed", lambda task: True)

    results = agent.run()
    assert results != {}, "a cleanly-run phase with 0 findings must NOT signal failure"
    assert agent._tasks_completed > 0
    assert sum(results.values()) == 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(pytest.main([__file__, "-q"]))
