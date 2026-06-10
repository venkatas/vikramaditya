"""Tests for the Google Gemini provider wired into the multi-provider brain.

Gemini exposes an OpenAI-compatible ``/chat/completions`` endpoint at
``https://generativelanguage.googleapis.com/v1beta/openai/`` with a
``Authorization: Bearer $GEMINI_API_KEY`` header, so it reuses brain.py's
existing OpenAI-compatible chat path. These tests are network-free — the
requests session's ``.post`` is replaced with a capturing fake.

Coverage:
  - provider init (base URL, auth header, availability, description)
  - single-turn chat() routes to the Gemini OpenAI-compat endpoint
  - chat_messages() preserves full multi-turn history (used by the active
    exploit loop in brain_scanner.py)
  - auto-detection selects gemini when only GEMINI_API_KEY is present
  - PROVIDER_PRIORITY / DEFAULT_MODELS / list_models include gemini
  - brain_scanner.pick_model() + ask_brain() route cloud vs ollama correctly
"""
import json

import pytest

import brain
from brain import LLMClient
import brain_scanner


GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/openai"


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


@pytest.fixture(autouse=True)
def _reset_scanner_llm_cache():
    """brain_scanner caches its LLMClient module-globally; reset between tests."""
    brain_scanner._SCANNER_LLM = None
    brain_scanner._SCANNER_LLM_SIG = None
    yield
    brain_scanner._SCANNER_LLM = None
    brain_scanner._SCANNER_LLM_SIG = None


@pytest.fixture
def gemini_env(monkeypatch):
    """Only the Gemini key present; other provider keys cleared."""
    monkeypatch.setenv("GEMINI_API_KEY", "AIza-TEST-KEY")
    for var in ("BRAIN_PROVIDER", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "XAI_API_KEY"):
        monkeypatch.delenv(var, raising=False)


# ── provider init ───────────────────────────────────────────────────────────

def test_gemini_init_base_and_auth(gemini_env):
    c = LLMClient("gemini")
    assert c.provider == "gemini"
    assert c.available is True
    assert c._gemini_base == GEMINI_BASE
    assert c._http.headers["Authorization"] == "Bearer AIza-TEST-KEY"
    assert "Gemini" in c.description


def test_gemini_no_key_is_unavailable(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    c = LLMClient("gemini")
    assert c.available is False


# ── chat routing ────────────────────────────────────────────────────────────

def test_gemini_chat_posts_to_openai_compat_endpoint(gemini_env):
    c = LLMClient("gemini")
    captured = {}

    def fake_post(url, data=None, timeout=None):
        captured["url"] = url
        captured["body"] = json.loads(data)
        return _FakeResp({"choices": [{"message": {"content": "PONG"}}]})

    c._http.post = fake_post
    out = c.chat("gemini-3.5-flash", "system text", "user text")

    assert out == "PONG"
    assert captured["url"] == f"{GEMINI_BASE}/chat/completions"
    assert captured["body"]["model"] == "gemini-3.5-flash"
    assert [m["role"] for m in captured["body"]["messages"]] == ["system", "user"]


def test_gemini_chat_messages_preserves_history(gemini_env):
    c = LLMClient("gemini")
    captured = {}

    def fake_post(url, data=None, timeout=None):
        captured["url"] = url
        captured["body"] = json.loads(data)
        return _FakeResp({"choices": [{"message": {"content": "OK"}}]})

    c._http.post = fake_post
    msgs = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "u1"},
        {"role": "assistant", "content": "a1"},
        {"role": "user", "content": "u2"},
    ]
    out = c.chat_messages("gemini-3.5-flash", msgs)

    assert out == "OK"
    assert captured["url"].endswith("/v1beta/openai/chat/completions")
    # Full multi-turn history must pass through unchanged (no flattening).
    assert captured["body"]["messages"] == msgs


# ── registration / discovery ────────────────────────────────────────────────

def test_gemini_in_priority_and_defaults():
    assert "gemini" in LLMClient.PROVIDER_PRIORITY
    assert LLMClient.DEFAULT_MODELS["gemini"].startswith("gemini-")


def test_gemini_list_models(gemini_env):
    c = LLMClient("gemini")
    models = c.list_models()
    assert models and all(m.startswith("gemini-") for m in models)


def test_auto_detect_picks_gemini_when_only_key(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "AIza-TEST-KEY")
    for var in ("BRAIN_PROVIDER", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "XAI_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    # Make local providers unavailable so auto-detect falls to the cloud key.
    monkeypatch.setattr(brain, "_ollama_lib", None, raising=False)
    monkeypatch.setattr(brain, "_mlx_lm", None, raising=False)
    c = LLMClient()  # auto-detect
    assert c.provider == "gemini"
    assert c.available is True


# ── brain_scanner cloud routing ─────────────────────────────────────────────

def test_scanner_pick_model_cloud_default(monkeypatch):
    monkeypatch.setenv("BRAIN_PROVIDER", "gemini")
    monkeypatch.delenv("BRAIN_SCANNER_MODEL", raising=False)
    assert brain_scanner.pick_model() == "gemini-3.5-flash"


def test_scanner_pick_model_cloud_override(monkeypatch):
    monkeypatch.setenv("BRAIN_PROVIDER", "gemini")
    monkeypatch.setenv("BRAIN_SCANNER_MODEL", "gemini-3.1-pro-preview")
    assert brain_scanner.pick_model() == "gemini-3.1-pro-preview"


def test_gemini_list_models_are_valid_codes(monkeypatch):
    # Advertised models must be real codes — bare pro/flash names 404 and would
    # trip the empty-response abort. GA names have no suffix; pro/base-flash do.
    monkeypatch.setenv("GEMINI_API_KEY", "AIza-TEST-KEY")
    monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
    c = LLMClient("gemini")
    models = c.list_models()
    assert "gemini-3.5-flash" in models          # GA default
    assert "gemini-3.1-pro-preview" in models     # preview-suffixed, not bare
    assert "gemini-3.1-pro" not in models         # bare name is invalid


def test_scanner_ask_brain_routes_to_cloud(monkeypatch):
    monkeypatch.setenv("BRAIN_PROVIDER", "gemini")
    captured = {}

    class _FakeLLM:
        def chat_messages(self, model, messages, max_tokens=4000):
            captured["model"] = model
            captured["messages"] = messages
            return "gemini cloud reply 12345"

    monkeypatch.setattr(brain_scanner, "_get_scanner_llm", lambda: _FakeLLM())
    msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
    out = brain_scanner.ask_brain("gemini-3.5-flash", msgs)

    assert out == "gemini cloud reply 12345"
    assert captured["model"] == "gemini-3.5-flash"
    assert captured["messages"] == msgs


def test_scanner_pick_model_mlx_returns_nonempty(monkeypatch):
    # MLX has no entry in DEFAULT_MODELS; pick_model must still return a truthy
    # model id (the MLX model is loaded internally / ignores the name) so the
    # scanner is not wrongly refused. Regression guard (Codex MEDIUM #1).
    monkeypatch.setenv("BRAIN_PROVIDER", "mlx")
    monkeypatch.delenv("BRAIN_SCANNER_MODEL", raising=False)
    monkeypatch.setenv("MLX_MODEL", "mlx-community/Some-Model-4bit")
    assert brain_scanner.pick_model() == "mlx-community/Some-Model-4bit"


def test_scanner_fails_fast_when_cloud_provider_unavailable(monkeypatch):
    # Cloud provider selected but client unavailable (e.g. no API key) must NOT
    # enter the iteration loop — it should log and return early. (Codex MEDIUM #2)
    monkeypatch.setenv("BRAIN_PROVIDER", "gemini")
    monkeypatch.setenv("BRAIN_SCANNER_MODEL", "gemini-3.5-flash")  # truthy model

    class _Unavail:
        available = False

        def chat_messages(self, *a, **k):  # pragma: no cover - must never be called
            raise AssertionError("loop must not run when provider unavailable")

    monkeypatch.setattr(brain_scanner, "_get_scanner_llm", lambda: _Unavail())
    # Should return None (early) without raising / without iterating.
    result = brain_scanner.run_brain_scanner("https://example.invalid", output_dir=None)
    assert result is None


def test_scanner_aborts_after_empty_response_streak(monkeypatch):
    # A provider that returns "" every call (revoked/over-quota key, invalid model,
    # network) must abort after MAX_EMPTY_STREAK iterations, not run all 15.
    # (Codex round-2 MEDIUM: the availability gate can't catch a live-call failure.)
    monkeypatch.setenv("BRAIN_PROVIDER", "gemini")
    monkeypatch.setenv("BRAIN_SCANNER_MODEL", "gemini-3.5-flash")

    class _Avail:
        available = True

    monkeypatch.setattr(brain_scanner, "_get_scanner_llm", lambda: _Avail())

    calls = {"n": 0}

    def fake_ask(model, messages, max_tokens=4000):
        calls["n"] += 1
        return ""

    monkeypatch.setattr(brain_scanner, "ask_brain", fake_ask)

    brain_scanner.run_brain_scanner(
        "https://example.invalid", briefing="probe", output_dir=None, mode="scan")

    assert calls["n"] == brain_scanner.MAX_EMPTY_STREAK


def test_scanner_llm_cache_rebuilds_on_provider_or_key_change(monkeypatch):
    # Cache must be keyed to (provider, key) so a long-lived process never reuses
    # a client bound to a stale provider / rotated credential. (Codex round-2 LOW)
    builds = {"n": 0}

    class _FakeClient:
        def __init__(self):
            builds["n"] += 1

    monkeypatch.setattr("brain.LLMClient", _FakeClient)
    brain_scanner._SCANNER_LLM = None
    brain_scanner._SCANNER_LLM_SIG = None

    monkeypatch.setenv("BRAIN_PROVIDER", "gemini")
    monkeypatch.setenv("GEMINI_API_KEY", "key-A")
    c1 = brain_scanner._get_scanner_llm()
    c2 = brain_scanner._get_scanner_llm()  # unchanged sig → cached
    assert c1 is c2
    assert builds["n"] == 1

    monkeypatch.setenv("BRAIN_PROVIDER", "openai")  # provider change → rebuild
    monkeypatch.setenv("OPENAI_API_KEY", "key-B")
    c3 = brain_scanner._get_scanner_llm()
    assert c3 is not c1
    assert builds["n"] == 2

    monkeypatch.setenv("OPENAI_API_KEY", "key-C")  # same provider, rotated key → rebuild
    brain_scanner._get_scanner_llm()
    assert builds["n"] == 3


def test_redact_secret_strips_bearer_and_apikey():
    from brain import _redact_secret
    assert _redact_secret("Connection error: Authorization: Bearer AIzaSECRETKEY here") \
        == "Connection error: Authorization: Bearer *** here"
    assert "SECRET" not in _redact_secret("x-api-key: SECRETVALUE")


def test_scanner_ask_brain_defaults_to_ollama(monkeypatch):
    monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
    import ollama
    captured = {}

    def fake_chat(model, messages, options=None):
        captured["model"] = model
        return {"message": {"content": "ollama local reply 67890"}}

    monkeypatch.setattr(ollama, "chat", fake_chat)
    out = brain_scanner.ask_brain("qwen2.5-coder:14b", [{"role": "user", "content": "hi"}])

    assert out == "ollama local reply 67890"
    assert captured["model"] == "qwen2.5-coder:14b"
