"""A misconfigured cloud brain must FAIL LOUD, not run a whole scan brainless.

ROOT CAUSE (reproduced): _init_provider marked HTTP providers (gemini/openai/grok)
``available=True`` from key-presence + an HTTP session alone — no check the key works
(only ollama did a real health-check). chat() then swallowed every exception -> "". An
invalid GEMINI_API_KEY (a real engagement hit this: a Google 'AQ.Ab8R…' OAuth token, not
an 'AIza…' key) ran a ~70-min scan with EVERY brain call empty; "HUNT COMPLETE" still
printed.

FIX: a startup health-check (one minimal chat request) classifies the response. It marks
the provider unavailable ONLY for a PERSISTENT auth/billing failure (bad key, revoked,
credits/quota depleted) — transient failures (timeout, connection, 5xx, plain rate-limit)
and non-auth 4xx (model-not-found) keep the provider. An explicitly-requested provider
that comes back unavailable falls back to local Ollama with a loud warning.

NOTE: GET /models is NOT usable for validation — Gemini's OpenAI-compat /models returns
200 even for an invalid key; only a real chat call surfaces the auth/billing error. The
same bad key was observed returning 400 "Please pass a valid API key" AND, later, 429
"prepayment credits are depleted" — so the classifier keys on the body, not just the code.
"""
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import brain  # noqa: E402


class _Resp:
    def __init__(self, status_code, text=""):
        self.status_code = status_code
        self.text = text


def _post_returning(status_code, text=""):
    def _fake_post(self, *args, **kwargs):
        return _Resp(status_code, text)
    return _fake_post


def _post_raising(exc):
    def _fake_post(self, *args, **kwargs):
        raise exc
    return _fake_post


class _FakeOllamaLib:
    class Client:
        def __init__(self, host=None):
            pass

        def list(self):
            return {"models": [{"model": "phi4:14b"}]}


def _gemini_client():
    c = brain.LLMClient.__new__(brain.LLMClient)
    c.provider = "gemini"
    c._http = None
    c.available = False
    return c


# ── classification: persistent auth/billing failure -> unavailable ────────────

@pytest.mark.parametrize("status,text", [
    (400, "Please pass a valid API key"),
    (401, "Unauthorized"),
    (403, "Permission denied"),
    (429, "Your prepayment credits are depleted. Please go to AI Studio billing."),
])
def test_healthcheck_false_on_persistent_auth_or_billing_failure(monkeypatch, status, text):
    monkeypatch.setenv("GEMINI_API_KEY", "AQ.bad")
    monkeypatch.setattr("requests.Session.post", _post_returning(status, text))
    c = _gemini_client()
    c._init_provider("gemini")
    assert c.available is False, f"status={status} text={text!r} should disable provider"


# ── classification: transient / non-auth -> keep provider ─────────────────────

@pytest.mark.parametrize("status,text", [
    (200, '{"choices":[]}'),
    (404, "models/foo is not found"),          # bad model, NOT bad key
    (429, "Resource has been exhausted (rate limit). Try again later."),  # transient
    (500, "Internal error"),
    (503, "Service unavailable"),
])
def test_healthcheck_true_on_transient_or_non_auth(monkeypatch, status, text):
    monkeypatch.setenv("GEMINI_API_KEY", "AIza-maybe-ok")
    monkeypatch.setattr("requests.Session.post", _post_returning(status, text))
    c = _gemini_client()
    c._init_provider("gemini")
    assert c.available is True, f"status={status} text={text!r} should NOT disable provider"


def test_healthcheck_true_on_network_exception(monkeypatch):
    """A connection/timeout error at startup must not wrongly disable the provider."""
    monkeypatch.setenv("GEMINI_API_KEY", "AIza-maybe-ok")
    monkeypatch.setattr("requests.Session.post", _post_raising(TimeoutError("timed out")))
    c = _gemini_client()
    c._init_provider("gemini")
    assert c.available is True


# ── explicit-provider fallback to local Ollama ────────────────────────────────

def test_explicit_provider_falls_back_to_ollama_on_bad_key(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "AQ.bad")
    monkeypatch.setattr("requests.Session.post",
                        _post_returning(400, "Please pass a valid API key"))
    monkeypatch.setattr(brain, "_ollama_lib", _FakeOllamaLib)

    c = brain.LLMClient(provider="gemini")

    assert c.available is True, "fallback to ollama did not happen"
    assert c.provider == "ollama", f"expected fallback to ollama, got provider={c.provider!r}"
