"""Triage must work with REASONING models (the gemini→ollama re-run found 13/13
UNKNOWN verdicts).

ROOT CAUSE (reproduced): Ollama streams a reasoning model's chain-of-thought into a
separate ``thinking`` field; brain._stream only kept ``content``. The triage budget
(num_predict=1000) was exhausted by the <think> block before the ``VERDICT:`` content
line was emitted, so ``content`` came back empty -> _parse_verdict("") -> UNKNOWN ->
retry (same budget) -> UNKNOWN. Confirmed: same model at num_predict=600 -> 0 content
chars; at 4000 -> 129 content chars starting "VERDICT:". The 3775-char thinking was
discarded.

FIX: _stream captures the thinking stream too and falls back to it when content is
empty, so a verdict stated in the model's reasoning is still parseable.
"""
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import brain  # noqa: E402


class _FakeOllamaStream:
    """Minimal Ollama client stand-in that yields a fixed list of stream chunks."""

    def __init__(self, chunks):
        self._chunks = chunks

    def chat(self, model=None, messages=None, stream=False, options=None):
        if stream:
            return iter(self._chunks)
        return {"message": {"content": ""}}

    def list(self):
        return {"models": [{"model": "fake-reasoner"}]}


def _make_brain(chunks):
    """Build a Brain wired to a fake Ollama client, bypassing __init__'s pre-warm."""
    b = brain.Brain.__new__(brain.Brain)
    llm = brain.LLMClient.__new__(brain.LLMClient)
    llm.provider = "ollama"
    b._llm = llm
    b.client = _FakeOllamaStream(chunks)
    b.model = "fake-reasoner"
    b.triage_model = "fake-reasoner"
    b.enabled = True
    return b


def test_stream_falls_back_to_thinking_when_content_empty():
    """For verdict/triage parsing (prefer_thinking_on_empty=True): a reasoning model that
    streams only `thinking` (content starved) must not yield an empty string."""
    chunks = [
        {"message": {"content": "", "thinking": "Let me reason about this. "}},
        {"message": {"content": "", "thinking": "It is exploitable.\nVERDICT: SUBMIT"}},
    ]
    b = _make_brain(chunks)
    out = b._stream("triage this finding", "Finding Triage", 1000,
                    prefer_thinking_on_empty=True)
    assert "VERDICT: SUBMIT" in out, f"thinking was discarded; got {out!r}"


def test_stream_does_not_leak_thinking_for_narration():
    """Default (narration/analysis/report) callers must NOT receive raw chain-of-thought
    when content is empty — that would persist <think> reasoning into saved reports."""
    chunks = [
        {"message": {"content": "", "thinking": "internal reasoning that must not leak"}},
    ]
    b = _make_brain(chunks)
    out = b._stream("summarise the phase", "Phase Complete")  # no prefer_thinking_on_empty
    assert out == "", f"thinking leaked into a non-triage caller: {out!r}"


def test_stream_prefers_content_when_present():
    """No regression: when content IS produced, thinking is ignored."""
    chunks = [
        {"message": {"content": "VERDICT: ", "thinking": "noise"}},
        {"message": {"content": "DROP\n", "thinking": "more noise"}},
    ]
    b = _make_brain(chunks)
    out = b._stream("x", "y", 1000)
    assert "VERDICT: DROP" in out
    assert "noise" not in out


def test_triage_parses_verdict_from_reasoning_models_thinking():
    """End-to-end: triage_finding on a content-starved reasoning model must return the
    real verdict (from thinking), NOT UNKNOWN."""
    chunks = [
        {"message": {"content": "", "thinking":
            "Q1 yes Q2 yes Q3 yes RCE Q4 yes Q5 yes Q6 yes Q7 yes.\nVERDICT: SUBMIT"}},
    ]
    b = _make_brain(chunks)
    verdict, _reasoning = b.triage_finding(
        "Unrestricted file upload on radar-testing.example — accepts .php, served executable")
    assert verdict == "SUBMIT", f"reasoning-model triage returned {verdict!r} (was UNKNOWN before fix)"
