"""Behavioral regression test for the v9.23.1 brain.py Q6 verdict-correction fix.

Bug (codex/grok review): the 7-Question-Gate Q6 polarity post-check only
APPENDED a 'Treating Q6 as YES/NO' note to gate_workings.md. The returned
verdict was parsed BEFORE the note and still reflected the model's *flipped*
Q6 answer, so triage acted on the uncorrected reading while the audit log
claimed a correction.

Fix: when the deterministic Q6 contradiction is detected, actually re-derive
the returned verdict so it matches the corrected Q6 (not just the log).

These tests assert real behavior:
  - _apply_q6_correction (pure, deterministic) — direct unit coverage.
  - triage_finding (full flow) — with _stream_fast stubbed to a canned gate
    body (the LLM is the only external/non-deterministic dependency); the
    verdict-correction code under test runs for real.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from brain import Brain  # noqa: E402


def _bare_brain():
    """Instantiate Brain without connecting to the LLM provider."""
    b = Brain.__new__(Brain)
    b.enabled = True
    return b


# ---------------------------------------------------------------------------
# Pure helper — _apply_q6_correction
# ---------------------------------------------------------------------------

def test_apply_q6_correction_no_note_is_passthrough():
    # No contradiction note -> verdict untouched.
    assert Brain._apply_q6_correction("SUBMIT", "Q6: YES\n", "") == "SUBMIT"
    assert Brain._apply_q6_correction("DROP", "Q6: NO\n", "") == "DROP"


def test_apply_q6_correction_should_be_no_downgrades_submit_to_drop():
    # Corrected Q6 = NO (finding IS on the rejected list) -> hard gate -> DROP.
    note = "[Q6 consistency] ... so Q6 should be NO (not YES). Treating Q6 as NO."
    gate = "Q6: YES\n- Missing SPF is on the always-rejected list.\nQ7: YES\n"
    assert Brain._apply_q6_correction("SUBMIT", gate, note) == "DROP"
    assert Brain._apply_q6_correction("CHAIN", gate, note) == "DROP"


def test_apply_q6_correction_should_be_yes_drop_to_submit_when_others_pass():
    # Corrected Q6 = YES and every other gate answer YES -> clean SUBMIT.
    note = "[Q6 consistency] ... so Q6 should be YES (not NO). Treating Q6 as YES."
    gate = (
        "Q1: YES\nQ2: YES\nQ3: YES\nQ4: YES\nQ5: YES\n"
        "Q6: NO\n- SQL injection is not listed as an always-rejected issue.\n"
        "Q7: YES\n"
    )
    assert Brain._apply_q6_correction("DROP", gate, note) == "SUBMIT"


def test_apply_q6_correction_should_be_yes_drop_to_chain_when_others_fail():
    # Corrected Q6 = YES but another gate answer is NO -> CHAIN, not SUBMIT.
    note = "[Q6 consistency] ... so Q6 should be YES (not NO). Treating Q6 as YES."
    gate = (
        "Q1: NO\nQ2: YES\nQ3: YES\nQ4: YES\nQ5: YES\n"
        "Q6: NO\n- not listed on the rejected list.\n"
        "Q7: YES\n"
    )
    assert Brain._apply_q6_correction("DROP", gate, note) == "CHAIN"


def test_apply_q6_correction_should_be_yes_leaves_submit_alone():
    # 'should be YES' correction only lifts a DROP; a SUBMIT is unaffected.
    note = "[Q6 consistency] ... so Q6 should be YES (not NO). Treating Q6 as YES."
    gate = "Q6: NO\n- not listed.\nQ7: YES\n"
    assert Brain._apply_q6_correction("SUBMIT", gate, note) == "SUBMIT"


# ---------------------------------------------------------------------------
# Full flow — triage_finding returns the CORRECTED verdict
# ---------------------------------------------------------------------------

def _flipped_no_gate():
    """Model output: verdict DROP, but Q6=NO contradicts its own reasoning."""
    return (
        "VERDICT: DROP\n"
        "GATE ANSWERS:\n"
        "Q1: YES\n- working PoC HTTP request returns the DB error\n"
        "Q2: YES\n- affects a normal authenticated user\n"
        "Q3: YES\n- leaks PII from the users table\n"
        "Q4: YES\n- in scope\n"
        "Q5: YES\n- not a duplicate\n"
        "Q6: NO\n- SQL injection is not listed as an always-rejected issue.\n"
        "Q7: YES\n- a triager would call this a real bug\n"
        "VERDICT REASONING: strong finding.\n"
    )


def test_triage_finding_corrects_flipped_q6_no_to_submit(monkeypatch):
    b = _bare_brain()
    monkeypatch.setattr(b, "_stream_fast", lambda *a, **k: _flipped_no_gate())

    verdict, result = b.triage_finding("Blind SQLi in /api/users?id=")

    # The model literally said 'VERDICT: DROP', but Q6 was a polarity flip and
    # every other gate answer is YES -> the corrected verdict is SUBMIT.
    assert verdict == "SUBMIT", f"expected corrected SUBMIT, got {verdict}"
    # The raw model body is returned unchanged (audit fidelity).
    assert "VERDICT: DROP" in result


def test_triage_finding_downgrades_flipped_q6_yes_to_drop(monkeypatch):
    b = _bare_brain()
    gate = (
        "VERDICT: SUBMIT\n"
        "GATE ANSWERS:\n"
        "Q1: YES\nQ2: YES\nQ3: YES\nQ4: YES\nQ5: YES\n"
        "Q6: YES\n- Missing SPF record is on the always-rejected list.\n"
        "Q7: YES\n"
        "VERDICT REASONING: looks reportable.\n"
    )
    monkeypatch.setattr(b, "_stream_fast", lambda *a, **k: gate)

    verdict, result = b.triage_finding("Missing SPF record")

    # Q6 reasoning says the finding IS on the always-rejected list -> Q6 should
    # be NO -> hard gate failure -> the SUBMIT the model emitted becomes DROP.
    assert verdict == "DROP", f"expected corrected DROP, got {verdict}"
    assert "VERDICT: SUBMIT" in result


def test_triage_finding_leaves_consistent_gate_untouched(monkeypatch):
    b = _bare_brain()
    gate = (
        "VERDICT: SUBMIT\n"
        "Q1: YES\nQ2: YES\nQ3: YES\nQ4: YES\nQ5: YES\n"
        "Q6: YES\n- The finding does not match any always-rejected criteria.\n"
        "Q7: YES\n"
    )
    monkeypatch.setattr(b, "_stream_fast", lambda *a, **k: gate)

    verdict, _ = b.triage_finding("Stored XSS in profile bio")
    assert verdict == "SUBMIT"


def test_triage_finding_writes_correction_marker_to_workings(monkeypatch, tmp_path):
    b = _bare_brain()
    wf = tmp_path / "gate_workings.md"
    b._gate_workings_path = str(wf)
    monkeypatch.setattr(b, "_stream_fast", lambda *a, **k: _flipped_no_gate())

    verdict, _ = b.triage_finding("Blind SQLi in /api/users?id=")
    assert verdict == "SUBMIT"

    body = wf.read_text()
    # Log header records the CORRECTED verdict, not the model's DROP.
    assert "VERDICT=SUBMIT" in body
    # And it explicitly records that a correction was applied (not just the note).
    assert "Q6 correction applied" in body
    assert "Treating Q6 as YES" in body


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
