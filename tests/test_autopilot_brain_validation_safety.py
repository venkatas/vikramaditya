"""Regression tests for brain-validation safety + coverage-gap markers in autopilot.

Covers four fixes (group autopilot_api_hunt.py):

1. Grounding floor: the LLM FP-review may NEVER physically remove a tool-confirmed
   (grounded) finding (sqlmap/dalfox/trufflehog/*_verified). A hallucinated
   {"action":"remove"} on a confirmed CRITICAL must be refused.
2. Exact type match: the apply loop matches f["type"] == finding_type exactly, so a
   coarse "sqli" can no longer collide with sqli_time_based / sqli_sqlmap_confirmed
   and mutate/drop the wrong finding.
3. Removed findings are preserved to removed_findings.json before the per-finding
   JSON is unlinked (never silently lost from disk).
4. _record_coverage_gap writes a {"tool","reason"} marker into the session
   coverage.json that reporter.py's coverage-limitations chapter consumes.

All data here is SYNTHETIC.
"""
import json
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import autopilot_api_hunt as ah  # noqa: E402


def _install_fake_ollama(monkeypatch, fixes):
    """Inject a fake `ollama` module whose chat() returns the given fixes JSON."""
    fake = types.ModuleType("ollama")
    fake.show = lambda name: {"name": name}

    def _chat(model, messages, options=None):
        return {"message": {"content": json.dumps({"fixes": fixes}), "thinking": ""}}

    fake.chat = _chat
    monkeypatch.setitem(sys.modules, "ollama", fake)


def test_grounding_floor_refuses_remove_of_confirmed_finding(monkeypatch, tmp_path):
    # An LLM tries to delete a sqlmap-confirmed CRITICAL via the coarse "sqli" type.
    _install_fake_ollama(monkeypatch, [
        {"finding_type": "sqli_sqlmap_confirmed", "action": "remove",
         "reason": "model thinks it is a false positive"},
    ])
    findings = [
        {"type": "sqli_sqlmap_confirmed", "severity": "critical",
         "detail": "sqlmap confirmed", "url": "http://127.0.0.1/x",
         "evidence": "sqlmap --level=3 confirmed injection"},
    ]
    out = ah._brain_validate_findings(findings, str(tmp_path))
    # The grounded finding survives — never removed.
    assert len(out) == 1
    assert out[0]["type"] == "sqli_sqlmap_confirmed"
    assert not out[0].get("_removed")
    # And the refusal is recorded on the finding for audit.
    assert any("refused" in n.lower() for n in out[0].get("_brain_notes", []))


def test_exact_match_does_not_collide_across_sqli_variants(monkeypatch, tmp_path):
    # Coarse "sqli" must NOT match sqli_time_based (an UNgrounded finding) — exact
    # equality means the coarse token matches nothing and nothing is dropped.
    _install_fake_ollama(monkeypatch, [
        {"finding_type": "sqli", "action": "remove", "reason": "coarse"},
    ])
    findings = [
        {"type": "sqli_time_based", "severity": "high", "detail": "time-based",
         "url": "http://127.0.0.1/a"},
        {"type": "sqli_error_based", "severity": "high", "detail": "error-based",
         "url": "http://127.0.0.1/b"},
    ]
    out = ah._brain_validate_findings(findings, str(tmp_path))
    # Neither distinct finding is dropped by the coarse "sqli".
    assert {f["type"] for f in out} == {"sqli_time_based", "sqli_error_based"}


def test_ungrounded_finding_can_still_be_removed_by_exact_type(monkeypatch, tmp_path):
    # The floor only protects GROUNDED findings; a plain unverified finding with an
    # exact-type remove is still honored (FP review remains useful).
    _install_fake_ollama(monkeypatch, [
        {"finding_type": "server_version_disclosure", "action": "remove",
         "reason": "info only"},
    ])
    findings = [
        {"type": "server_version_disclosure", "severity": "low",
         "detail": "Server: x/1.0", "url": "http://127.0.0.1/"},
    ]
    out = ah._brain_validate_findings(findings, str(tmp_path))
    assert out == []


def test_rewrite_saver_artifacts_preserves_removed_findings(tmp_path):
    from auth_utils import FindingSaver

    saver = FindingSaver(str(tmp_path), "autopilot")
    kept = {"type": "idor", "severity": "high", "detail": "kept", "url": "http://127.0.0.1/a"}
    dropped = {"type": "x_unverified", "severity": "low", "detail": "drop",
               "url": "http://127.0.0.1/b", "_removed": True}
    saver.save(kept)
    saver.save(dropped)

    ah._rewrite_saver_artifacts(saver, [kept])

    # The removed finding was snapshotted to a sidecar before its JSON was unlinked.
    sidecar = os.path.join(saver.dir, "removed_findings.json")
    assert os.path.isfile(sidecar)
    with open(sidecar) as fh:
        preserved = json.load(fh)
    assert any(f["type"] == "x_unverified" for f in preserved)
    # In-memory list now reflects only the kept finding.
    assert [f["type"] for f in saver._findings] == ["idor"]


def test_record_coverage_gap_writes_and_dedupes(tmp_path):
    from auth_utils import FindingSaver

    saver = FindingSaver(str(tmp_path), "autopilot")
    ah._record_coverage_gap(saver, tool="api-phase:idor",
                            reason="IDOR target surface capped at 15: 3 untested.")
    # Idempotent — a repeat marker does not duplicate.
    ah._record_coverage_gap(saver, tool="api-phase:idor",
                            reason="IDOR target surface capped at 15: 3 untested.")

    # coverage.json must land where reporter.py READS it: the recon->findings
    # swap of the saver's category dir (here a no-op tmp_path with no recon/
    # segment, so == saver.dir). The prior os.path.dirname(saver.dir) was the
    # mislocated path the verifier flagged — one level too shallow, so the
    # report never surfaced the gap.
    cov_path = os.path.join(ah._coverage_dir_from(saver), "coverage.json")
    assert os.path.isfile(cov_path)
    with open(cov_path) as fh:
        data = json.load(fh)
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["tool"] == "api-phase:idor"
    assert "capped" in data[0]["reason"]
