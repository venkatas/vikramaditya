"""P1 — reliable coverage-failure reporting + phase manifest.

A phase that failed (missing tool / non-zero exit / signal / timeout) must mark the run
inconclusive (success=False), and the three historically-separate coverage artifacts must
consolidate into one canonical coverage.json the reporter can render identically in HTML+MD.
"""
import json
import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import phase_manifest as pm  # noqa: E402


# ── derive_status: signals → status (fail-closed) ────────────────────────────
@pytest.mark.parametrize("kw,expected", [
    (dict(exit_code=0), pm.PHASE_OK),
    (dict(exit_code=0, degraded=True), pm.PHASE_DEGRADED),
    (dict(exit_code=1), pm.PHASE_FAILED),
    (dict(exit_code=2, degraded=True), pm.PHASE_FAILED),      # non-zero dominates degraded
    (dict(timed_out=True), pm.PHASE_ABORTED),
    (dict(signal=15), pm.PHASE_ABORTED),
    (dict(exit_code=1, timed_out=True), pm.PHASE_ABORTED),    # abort dominates fail
])
def test_derive_status(kw, expected):
    assert pm.derive_status(**kw) == expected


# ── healthy zero-result is success; a failed phase is not ─────────────────────
def test_zero_result_ran_is_success(tmp_path):
    pm.record_phase(str(tmp_path), "scan", exit_code=0, artifact_counts={"findings": 0})
    doc = pm.read_manifest(str(tmp_path))
    assert doc["success"] is True and doc["overall_status"] == "success"


def test_failed_phase_forces_inconclusive(tmp_path):
    pm.record_phase(str(tmp_path), "recon", exit_code=0)
    pm.record_phase(str(tmp_path), "scan", exit_code=1)       # a tool crash
    doc = pm.read_manifest(str(tmp_path))
    assert doc["success"] is False and doc["overall_status"] == "inconclusive"
    assert pm.is_inconclusive(str(tmp_path)) is True


def test_aborted_phase_forces_inconclusive(tmp_path):
    pm.record_phase(str(tmp_path), "sqlmap", timed_out=True)
    assert pm.is_inconclusive(str(tmp_path)) is True


def test_degraded_phase_forces_inconclusive(tmp_path):
    pm.record_phase(str(tmp_path), "cors", exit_code=0, degraded=True)
    assert pm.is_inconclusive(str(tmp_path)) is True


# ── manifest persists exit_code / signal / timeout / artifacts ───────────────
def test_manifest_persists_full_record(tmp_path):
    pm.record_phase(str(tmp_path), "recon", command="bash recon.sh x", tool="httpx",
                    tool_version="1.6.0", exit_code=124, timed_out=True,
                    artifact_counts={"live_hosts": 0})
    rec = pm.read_manifest(str(tmp_path))["phases"][0]
    assert rec["exit_code"] == 124 and rec["timed_out"] is True
    assert rec["tool"] == "httpx" and rec["artifact_counts"] == {"live_hosts": 0}
    assert rec["status"] == pm.PHASE_ABORTED
    # on disk, not just in-memory
    assert os.path.isfile(os.path.join(str(tmp_path), "phase_manifest.json"))


# ── three coverage artifacts merge into canonical coverage.json ──────────────
def test_merge_three_sources(tmp_path):
    d = str(tmp_path)
    # 1) hunt.py list
    with open(os.path.join(d, "coverage.json"), "w") as fh:
        json.dump([{"tool": "git-hound", "reason": "no config.yml"}], fh)
    # 2) scanner.sh gaps
    os.makedirs(os.path.join(d, "manual_review"))
    with open(os.path.join(d, "manual_review", "coverage_gaps.txt"), "w") as fh:
        fh.write("[COVERAGE-GAP] sqli: focused profile skipped time-based\n")
    # 3) vikramaditya degraded
    with open(os.path.join(d, "coverage_degraded.json"), "w") as fh:
        json.dump([{"tool": "sqlmap", "reason": "fell back after crash", "phase": "scan"}], fh)

    merged = pm.merge_coverage(d)
    sources = {m["source"] for m in merged}
    assert sources == {"hunt", "scanner.sh", "vikramaditya"}
    assert all({"source", "tool_or_phase", "reason", "status"} <= set(m) for m in merged)
    # written back canonically as a list
    on_disk = json.load(open(os.path.join(d, "coverage.json")))
    assert isinstance(on_disk, list) and len(on_disk) == 3


def test_merge_accepts_api_audit_dict(tmp_path):
    d = str(tmp_path)
    with open(os.path.join(d, "coverage.json"), "w") as fh:
        json.dump({"probed_hosts": 2, "total_hosts": 10,
                   "degraded": [{"tool": "kiterunner", "reason": "no wordlist"}]}, fh)
    merged = pm.merge_coverage(d)
    reasons = " ".join(m["reason"] for m in merged)
    assert "no wordlist" in reasons and "2 of 10" in reasons  # dict no longer silently dropped


def test_merge_is_idempotent(tmp_path):
    d = str(tmp_path)
    with open(os.path.join(d, "coverage.json"), "w") as fh:
        json.dump([{"tool": "x", "reason": "y"}], fh)
    first = pm.merge_coverage(d)
    second = pm.merge_coverage(d)     # re-merging the already-merged file must not duplicate
    assert first == second and len(second) == 1


def test_merge_empty_dir_is_empty(tmp_path):
    assert pm.merge_coverage(str(tmp_path)) == []


# ── reporter: HTML and MD show IDENTICAL degradation info + INCONCLUSIVE banner ──
def _findings_report_dir(tmp_path):
    d = tmp_path / "findings" / "acme" / "sessions" / "20260101_x"
    d.mkdir(parents=True)
    return str(d)


def test_reporter_html_and_md_agree(tmp_path):
    import reporter
    rd = _findings_report_dir(tmp_path)
    with open(os.path.join(rd, "coverage.json"), "w") as fh:
        json.dump([{"tool": "sqlmap", "reason": "crashed on batch 2"}], fh)
    pm.record_phase(rd, "scan", exit_code=1)          # → inconclusive
    html = reporter._render_coverage_limitations_html(rd)
    md = reporter._render_coverage_limitations_md(rd)
    for blob in (html, md):
        assert "sqlmap" in blob and "crashed on batch 2" in blob, "coverage row missing"
        assert "INCONCLUSIVE" in blob, "inconclusive banner missing"


def test_reporter_md_no_longer_silent_on_gaps(tmp_path):
    import reporter
    rd = _findings_report_dir(tmp_path)
    os.makedirs(os.path.join(rd, "manual_review"))
    with open(os.path.join(rd, "manual_review", "coverage_gaps.txt"), "w") as fh:
        fh.write("[COVERAGE-GAP] xss: dalfox skipped (focused profile)\n")
    md = reporter._render_coverage_limitations_md(rd)
    assert "xss" in md and "dalfox skipped" in md, "MD report still hides scanner.sh gaps"


def test_reporter_clean_run_renders_nothing(tmp_path):
    import reporter
    rd = _findings_report_dir(tmp_path)
    with open(os.path.join(rd, "coverage.json"), "w") as fh:
        json.dump([], fh)
    pm.record_phase(rd, "scan", exit_code=0)          # clean
    assert reporter._render_coverage_limitations_html(rd) == ""
    assert reporter._render_coverage_limitations_md(rd) == ""


# ── hunt.py: derive_phase_status FAILED + inconclusive exit code ─────────────
def test_derive_phase_status_failed():
    import hunt
    assert hunt.derive_phase_status(True, False, failed=True) == hunt.PHASE_STATUS_FAILED
    assert hunt.PHASE_STATUS_FAILED in hunt._PHASE_STATUS_GLYPH


def test_exit_for_assessment_exits_2_on_inconclusive():
    import hunt
    with pytest.raises(SystemExit) as ei:
        hunt._exit_for_assessment([{"assessment_status": "inconclusive"}])
    assert ei.value.code == 2
    with pytest.raises(SystemExit) as ei2:
        hunt._exit_for_assessment([{"success": False}])
    assert ei2.value.code == 2


def test_exit_for_assessment_clean_is_noop():
    import hunt
    hunt._exit_for_assessment([{"success": True, "assessment_status": "complete"}])  # must not raise


def test_run_live_marks_nonzero_exit_degraded_source():
    # source-assertion: run_live now marks a plain non-zero exit degraded (was timeout-only)
    h = (Path(__file__).resolve().parent.parent / "hunt.py").read_text()
    assert 'if rc != 0 and not timed_out:' in h
    assert '_record_phase_manifest(' in h


# ── api_audit no longer overwrites the canonical list with a dict ────────────
def test_api_audit_appends_to_canonical_list():
    a = (Path(__file__).resolve().parent.parent / "api_audit.py").read_text()
    assert '"api_coverage.json"' in a, "rich api dict not moved to its own file"
    assert 'isinstance(_existing, list)' in a and '_existing.append' in a, \
        "api_audit does not append to the canonical coverage.json list"
