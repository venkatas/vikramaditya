"""Coverage failures must survive invalid evidence and unsuccessful HTTP probes."""
from __future__ import annotations

import builtins
import json
import ssl
import sys
from pathlib import Path

import pytest

import api_audit as api
import phase_manifest as pm


@pytest.fixture
def session(tmp_path, monkeypatch):
    for key in ("SCOPE_LOCK", "SCOPE_ALLOW_FILE"):
        monkeypatch.delenv(key, raising=False)
    recon, findings = [tmp_path / tree / "example.invalid" / "sessions" / "one"
                       for tree in ("recon", "findings")]
    for path in (recon, findings):
        path.mkdir(parents=True)
    return recon, findings


@pytest.mark.parametrize("bad", [
    '{"interrupted":', 'null', '[]', '{}', '{"phases":[null]}',
    '{"phases":[{"status":"unrecognized"}]}',
    '{"phases":[{"status":[]}]}', '{"phases":[],"success":[]}',
])
def test_bad_manifest_alone_fails_closed_read_only(session, bad):
    _, findings = session
    path = findings / "phase_manifest.json"
    path.write_text(bad)
    before = path.read_bytes()
    assert pm.assessment_status(str(findings)) == "inconclusive"
    assert pm.read_manifest(str(findings))["success"] is False
    rows = pm.collect_coverage(str(findings))
    assert len(rows) == 1 and rows[0]["status"] == "failed"
    assert path.read_bytes() == before
    assert list(findings.iterdir()) == [path]


@pytest.mark.parametrize("relative", [
    "coverage.json", "coverage_degraded.json", "api_specs/coverage.json",
    "api_specs/api_coverage.json",
])
@pytest.mark.parametrize("bad", ['{"interrupted":', 'null', '"wrong"', '[7]',
                                '[{"reason":"broken metadata","status":{}}]'])
def test_bad_coverage_documents_fail_closed_and_merge_idempotently(session, relative, bad):
    recon, findings = session
    root = recon if relative.startswith("api_specs/") else findings
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(bad)
    assert pm.assessment_status(str(findings)) == "inconclusive"
    first = pm.merge_coverage(str(findings))
    second = pm.merge_coverage(str(findings))
    assert first == second and len(first) == 1
    assert first[0]["source"] == "coverage_integrity"
    assert first[0]["status"] == "failed"


@pytest.mark.parametrize("payload", [
    {"probed_hosts": -1, "total_hosts": 1},
    {"probed_hosts": True, "total_hosts": 1},
    {"probed_hosts": "1", "total_hosts": 1},
    {"degraded": "false"}, {"degraded": [7]}, {"degraded": [{"unknown": "reason"}]},
    {"probed_hosts": 2, "attempted_hosts": 1, "total_hosts": 1},
    {"unknown": "schema"},
])
def test_invalid_rich_api_shapes_are_not_successful_coverage(session, payload):
    recon, findings = session
    (recon / "api_specs").mkdir()
    (recon / "api_specs/api_coverage.json").write_text(json.dumps(payload))
    assert pm.assessment_status(str(findings)) == "inconclusive"


def test_missing_optional_and_completed_zero_results_remain_clean(session):
    recon, findings = session
    assert pm.assessment_status(str(findings)) == "complete"
    pm.record_phase(str(findings), "RECON", exit_code=0, artifact_counts={"urls": 0})
    pm.write_coverage(str(findings), [])
    (recon / "api_specs").mkdir()
    (recon / "api_specs/coverage.json").write_text("[]")
    (recon / "api_specs/api_coverage.json").write_text(json.dumps({
        "probed_hosts": 0, "total_hosts": 0, "tested_public_operations": 0,
        "total_probeable_public_operations": 0, "degraded": False,
    }))
    assert pm.collect_coverage(str(findings)) == []
    assert pm.assessment_status(str(findings)) == "complete"


def test_unreadable_existing_coverage_is_not_optional_absence(session, monkeypatch):
    _, findings = session
    path = findings / "coverage.json"
    path.write_text("[]")
    real_open = builtins.open

    def unavailable(filename, *args, **kwargs):
        if str(filename) == str(path):
            raise PermissionError("fixture denied")
        return real_open(filename, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", unavailable)
    rows = pm.collect_coverage(str(findings))
    assert len(rows) == 1 and rows[0]["status"] == "failed"
    assert pm.assessment_status(str(findings)) == "inconclusive"


def test_manifest_repair_preserves_bad_bytes_and_durable_failure(session):
    _, findings = session
    path = findings / "phase_manifest.json"
    bad = b'{"phases": ['
    path.write_bytes(bad)
    assert pm.record_phase(str(findings), "REPORTS", exit_code=0) == str(path)
    assert [p.read_bytes() for p in findings.glob("phase_manifest.json.corrupt.*")] == [bad]
    doc = pm.read_manifest(str(findings))
    assert doc["success"] is False
    assert doc["phases"][-1]["phase"] == "REPORTS"
    assert pm.record_phase(str(findings), "REPORTS", exit_code=0) == str(path)
    assert len(list(findings.glob("phase_manifest.json.corrupt.*"))) == 1
    assert pm.assessment_status(str(findings)) == "inconclusive"


def test_coverage_repair_preserves_bad_bytes_and_existing_gap(session):
    _, findings = session
    path = findings / "coverage.json"
    bad = b'{"degraded": '
    path.write_bytes(bad)
    rows = [{"tool": "arjun", "reason": "fixture timeout"}]
    assert pm.write_coverage(str(findings), rows) == str(path)
    assert rows == [{"tool": "arjun", "reason": "fixture timeout"}], "do not mutate the caller"
    assert [p.read_bytes() for p in findings.glob("coverage.json.corrupt.*")] == [bad]
    saved = json.loads(path.read_text())
    assert saved[0] == rows[0] and saved[1]["status"] == "failed"
    pm.write_coverage(str(findings), [])
    assert pm.assessment_status(str(findings)) == "inconclusive"


def test_manifest_failure_facts_override_stale_success_metadata(session):
    _, findings = session
    (findings / "phase_manifest.json").write_text(json.dumps({
        "phases": [{"phase": "RECON", "status": "ran", "exit_code": 7}],
        "success": True, "overall_status": "success",
    }))
    assert pm.assessment_status(str(findings)) == "inconclusive"


def test_broken_optional_artifact_symlink_is_not_absence(session):
    _, findings = session
    (findings / "coverage.json").symlink_to(findings / "missing-evidence.json")
    assert pm.assessment_status(str(findings)) == "inconclusive"


def test_atomic_manifest_publish_failure_keeps_previous_file(session, monkeypatch):
    import storage

    _, findings = session
    pm.record_phase(str(findings), "RECON", exit_code=1)
    path = findings / "phase_manifest.json"
    before = path.read_bytes()

    def interrupted(*args, **kwargs):
        raise OSError("fixture atomic rename failed")

    monkeypatch.setattr(storage.os, "replace", interrupted)
    assert pm.record_phase(str(findings), "REPORTS", exit_code=0) is None
    assert path.read_bytes() == before
    assert not list(findings.glob("*.tmp.*"))
    assert pm.assessment_status(str(findings)) == "inconclusive"


def test_actual_merge_publish_failure_is_not_silently_successful(session, monkeypatch):
    _, findings = session

    def unavailable(*args, **kwargs):
        raise OSError("fixture coverage publish failed")

    monkeypatch.setattr(pm, "atomic_write_json", unavailable)
    with pytest.raises(OSError, match="publish failed"):
        pm.merge_coverage(str(findings))


def _dead(url, **kwargs):
    return {"status": 0, "body": "", "content_type": "", "final_url": url,
            "error": "TimeoutError: fixture connect timed out"}


def _operation(index):
    return {"method": "GET", "requires_auth": False,
            "sample_url": f"https://example.invalid/users/{index}", "sensitive": True,
            "source_url": "https://example.invalid/openapi.json"}


def test_all_discovery_requests_failing_are_partial_not_fully_probed(session, monkeypatch):
    recon, findings = session
    (recon / "live").mkdir()
    (recon / "live/urls.txt").write_text("https://example.invalid\n")
    calls = []

    def dead(url, **kwargs):
        calls.append(url)
        return _dead(url)

    monkeypatch.setattr(api, "fetch", dead)
    monkeypatch.setattr(sys, "argv", ["api_audit.py", "--recon-dir", str(recon)])
    assert api.main() == 0
    out = recon / "api_specs"
    coverage = json.loads((out / "api_coverage.json").read_text())
    assert len(calls) == 3, "keep the existing fast-fail request budget"
    assert coverage["attempted_hosts"] == 1 and coverage["probed_hosts"] == 0
    assert coverage["degraded"] and coverage["transport_errors"] == 3
    assert len(json.loads((out / "request_errors.json").read_text())) == 3
    assert not (out / "COVERAGE_CAPPED.marker").exists(), "transport errors are not a host cap"
    assert json.loads((out / "unauth_findings.json").read_text()) == []
    assert pm.assessment_status(str(findings)) == "inconclusive"
    rows = pm.collect_coverage(str(findings))
    assert len(rows) == 1 and "transport failed 3" in rows[0]["reason"]


def test_failed_operations_count_attempts_for_budget_but_not_completed_probes(session, monkeypatch):
    recon, findings = session
    errors, stats, calls = [], {}, []

    def dead(url, **kwargs):
        calls.append(url)
        return _dead(url)

    monkeypatch.setattr(api, "fetch", dead)
    operations = [_operation(i) for i in range(3)]
    hits, tested = api.audit_public_operations(
        operations, max_ops=2, request_errors=errors, probe_stats=stats)
    assert len(calls) == stats["attempted_ops"] == 2
    assert hits == [] and tested == 0 and len(errors) == 2
    api.write_outputs(recon / "api_specs", [], operations, hits, coverage={
        "probed_hosts": 1, "total_hosts": 1, "max_hosts": 20,
        "tested_ops": tested, "attempted_ops": stats["attempted_ops"],
        "total_probeable_ops": 3, "max_ops": 2, "request_errors": errors,
    })
    first = pm.collect_coverage(str(findings))
    assert len(first) == 1 and "transport failed 2" in first[0]["reason"]
    assert "surface capped" in first[0]["reason"]
    (recon / "api_specs/coverage.json").unlink()
    assert pm.collect_coverage(str(findings)) == first, "rich summary is also authoritative"


def test_transport_failures_without_a_real_cap_do_not_claim_capped(session, monkeypatch):
    recon, findings = session
    errors, stats = [], {}
    monkeypatch.setattr(api, "fetch", _dead)
    operations = [_operation(0), _operation(1)]
    hits, tested = api.audit_public_operations(
        operations, max_ops=20, request_errors=errors, probe_stats=stats)
    api.write_outputs(recon / "api_specs", [], operations, hits, coverage={
        "probed_hosts": 1, "total_hosts": 1, "max_hosts": 20,
        "tested_ops": tested, "attempted_ops": stats["attempted_ops"],
        "total_probeable_ops": 2, "max_ops": 20, "request_errors": errors,
    })
    assert not (recon / "api_specs/COVERAGE_CAPPED.marker").exists()
    rows = pm.collect_coverage(str(findings))
    assert len(rows) == 1 and "capped" not in rows[0]["reason"]


@pytest.mark.parametrize("error", [TimeoutError("fixture timeout"), ssl.SSLError("fixture TLS failure")])
def test_fetch_transport_details_reach_coverage_without_findings(monkeypatch, error):
    def unavailable(*args, **kwargs):
        raise error

    monkeypatch.setattr(api, "urlopen", unavailable)
    errors = []
    response = api._fetch_for_scope("https://example.invalid/swagger.json", None, [],
                                    "spec discovery", errors)
    assert response["status"] == 0 and len(errors) == 1
    assert type(error).__name__ in errors[0]["reason"]


def test_rich_coverage_repair_keeps_bad_original_and_integrity_gap(session):
    recon, findings = session
    out = recon / "api_specs"
    out.mkdir()
    bad = b'{"degraded":'
    (out / "api_coverage.json").write_bytes(bad)
    api.write_outputs(out, [], [], [], coverage={
        "probed_hosts": 0, "total_hosts": 0, "tested_ops": 0,
        "total_probeable_ops": 0, "max_hosts": 20, "max_ops": 60,
    })
    assert [p.read_bytes() for p in out.glob("api_coverage.json.corrupt.*")] == [bad]
    assert pm.assessment_status(str(findings)) == "inconclusive"
    assert len(pm.collect_coverage(str(findings))) == 1


@pytest.mark.parametrize("kind", ["hosts", "legacy-ops", "rich-ops", "mixed-ops"])
def test_count_shortfalls_are_degraded_without_request_error_details(session, kind):
    recon, findings = session
    coverage = {"probed_hosts": 1, "attempted_hosts": 1, "total_hosts": 1,
                "tested_ops": 1, "attempted_ops": 1, "total_probeable_ops": 1,
                "max_hosts": 20, "max_ops": 20}
    if kind == "hosts":
        coverage["probed_hosts"] = 0
    elif kind == "legacy-ops":
        coverage["tested_ops"] = 0
    elif kind == "rich-ops":
        for old, new in (("tested_ops", "tested_public_operations"),
                         ("attempted_ops", "attempted_public_operations"),
                         ("total_probeable_ops", "total_probeable_public_operations")):
            coverage[new] = coverage.pop(old)
        coverage["tested_public_operations"] = 0
    else:
        coverage["attempted_public_operations"] = coverage.pop("attempted_ops")
        coverage["tested_ops"] = 0
    out = recon / "api_specs"
    api.write_outputs(out, [], [], [], coverage=coverage)
    rich = json.loads((out / "api_coverage.json").read_text())
    assert rich["degraded"] and rich["transport_errors"] == 0
    assert not (out / "COVERAGE_CAPPED.marker").exists()
    first = pm.collect_coverage(str(findings))
    assert len(first) == 1 and "completion shortfall" in first[0]["reason"]
    assert pm.assessment_status(str(findings)) == "inconclusive"
    (out / "coverage.json").unlink()
    assert pm.collect_coverage(str(findings)) == first
    assert pm.merge_coverage(str(findings)) == pm.merge_coverage(str(findings)) == first


@pytest.mark.parametrize("entry_point", ["canonical", "nested"])
def test_collector_detects_falsely_clean_count_only_api_summary(session, entry_point):
    recon, findings = session
    path = findings / "coverage.json"
    if entry_point == "nested":
        path = recon / "api_specs/api_coverage.json"
        path.parent.mkdir()
    path.write_text(json.dumps({"probed_hosts": 0, "attempted_hosts": 1,
                                "total_hosts": 1, "tested_ops": 0,
                                "attempted_ops": 1, "total_probeable_ops": 1,
                                "transport_errors": 0, "degraded": False}))
    assert pm.assessment_status(str(findings)) == "inconclusive"
    assert "completion shortfall" in pm.collect_coverage(str(findings))[0]["reason"]


def test_discover_only_suppresses_operation_completion_shortfalls(session):
    recon, findings = session
    out = recon / "api_specs"
    api.write_outputs(out, [], [], [], coverage={
        "probed_hosts": 1, "attempted_hosts": 1, "total_hosts": 1,
        "tested_ops": 0, "attempted_ops": 1, "total_probeable_ops": 1,
        "discover_only": True,
    })
    assert not json.loads((out / "api_coverage.json").read_text())["degraded"]
    assert pm.assessment_status(str(findings)) == "complete"
