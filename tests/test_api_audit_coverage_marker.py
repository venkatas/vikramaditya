"""OpenAPI audit must not silently drop coverage when --max-hosts / --max-ops cap.

GAP (audit 2026-06-20): collect_candidate_hosts()[:max_hosts] and the
audit_public_operations() `if tested >= max_ops: break` both silently
truncated coverage with no degradation marker. An operator on an engagement
with >max_hosts candidate hosts (or >max_ops public ops) got no signal that
hosts/ops 21+/61+ were never probed. Fix: emit an explicit "X of Y (CAPPED)"
coverage marker in summary.md + coverage.json + COVERAGE_CAPPED.marker, and
warn on stderr (mirrors the --max-urls / _mark_degraded convention).

All data here is SYNTHETIC.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import api_audit  # noqa: E402


def test_collect_candidate_hosts_reports_pre_cap_total(tmp_path):
    prio = tmp_path / "priority"
    prio.mkdir()
    live = tmp_path / "live"
    live.mkdir()
    (live / "urls.txt").write_text(
        "\n".join(f"https://host{i}.example.invalid" for i in range(10)) + "\n"
    )
    hosts, total = api_audit.collect_candidate_hosts(tmp_path, max_hosts=3)
    assert len(hosts) == 3
    assert total == 10  # pre-cap de-duplicated count is preserved


def test_count_probeable_public_ops_mirrors_audit_skip_logic():
    ops = [
        {"method": "GET", "requires_auth": False},   # probeable
        {"method": "HEAD", "requires_auth": False},  # probeable
        {"method": "POST", "requires_auth": False},  # not a safe method
        {"method": "GET", "requires_auth": True},    # requires auth
    ]
    assert api_audit.count_probeable_public_ops(ops) == 2


def test_audit_public_operations_returns_tested_count(monkeypatch):
    ops = [
        {"method": "GET", "requires_auth": False, "sample_url": f"https://x.invalid/{i}",
         "sensitive": False, "summary": "", "title": ""}
        for i in range(5)
    ]
    monkeypatch.setattr(
        api_audit, "fetch",
        lambda url, timeout=6: {"status": 404, "content_type": "", "body": "", "final_url": url},
    )
    findings, tested = api_audit.audit_public_operations(ops, max_ops=2)
    assert tested == 2, "max_ops must cap the probe loop and be reported back"


def test_write_outputs_emits_capped_markers(tmp_path):
    out = tmp_path / "api_specs"
    operations = [
        {"method": "GET", "requires_auth": False, "sample_url": "https://x.invalid/a",
         "sensitive": False, "source_url": "https://x.invalid/spec"},
    ]
    coverage = {
        "probed_hosts": 20,
        "total_hosts": 47,
        "max_hosts": 20,
        "tested_ops": 60,
        "total_probeable_ops": 400,
        "max_ops": 60,
        "discover_only": False,
    }
    api_audit.write_outputs(out, [], operations, [], raw_specs=[], coverage=coverage)

    summary = (out / "summary.md").read_text()
    assert "## Coverage" in summary
    assert "20 of 47 probed (CAPPED by --max-hosts=20, 27 untested)" in summary
    assert "60 of 400 (CAPPED by --max-ops=60, 340 untested)" in summary

    cov = json.loads((out / "coverage.json").read_text())
    assert cov["degraded"] is True
    assert cov["total_hosts"] == 47 and cov["probed_hosts"] == 20
    assert cov["total_probeable_public_operations"] == 400

    marker = out / "COVERAGE_CAPPED.marker"
    assert marker.is_file(), "a degradation marker file must exist when capped"


def test_write_outputs_no_marker_when_full(tmp_path):
    out = tmp_path / "api_specs"
    coverage = {
        "probed_hosts": 5,
        "total_hosts": 5,
        "max_hosts": 20,
        "tested_ops": 3,
        "total_probeable_ops": 3,
        "max_ops": 60,
        "discover_only": False,
    }
    api_audit.write_outputs(out, [], [], [], raw_specs=[], coverage=coverage)
    summary = (out / "summary.md").read_text()
    assert "CAPPED" not in summary
    assert not (out / "COVERAGE_CAPPED.marker").is_file()
    cov = json.loads((out / "coverage.json").read_text())
    assert cov["degraded"] is False


def test_discover_only_suppresses_op_cap_marker(tmp_path):
    """In --discover-only mode no ops are probed, so the op cap must not warn."""
    out = tmp_path / "api_specs"
    coverage = {
        "probed_hosts": 5,
        "total_hosts": 5,
        "max_hosts": 20,
        "tested_ops": 0,
        "total_probeable_ops": 400,
        "max_ops": 60,
        "discover_only": True,
    }
    api_audit.write_outputs(out, [], [], [], raw_specs=[], coverage=coverage)
    summary = (out / "summary.md").read_text()
    assert "Public operations probed" not in summary
    cov = json.loads((out / "coverage.json").read_text())
    assert cov["degraded"] is False
