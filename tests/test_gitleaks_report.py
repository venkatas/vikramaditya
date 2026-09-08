#!/usr/bin/env python3
"""Glue tests for gitleaks_report — fixtures only; no live gitleaks required."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
# Also allow importing finding_schema from a sibling checkout if present
import gitleaks_report as gr  # noqa: E402


SAMPLE_LEAK = {
    "RuleID": "aws-access-token",
    "Description": "AWS Access Key",
    "StartLine": 3,
    "EndLine": 3,
    "Match": "AKIAIOSFODNN7EXAMPLE",
    "Secret": "AKIAIOSFODNN7EXAMPLE",
    "File": "config/creds.example.invalid",
    "Commit": "abc123deadbeef",
    "Tags": ["key", "AWS"],
    "Fingerprint": "config/creds.example.invalid:aws-access-token:3",
}


def test_redact_secret():
    assert "<redacted>" in gr.redact_secret("SUPERSECRETVALUE")
    assert gr.redact_secret("SUPERSECRETVALUE").startswith("SUPE")
    assert gr.redact_secret("ab") == "<redacted>"


def test_severity_for_leak_aws_critical_or_high():
    sev = gr.severity_for_leak(SAMPLE_LEAK)
    assert sev in ("critical", "high")


def test_severity_private_key_critical():
    item = {"RuleID": "generic-api-key", "Description": "x"}
    assert gr.severity_for_leak({"RuleID": "private-key", "Description": "RSA"}) == "critical"
    assert gr.severity_for_leak(item) == "high"


def test_parse_and_finding_redacts_and_schemas():
    findings = gr.parse_gitleaks_json([SAMPLE_LEAK])
    assert len(findings) == 1
    f = findings[0]
    assert f["vtype"] == "exposure"
    assert f["verification_method"] == "data_extracted"
    assert "AKIAIOSFODNN7EXAMPLE" not in f["evidence"]
    assert "<redacted>" in f["evidence"]
    assert f["source"] == "gitleaks"
    # finding_schema gate should allow medium+ with data_extracted
    try:
        from finding_schema import should_report

        assert should_report(f["severity"], f["verification_method"])
    except ImportError:
        pytest.skip("finding_schema not on path")


def test_parse_wrapped_json():
    assert len(gr.parse_gitleaks_json({"findings": [SAMPLE_LEAK]})) == 1
    assert len(gr.parse_gitleaks_json({"results": [SAMPLE_LEAK]})) == 1


def test_findings_to_sarif_shape():
    findings = gr.parse_gitleaks_json([SAMPLE_LEAK])
    doc = gr.findings_to_sarif(findings, tool_version="8.0.0")
    assert doc["version"] == gr.SARIF_VERSION
    assert "$schema" in doc
    assert len(doc["runs"][0]["results"]) == 1
    assert doc["runs"][0]["tool"]["driver"]["name"] == "gitleaks"
    assert doc["runs"][0]["results"][0]["ruleId"] == "aws-access-token"


def test_write_findings_artifacts(tmp_path: Path):
    findings = gr.parse_gitleaks_json([SAMPLE_LEAK])
    summary = gr.write_findings_artifacts(findings, tmp_path)
    assert summary["count"] == 1
    assert (tmp_path / "gitleaks" / "findings.json").is_file()
    assert (tmp_path / "gitleaks" / "gitleaks.sarif.json").is_file()
    assert (tmp_path / "gitleaks" / "summary.json").is_file()
    assert (tmp_path / "exposure" / "gitleaks.txt").is_file()
    text = (tmp_path / "exposure" / "gitleaks.txt").read_text(encoding="utf-8")
    assert "AKIAIOSFODNN7EXAMPLE" not in text


def test_run_gitleaks_mocked(tmp_path: Path):
    src = tmp_path / "repo"
    src.mkdir()
    out = tmp_path / "out"

    def fake_runner(cmd, **kwargs):
        # Write report path contents
        if "--report-path" in cmd:
            path = Path(cmd[cmd.index("--report-path") + 1])
            path.parent.mkdir(parents=True, exist_ok=True)
            fmt = cmd[cmd.index("--report-format") + 1]
            if fmt == "json":
                path.write_text(json.dumps([SAMPLE_LEAK]), encoding="utf-8")
            else:
                path.write_text(
                    json.dumps({"version": "2.1.0", "runs": []}), encoding="utf-8"
                )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    with mock.patch.object(gr, "resolve_gitleaks", return_value="/fake/gitleaks"):
        meta = gr.run_gitleaks(src, out, runner=fake_runner)
    assert len(meta["findings"]) == 1
    assert meta["findings"][0]["rule_id"] == "aws-access-token"


def test_validate_with_gate(tmp_path: Path):
    findings = gr.parse_gitleaks_json([SAMPLE_LEAK])
    buckets = gr.validate_with_gate(findings)
    assert "pass" in buckets
    # Should not all be killed when finding_validator is present
    total = sum(len(v) for v in buckets.values())
    assert total == 1


def test_cli_ingest(tmp_path: Path):
    leaks = tmp_path / "leaks.json"
    leaks.write_text(json.dumps([SAMPLE_LEAK]), encoding="utf-8")
    findings_dir = tmp_path / "findings" / "demo"
    rc = gr.main(["--ingest-json", str(leaks), "--findings-dir", str(findings_dir), "--json"])
    assert rc == 0
    assert (findings_dir / "gitleaks" / "gitleaks.sarif.json").is_file()
