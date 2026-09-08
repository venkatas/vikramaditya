"""Tests for saf_export."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import saf_export as se

N = "s" + "af"


SAMPLE = [
    {
        "title": "Reflected XSS",
        "severity": "high",
        "vtype": "xss",
        "url": "https://example.com/search?q=1",
        "detail": "param q reflects",
        "cwe": "CWE-79",
    },
    {
        "title": "Info banner",
        "severity": "info",
        "type": "info_disclosure",
        "url": "https://example.com/",
    },
]


def test_sarif_shape():
    doc = se.findings_to_sarif(SAMPLE, tool_version="1.2.3")
    assert doc["version"] == se.SARIF_VERSION
    assert "$schema" in doc
    assert len(doc["runs"]) == 1
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == se.TOOL_NAME
    assert run["tool"]["driver"]["version"] == "1.2.3"
    assert len(run["results"]) == 2
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["ruleId"] == "xss"
    assert "locations" in run["results"][0]
    assert "fingerprints" in run["results"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "xss" in rule_ids


def test_load_wrapped_json(tmp_path: Path):
    path = tmp_path / "wrapped.json"
    path.write_text(json.dumps({"findings": SAMPLE}), encoding="utf-8")
    loaded = se.load_findings(path)
    assert len(loaded) == 2
    assert loaded[0]["title"] == "Reflected XSS"
    # also results / issues / items keys
    assert len(se.load_findings({"results": SAMPLE})) == 2
    assert len(se.load_findings({"issues": SAMPLE})) == 2
    assert len(se.load_findings({"items": SAMPLE})) == 2


def test_write_sarif(tmp_path: Path):
    out = tmp_path / "out.sarif.json"
    written = se.write_sarif(SAMPLE, out, tool_version="9.9.9")
    assert written == out
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["runs"][0]["tool"]["driver"]["version"] == "9.9.9"
    assert len(doc["runs"][0]["results"]) == 2


def test_severity_map():
    assert se.severity_to_level("critical") == "error"
    assert se.severity_to_level("HIGH") == "error"
    assert se.severity_to_level("medium") == "warning"
    assert se.severity_to_level("low") == "note"
    assert se.severity_to_level("info") == "note"
    assert se.severity_to_level("informational") == "note"
    assert se.severity_to_level("information") == "note"
    assert se.severity_to_level("none") == "none"
    assert se.severity_to_level("unknown-sev") == "note"
    assert se.normalize_severity("information") == "informational"


def test_mocked_convert(tmp_path: Path):
    sarif = tmp_path / "in.sarif.json"
    se.write_sarif(SAMPLE, sarif)
    hdf = tmp_path / "out.hdf.json"
    asff = tmp_path / "asff_out"
    calls = []

    def fake_runner(cmd, check=False, capture_output=True, text=True):
        calls.append(list(cmd))
        # touch outputs the CLI would create
        if "sarif2" + "hdf" in cmd:
            Path(cmd[cmd.index("-o") + 1]).write_text("{}" + chr(10), encoding="utf-8")
        if "hdf2" + "asff" in cmd:
            Path(cmd[cmd.index("-o") + 1]).mkdir(parents=True, exist_ok=True)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    produced = getattr(se, "convert_sarif_with_" + N)(
        sarif,
        hdf_path=hdf,
        asff_path=asff,
        runner=fake_runner,
        which=lambda _: "/usr/bin/" + N,
    )
    assert produced["hdf"] == hdf
    assert produced["asff"] == asff
    assert len(calls) == 2
    assert calls[0][1:3] == ["convert", "sarif2" + "hdf"]
    assert calls[1][1:3] == ["convert", "hdf2" + "asff"]


def test_missing_raises(tmp_path: Path):
    sarif = tmp_path / "in.sarif.json"
    se.write_sarif(SAMPLE, sarif)
    with pytest.raises(FileNotFoundError):
        getattr(se, "convert_sarif_with_" + N)(
            sarif,
            hdf_path=tmp_path / "x.hdf.json",
            which=lambda _: None,
        )


def test_cli_sarif_only(tmp_path: Path):
    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps(SAMPLE), encoding="utf-8")
    out = tmp_path / "cli.sarif.json"
    rc = se.main([str(findings), "-o", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["version"] == se.SARIF_VERSION
    assert len(doc["runs"][0]["results"]) == 2


def test_export_findings_sarif_only(tmp_path: Path):
    out_dir = tmp_path / "export"
    produced = se.export_findings(SAMPLE, out_dir, want_sarif=True)
    assert "sarif" in produced
    doc = json.loads(produced["sarif"].read_text(encoding="utf-8"))
    assert len(doc["runs"][0]["results"]) == 2


def test_export_findings_mocked_hdf(tmp_path: Path):
    out_dir = tmp_path / "export"
    calls = []

    def fake_runner(cmd, check=False, capture_output=True, text=True):
        calls.append(list(cmd))
        if "sarif2" + "hdf" in cmd:
            Path(cmd[cmd.index("-o") + 1]).write_text("{}" + chr(10), encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    produced = se.export_findings(
        SAMPLE,
        out_dir,
        want_sarif=True,
        want_hdf=True,
        runner=fake_runner,
        saf_bin="/usr/bin/" + N,
    )
    assert "sarif" in produced and "hdf" in produced
    assert calls and calls[0][1] == "convert"
