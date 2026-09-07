#!/usr/bin/env python3
"""Glue tests for evidence_bag — stdlib BagIt path; synthetic artefacts only."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import evidence_bag as eb  # noqa: E402


def _seed_pack(pack: Path) -> None:
    (pack / "reports").mkdir(parents=True)
    (pack / "reports" / "report.html").write_text("<html>demo</html>\n", encoding="utf-8")
    (pack / "findings" / "burp").mkdir(parents=True)
    (pack / "findings" / "burp" / "findings.json").write_text("[]\n", encoding="utf-8")
    (pack / "findings" / "gitleaks").mkdir(parents=True)
    (pack / "findings" / "gitleaks" / "gitleaks.sarif.json").write_text(
        json.dumps({"version": "2.1.0", "runs": []}) + "\n", encoding="utf-8"
    )
    (pack / "sbom").mkdir(parents=True)
    (pack / "sbom" / "sbom.cdx.json").write_text('{"bomFormat":"CycloneDX"}\n', encoding="utf-8")
    (pack / "reports" / "poc_screenshots").mkdir(parents=True)
    (pack / "reports" / "poc_screenshots" / "shot.png").write_bytes(b"\x89PNG\r\n\x1a\n")


def test_collect_and_stdlib_bag(tmp_path: Path):
    pack = tmp_path / "eng"
    pack.mkdir()
    _seed_pack(pack)
    bag = tmp_path / "bag"
    data = bag / "data"
    inv = eb.collect_evidence(
        data,
        report=[pack / "reports" / "report.html"],
        burp=[pack / "findings" / "burp"],
        sarif=[pack / "findings" / "gitleaks" / "gitleaks.sarif.json"],
        sbom=[pack / "sbom"],
        screenshots=[pack / "reports" / "poc_screenshots"],
    )
    assert "report" in inv and "burp" in inv and "sarif" in inv and "sbom" in inv
    assert "screenshots" in inv
    meta = eb.make_evidence_bag(bag, prefer_bagit_lib=False)
    assert meta["backend"] == "stdlib"
    assert (bag / "bagit.txt").is_file()
    assert (bag / "manifest-sha256.txt").is_file()
    assert (bag / "tagmanifest-sha256.txt").is_file()
    validation = eb.validate_bag(bag)
    assert validation["valid"] is True


def test_build_evidence_pack_autodiscover(tmp_path: Path):
    pack = tmp_path / "acme"
    pack.mkdir()
    _seed_pack(pack)
    out = pack / "evidence-bags"
    summary = eb.build_evidence_pack(pack, out, stamp="20260101T000000Z", auto_discover=True)
    assert summary["validation"]["valid"] is True
    bag_dir = Path(summary["bag_dir"])
    assert (bag_dir / "bagit.txt").is_file()
    assert (bag_dir / "data" / "report" / "report.html").is_file()
    assert (bag_dir / "data" / "sarif" / "gitleaks.sarif.json").is_file()
    assert (bag_dir / "data" / "sbom" / "sbom.cdx.json").is_file()
    assert (out / "evidence-20260101T000000Z.summary.json").is_file()


def test_tamper_fails_validation(tmp_path: Path):
    pack = tmp_path / "eng"
    pack.mkdir()
    _seed_pack(pack)
    summary = eb.build_evidence_pack(pack, tmp_path / "bags", stamp="t1", auto_discover=True)
    bag = Path(summary["bag_dir"])
    target = bag / "data" / "report" / "report.html"
    target.write_text("TAMPERED\n", encoding="utf-8")
    assert (bag / "manifest-sha256.txt").is_file()
    result = eb.validate_bag(bag)
    assert result["valid"] is False


def test_cli(tmp_path: Path):
    pack = tmp_path / "eng"
    pack.mkdir()
    _seed_pack(pack)
    rc = eb.main(["--pack-dir", str(pack), "--out", str(pack / "evidence-bags"), "--json"])
    assert rc == 0
