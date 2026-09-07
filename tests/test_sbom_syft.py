#!/usr/bin/env python3
"""Glue tests for sbom_syft — mocked binaries; synthetic SBOM files only."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import sbom_syft as ss  # noqa: E402


def test_build_syft_argv():
    args = ss.build_syft_argv(
        "dir:.",
        [("cyclonedx-json", Path("/tmp/sbom.cdx.json")), ("spdx-json", Path("/tmp/sbom.spdx.json"))],
    )
    assert args[0] == "dir:."
    assert "-o" in args
    assert "cyclonedx-json=/tmp/sbom.cdx.json" in args
    assert "spdx-json=/tmp/sbom.spdx.json" in args


def test_format_outfile():
    d = Path("/pack/sbom")
    assert ss.format_outfile(d, "cyclonedx-json").name == "sbom.cdx.json"
    assert ss.format_outfile(d, "spdx-json").name == "sbom.spdx.json"


def test_run_syft_mocked(tmp_path: Path):
    pack = tmp_path / "eng"
    pack.mkdir()

    def fake_runner(cmd, **kwargs):
        # last -o value paths
        for i, tok in enumerate(cmd):
            if tok == "-o" and i + 1 < len(cmd):
                spec = cmd[i + 1]
                if "=" in spec:
                    Path(spec.split("=", 1)[1]).write_text('{"bomFormat":"CycloneDX"}\n', encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    with mock.patch.object(ss, "resolve_syft", return_value="/fake/syft"):
        result = ss.run_syft("dir:.", pack, formats=["cyclonedx-json"], runner=fake_runner)
    assert result["files"]
    assert Path(result["files"][0]).is_file()


def test_attach_sbom_to_pack(tmp_path: Path):
    pack = tmp_path / "eng"
    pack.mkdir()
    sbom = tmp_path / "external.cdx.json"
    sbom.write_text('{"bomFormat":"CycloneDX","specVersion":"1.5"}\n', encoding="utf-8")
    grype = tmp_path / "grype.json"
    grype.write_text('{"matches":[]}\n', encoding="utf-8")
    manifest = ss.attach_sbom_to_pack(pack, [sbom], grype_path=grype, target_label="dir:.")
    assert len(manifest["sbom_files"]) == 1
    assert manifest["grype_file"]
    assert (pack / "sbom" / "attach_manifest.json").is_file()
    assert (pack / "sbom" / "external.cdx.json").is_file()


def test_run_grype_mocked(tmp_path: Path):
    sbom = tmp_path / "sbom.cdx.json"
    sbom.write_text("{}\n", encoding="utf-8")
    out = tmp_path / "grype.json"

    def fake_runner(cmd, **kwargs):
        Path(cmd[cmd.index("--file") + 1]).write_text('{"matches":[]}\n', encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    with mock.patch.object(ss, "resolve_grype", return_value="/fake/grype"):
        meta = ss.run_grype_on_sbom(sbom, out, runner=fake_runner)
    assert meta["file"]
    assert "sbom:" in meta["cmd"][1]


def test_cli_attach_only(tmp_path: Path):
    pack = tmp_path / "eng"
    pack.mkdir()
    sbom = tmp_path / "a.cdx.json"
    sbom.write_text("{}\n", encoding="utf-8")
    rc = ss.main(["--attach-only", "--pack-dir", str(pack), "--sbom", str(sbom), "--json"])
    assert rc == 0
    assert (pack / "sbom" / "a.cdx.json").is_file()
