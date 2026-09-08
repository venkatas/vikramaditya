#!/usr/bin/env python3
"""Glue tests for cats_audit.py — mock binary; synthetic CATS summary JSON only."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cats_audit as ca  # noqa: E402


def test_resolve_cats_prefer_cats_bin(tmp_path, monkeypatch):
    fake = tmp_path / "cats"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setenv("CATS_BIN", str(fake))
    monkeypatch.delenv("CATS_JAR", raising=False)
    mode, prefix = ca.resolve_cats_cmd()
    assert mode == "native"
    assert prefix == [str(fake)]


def test_resolve_cats_jar_fallback(tmp_path, monkeypatch):
    jar = tmp_path / "cats.jar"
    jar.write_bytes(b"PK")
    monkeypatch.delenv("CATS_BIN", raising=False)
    monkeypatch.setenv("CATS_JAR", str(jar))
    with mock.patch.object(ca, "_which", side_effect=lambda n: "/usr/bin/java" if n == "java" else None):
        mode, prefix = ca.resolve_cats_cmd()
    assert mode == "jar"
    assert prefix == ["/usr/bin/java", "-jar", str(jar)]


def test_resolve_cats_none(monkeypatch):
    monkeypatch.delenv("CATS_BIN", raising=False)
    monkeypatch.delenv("CATS_JAR", raising=False)
    with mock.patch.object(ca, "_which", return_value=None):
        mode, prefix = ca.resolve_cats_cmd()
    assert mode == "none"
    assert prefix == []


def test_build_cats_argv_header_colon_to_equals():
    args = ca.build_cats_argv(
        contract="openapi.yml",
        server="https://api.example.invalid",
        output_dir=Path("/tmp/cats-out"),
        headers=["Authorization: Bearer abc"],
        token=None,
        headers_file=None,
        blackbox=False,
        paths=None,
        skip_ssl=False,
        dry_run=False,
        extra=[],
    )
    assert "--contract=openapi.yml" in args
    assert "--server=https://api.example.invalid" in args
    assert "--output=/tmp/cats-out" in args
    i = args.index("-H")
    assert args[i + 1] == "Authorization=Bearer abc"


def test_build_cats_argv_token_and_blackbox():
    args = ca.build_cats_argv(
        contract="c.yml",
        server="https://x.example.invalid",
        output_dir=Path("/out"),
        headers=[],
        token="Bearer tok",
        headers_file=None,
        blackbox=True,
        paths="/v1/users,/v1/orders",
        skip_ssl=False,
        dry_run=True,
        extra=["--verbosity=SUMMARY"],
    )
    assert "-H" in args
    assert "Authorization=Bearer tok" in args
    assert "--blackbox" in args
    assert "-k" in args
    assert "--paths=/v1/users,/v1/orders" in args
    assert "--dryRun" in args
    assert "--verbosity=SUMMARY" in args


def test_parse_cats_summary_errors(tmp_path):
    report = {
        "errors": 2,
        "warnings": 1,
        "success": 10,
        "totalTests": 13,
        "catsVersion": "14.0.0",
        "timestamp": "Mon, 07 Sep 2026 12:00:00 GMT",
        "testCases": [
            {
                "id": "Test1",
                "result": "error",
                "resultReason": "Unexpected Response Code",
                "path": "/v1/users",
                "httpMethod": "post",
                "httpResponseCode": 500,
                "fuzzer": "NullValuesInFieldsFuzzer",
                "scenario": "Send null",
                "resultDetails": "expected 4xx got 500",
            },
            {
                "id": "Test2",
                "result": "error",
                "resultReason": "Error details leak",
                "path": "/v1/orders",
                "httpMethod": "get",
                "httpResponseCode": 500,
                "fuzzer": "LargeValuesFuzzer",
                "scenario": "Huge string",
                "resultDetails": "stack trace",
            },
            {
                "id": "Test3",
                "result": "warn",
                "resultReason": "Undocumented Response Code",
                "path": "/v1/ping",
                "httpMethod": "get",
                "httpResponseCode": 204,
                "fuzzer": "HappyPath",
                "scenario": "ok",
                "resultDetails": "",
            },
            {
                "id": "Test4",
                "result": "success",
                "path": "/v1/ping",
                "httpMethod": "get",
                "fuzzer": "HappyPath",
            },
        ],
    }
    (tmp_path / "cats-summary-report.json").write_text(json.dumps(report), encoding="utf-8")
    parsed = ca.parse_cats_summary(tmp_path)
    assert parsed["errors"] == 2
    assert parsed["warnings"] == 1
    assert parsed["success"] == 10
    assert parsed["total_tests"] == 13
    assert len(parsed["error_leads"]) == 2
    assert parsed["error_leads"][0]["result_reason"] == "Unexpected Response Code"
    assert parsed["error_leads"][0]["path"] == "/v1/users"
    assert len(parsed["warn_leads"]) == 1
    assert parsed["html_report"].endswith("index.html")


def test_parse_fallback_test_json(tmp_path):
    (tmp_path / "Test9.json").write_text(
        json.dumps({"id": "Test9", "result": "error", "path": "/x", "resultReason": "boom"}),
        encoding="utf-8",
    )
    (tmp_path / "Test10.json").write_text(
        json.dumps({"id": "Test10", "result": "success", "path": "/y"}),
        encoding="utf-8",
    )
    parsed = ca.parse_cats_summary(tmp_path)
    assert parsed["errors"] == 1
    assert parsed["error_leads"][0]["id"] == "Test9"
    assert "missing" in (parsed.get("parse_note") or "")


def test_main_parse_only(tmp_path):
    report = {
        "errors": 1,
        "warnings": 0,
        "success": 0,
        "totalTests": 1,
        "testCases": [
            {"id": "Test1", "result": "error", "path": "/a", "resultReason": "Unexpected Behaviour"},
        ],
    }
    (tmp_path / "cats-summary-report.json").write_text(json.dumps(report), encoding="utf-8")
    rc = ca.main(["--contract", "x.yml", "--server", "https://x.invalid", "--parse-only", str(tmp_path)])
    assert rc == 0
    summary = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert summary["parsed"]["errors"] == 1
    assert (tmp_path / "error_leads.json").is_file()


def test_main_runs_mock_binary(tmp_path, monkeypatch):
    fake = tmp_path / "fake-cats"
    # Write a tiny script that creates a minimal CATS summary in --output=
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json,sys\n"
        "from pathlib import Path\n"
        "out=None\n"
        "for a in sys.argv[1:]:\n"
        "  if a.startswith('--output='): out=Path(a.split('=',1)[1])\n"
        "out=out or Path('cats-report')\n"
        "out.mkdir(parents=True, exist_ok=True)\n"
        "(out/'index.html').write_text('<html></html>')\n"
        "(out/'cats-summary-report.json').write_text(json.dumps({\n"
        "  'errors':0,'warnings':0,'success':1,'totalTests':1,'testCases':[\n"
        "    {'id':'Test1','result':'success','path':'/p'}]}))\n"
        "sys.exit(0)\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    monkeypatch.setenv("CATS_BIN", str(fake))
    out = tmp_path / "report"
    contract = tmp_path / "openapi.yml"
    contract.write_text("openapi: 3.0.0\ninfo: {title: t, version: '0'}\npaths: {}\n")
    rc = ca.main([
        "--contract", str(contract),
        "--server", "https://api.example.invalid",
        "--output-dir", str(out),
        "--header", "X-Test: 1",
        "--timeout", "30",
    ])
    assert rc == 0
    assert (out / "summary.json").is_file()
    assert (out / "cats-summary-report.json").is_file()
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["parsed"]["success"] == 1


def test_main_missing_binary_returns_127(monkeypatch, tmp_path):
    monkeypatch.delenv("CATS_BIN", raising=False)
    monkeypatch.delenv("CATS_JAR", raising=False)
    with mock.patch.object(ca, "_which", return_value=None):
        rc = ca.main([
            "--contract", str(tmp_path / "o.yml"),
            "--server", "https://api.example.invalid",
            "--output-dir", str(tmp_path / "out"),
        ])
    assert rc == 127


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
