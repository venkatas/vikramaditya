#!/usr/bin/env python3
"""Tests for hadrian_audit glue — synthetic data only, no network."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import hadrian_audit as ha  # noqa: E402
import tool_parsers as tp  # noqa: E402


@pytest.fixture()
def cfg(tmp_path: Path):
    roles = tmp_path / "roles.yaml"
    auth = tmp_path / "auth.yaml"
    api = tmp_path / "openapi.yaml"
    roles.write_text("roles: []\n")
    auth.write_text("method: bearer\nroles: {}\n")
    api.write_text("openapi: 3.0.0\ninfo: {title: t, version: 0}\npaths: {}\n")
    return {"roles": str(roles), "auth": str(auth), "api": str(api), "tmp": tmp_path}


def test_build_cmd_rest_requires_api(cfg):
    out = cfg["tmp"] / "report.json"
    cmd = ha.build_hadrian_cmd(
        binary="/usr/bin/hadrian",
        protocol="rest",
        api=cfg["api"],
        target="",
        proto="",
        roles=cfg["roles"],
        auth=cfg["auth"],
        category="all",
        output_file=out,
        dry_run=True,
        insecure=False,
        proxy="",
        templates_dir="",
    )
    assert cmd[:3] == ["/usr/bin/hadrian", "test", "rest"]
    assert "--api" in cmd and cfg["api"] in cmd
    assert "--roles" in cmd and "--auth" in cmd
    assert "--dry-run" in cmd
    assert "--output" in cmd and "json" in cmd
    assert str(out) in cmd


def test_build_cmd_fails_closed_missing_roles(cfg):
    with pytest.raises(SystemExit):
        ha.build_hadrian_cmd(
            binary="hadrian",
            protocol="rest",
            api=cfg["api"],
            target="",
            proto="",
            roles="/no/such/roles.yaml",
            auth=cfg["auth"],
            category="all",
            output_file=cfg["tmp"] / "r.json",
            dry_run=False,
            insecure=False,
            proxy="",
            templates_dir="",
        )


def test_build_cmd_graphql_needs_target(cfg):
    with pytest.raises(SystemExit):
        ha.build_hadrian_cmd(
            binary="hadrian",
            protocol="graphql",
            api="",
            target="",
            proto="",
            roles=cfg["roles"],
            auth=cfg["auth"],
            category="all",
            output_file=cfg["tmp"] / "r.json",
            dry_run=False,
            insecure=False,
            proxy="",
            templates_dir="",
        )
    cmd = ha.build_hadrian_cmd(
        binary="hadrian",
        protocol="graphql",
        api="",
        target="https://api.example.invalid/graphql",
        proto="",
        roles=cfg["roles"],
        auth=cfg["auth"],
        category="API1",
        output_file=cfg["tmp"] / "r.json",
        dry_run=False,
        insecure=True,
        proxy="http://127.0.0.1:8080",
        templates_dir="",
    )
    assert "--target" in cmd
    assert "--insecure" in cmd
    assert "--proxy" in cmd


def test_resolve_hadrian_bin_env(monkeypatch, tmp_path):
    fake = tmp_path / "hadrian"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setenv("HADRIAN_BIN", str(fake))
    assert ha.resolve_hadrian_bin() == str(fake)


def test_main_missing_binary_returns_127(cfg, monkeypatch):
    monkeypatch.setattr(ha, "resolve_hadrian_bin", lambda: None)
    rc = ha.main([
        "--api", cfg["api"], "--roles", cfg["roles"], "--auth", cfg["auth"],
        "--output-dir", str(cfg["tmp"] / "out"),
    ])
    assert rc == 127


def test_main_dry_run_invokes_and_parses(cfg, monkeypatch):
    report = {
        "metadata": {"tool": "hadrian", "version": "1.0.0"},
        "summary": {"total_findings": 1},
        "findings": [{
            "id": "f1",
            "template_id": "rest-bola",
            "category": "API1",
            "name": "BOLA on /api/orders/{id}",
            "description": "user read admin order",
            "severity": "HIGH",
            "confidence": 0.9,
            "is_vulnerability": True,
            "endpoint": "GET /api/orders/{id}",
            "method": "GET",
            "attacker_role": "user",
            "victim_role": "admin",
            "evidence": {
                "request": {
                    "method": "GET",
                    "url": "https://api.example.invalid/api/orders/1",
                    "headers": {},
                },
                "response": {
                    "status_code": 200,
                    "headers": {},
                    "body": "{}",
                    "body_hash": "x",
                    "size": 2,
                    "truncated": False,
                },
            },
        }],
    }

    def fake_run(cmd, log_path, timeout):
        idx = cmd.index("--output-file")
        Path(cmd[idx + 1]).write_text(json.dumps(report))
        return 1

    monkeypatch.setattr(ha, "resolve_hadrian_bin", lambda: "/usr/bin/hadrian")
    monkeypatch.setattr(ha, "run_hadrian", fake_run)
    out = cfg["tmp"] / "out"
    rc = ha.main([
        "--protocol", "rest",
        "--api", cfg["api"],
        "--roles", cfg["roles"],
        "--auth", cfg["auth"],
        "--dry-run",
        "--output-dir", str(out),
    ])
    assert rc == 0
    findings = json.loads((out / "findings.json").read_text())
    assert len(findings) == 1
    assert findings[0]["tool"] == "hadrian"
    assert findings[0]["status"] == "suspected"
    assert findings[0]["severity"] == "high"
    summary = json.loads((out / "summary.json").read_text())
    assert summary["finding_count"] == 1
    assert summary["dry_run"] is True


def test_parse_hadrian_json_empty_and_malformed():
    assert tp.parse_hadrian_json("") == []
    assert tp.parse_hadrian_json("{not json") == []
    assert tp.parse_hadrian_json("[]") == []


def test_parse_hadrian_json_report_shape():
    payload = {
        "metadata": {"tool": "hadrian"},
        "findings": [{
            "name": "BFLA admin endpoint",
            "category": "API5",
            "severity": "CRITICAL",
            "is_vulnerability": True,
            "endpoint": "DELETE /api/admin/users/{id}",
            "method": "DELETE",
            "attacker_role": "user",
            "victim_role": "admin",
            "description": "low-priv delete succeeded",
            "evidence": {
                "request": {
                    "method": "DELETE",
                    "url": "https://api.example.invalid/api/admin/users/9",
                },
                "response": {"status_code": 204},
            },
        }],
    }
    findings = tp.parse_hadrian_json(json.dumps(payload))
    assert len(findings) == 1
    f = findings[0]
    assert f["tool"] == "hadrian"
    assert f["severity"] == "critical"
    assert f["category"] == "API5"
    assert "user" in f["evidence"]
    assert f["url"].startswith("https://")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
