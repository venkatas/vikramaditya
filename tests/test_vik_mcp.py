"""Opt-in Vik MCP facade. Stdlib JSON-RPC. No network, no tool execution."""

from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path

import hexstrike_patterns
import session_tool_cache as cache


def _load_server():
    repo = Path(__file__).resolve().parents[1]
    path = repo / "mcp" / "vik-mcp" / "server.py"
    spec = importlib.util.spec_from_file_location("vik_mcp_server", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_tool_list_is_narrow_and_has_no_exec():
    srv = _load_server()
    names = [t["name"] for t in srv.tool_list()]
    assert names == [
        "vik_list_skills",
        "vik_load_skill",
        "vik_session_status",
        "vik_cached_tool_lookup",
        "vik_scope_check",
        "vik_coverage_notes",
    ]
    blob = " ".join(names)
    for forbidden in srv.FORBIDDEN_TOOL_NAMES:
        assert forbidden not in names
    assert "run_command" not in blob
    source = (Path(__file__).resolve().parents[1] / "mcp" / "vik-mcp" / "server.py").read_text()
    assert "import subprocess" not in source
    assert "os.system" not in source
    assert "os.exec" not in source


def test_initialize_and_tools_call_over_framed_stdio():
    srv = _load_server()
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}}
    listed = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    inbound = io.BytesIO(srv.encode_message(init) + srv.encode_message(listed))
    outbound = io.BytesIO()
    # serve() loops until EOF
    rc = srv.serve(stdin=inbound, stdout=outbound)
    assert rc == 0
    raw = outbound.getvalue()
    first = srv.read_message(io.BytesIO(raw))
    second = srv.read_message(io.BytesIO(raw[raw.find(b"Content-Length:", 1):] if False else raw))
    # parse both frames sequentially
    stream = io.BytesIO(raw)
    first = srv.read_message(stream)
    second = srv.read_message(stream)
    assert first["result"]["serverInfo"]["name"] == "vik-mcp"
    assert first["result"]["protocolVersion"] == "2024-11-05"
    names = [t["name"] for t in second["result"]["tools"]]
    assert "vik_scope_check" in names
    assert "run_command" not in names


def test_scope_check_reuses_scope_checker_and_does_not_claim_traffic():
    srv = _load_server()
    result = srv.call_tool("vik_scope_check", {
        "host": "https://api.example.com/v1",
        "domains": ["*.example.com"],
        "excluded": ["admin.example.com"],
    })
    body = json.loads(result["content"][0]["text"])
    assert body["in_scope"] is True
    assert body["traffic"] is False
    denied = srv.call_tool("vik_scope_check", {
        "host": "https://evil-example.com",
        "domains": ["*.example.com"],
    })
    denied_body = json.loads(denied["content"][0]["text"])
    assert denied_body["in_scope"] is False
    missing = srv.call_tool("vik_scope_check", {"host": "https://example.com"})
    assert missing["isError"] is True


def test_cached_lookup_does_not_execute_and_rejects_outside_roots(tmp_path, monkeypatch):
    srv = _load_server()
    session = tmp_path / "sess"
    session.mkdir()
    os.chmod(session, 0o700)
    monkeypatch.setenv("VIK_SESSION_DIR", str(session))
    monkeypatch.setenv("VIK_SESSION_TOOL_CACHE", "1")
    args = ["httpx", "-u", "https://app.example.invalid"]
    cache.store(
        "app.example.invalid", "httpx", args, True, "cached-body", str(session),
        scope_domains=["app.example.invalid"],
    )
    result = srv.call_tool("vik_cached_tool_lookup", {
        "target": "app.example.invalid",
        "tool": "httpx",
        "args": args,
        "session_dir": str(session),
    })
    body = json.loads(result["content"][0]["text"])
    assert body["hit"] is True
    assert body["executed"] is False
    assert "cached-body" in body["output"]
    assert "path" not in body

    outside = srv.call_tool("vik_cached_tool_lookup", {
        "target": "app.example.invalid",
        "tool": "httpx",
        "args": args,
        "session_dir": "/etc",
    })
    assert outside["isError"] is True


def test_unknown_tool_rejected():
    srv = _load_server()
    result = srv.call_tool("run_command", {"cmd": "id"})
    assert result["isError"] is True


def test_coverage_notes_are_short_and_not_an_install_wall():
    notes = hexstrike_patterns.coverage_notes()
    assert notes["vendored"] is False
    assert notes["runtime"] == "skipped"
    assert len(notes["optional_coverage"]) <= 5
    assert all(item["installed_by_setup"] is False for item in notes["optional_coverage"])
    assert all(item["on_default_scan_path"] is False for item in notes["optional_coverage"])
    ids = {item["id"] for item in notes["optional_coverage"]}
    assert "ctf-coverage-notes" in ids
    assert "cloud-iam-notes" in ids


def test_skill_stubs_are_registered():
    import skill_loader
    names = skill_loader.list_skills()
    assert "cloud-iam-notes" in names
    assert "ctf-coverage-notes" in names
    iam = skill_loader.load_skill("cloud-iam-notes")
    assert "Prowler" in iam or "whitebox" in iam
    ctf = skill_loader.load_skill("ctf-coverage-notes")
    assert "not a CTF" in ctf or "not a CTF solver" in ctf or "CTF" in ctf
    matched = skill_loader.skills_for_findings("CTF forensics binwalk and IAM posture unused access key")
    assert "ctf-coverage-notes" in matched
    assert "cloud-iam-notes" in matched
