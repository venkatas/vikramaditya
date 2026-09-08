"""Unit tests for skill_loader — on-demand web vuln skill packs."""

from __future__ import annotations

import os

import skill_loader


def test_list_skills_includes_core_packs():
    names = skill_loader.list_skills()
    for expected in (
        "ssrf", "sqli", "ssti", "lfi-traversal",
        "auth-bypass-idor", "xxe", "upload-rce", "deserialization",
        "api-authz-hadrian",
    ):
        assert expected in names, names


def test_load_skill_by_name_and_alias():
    body = skill_loader.load_skill("ssrf")
    assert "SSRF" in body
    assert "Proof standard" in body or "proof" in body.lower()
    aliased = skill_loader.load_skill("sql-injection")
    assert "SQL" in aliased.upper()


def test_load_missing_skill_message():
    msg = skill_loader.load_skill("no-such-pack-xyz")
    assert "not found" in msg.lower()
    assert "available" in msg.lower()


def test_skills_for_findings_heuristics():
    text = "Possible SQL injection on /search and SSRF via webhook= plus IDOR on /orders/{id}"
    matched = skill_loader.skills_for_findings(text)
    assert "sqli" in matched
    assert "ssrf" in matched
    assert "auth-bypass-idor" in matched


def test_format_skills_context_cap_and_disable(monkeypatch):
    monkeypatch.delenv("VIK_SKILLS", raising=False)
    ctx = skill_loader.format_skills_context(["sqli", "ssrf"], max_chars=500)
    assert "SKILL PACK" in ctx
    assert len(ctx) <= 500 + 80  # header overhead slack for truncation marker

    monkeypatch.setenv("VIK_SKILLS", "0")
    assert skill_loader.skills_enabled() is False
    assert skill_loader.format_skills_context(["sqli"]) == ""


def test_hadrian_skill_match():
    matched = skill_loader.skills_for_findings(
        'Hadrian BFLA / API authz role-matrix on /admin'
    )
    assert 'api-authz-hadrian' in matched
