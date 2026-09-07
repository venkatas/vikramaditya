"""Unit tests for skill_loader — on-demand web/recon/cloud skill packs."""

from __future__ import annotations

import os

import skill_loader


def test_list_skills_includes_core_packs():
    names = skill_loader.list_skills()
    for expected in (
        "ssrf", "sqli", "ssti", "lfi-traversal",
        "auth-bypass-idor", "xxe", "upload-rce", "deserialization",
    ):
        assert expected in names, names


def test_list_skills_includes_cai_portable_packs():
    names = skill_loader.list_skills()
    for expected in (
        "http-security-headers",
        "api-authz-matrix",
        "passive-osint",
        "attack-surface-map",
        "cloud-metadata-imds",
        "storage-exposure",
    ):
        assert expected in names, names


def test_load_skill_by_name_and_alias():
    body = skill_loader.load_skill("ssrf")
    assert "SSRF" in body
    assert "Proof standard" in body or "proof" in body.lower()
    aliased = skill_loader.load_skill("sql-injection")
    assert "SQL" in aliased.upper()


def test_load_cai_portable_aliases():
    osint = skill_loader.load_skill("osint")
    assert "OSINT" in osint or "Passive" in osint
    imds = skill_loader.load_skill("imds")
    assert "IMDS" in imds or "169.254.169.254" in imds
    headers = skill_loader.load_skill("cors")
    assert "CORS" in headers or "header" in headers.lower()
    storage = skill_loader.load_skill("s3")
    assert "storage" in storage.lower() or "S3" in storage or "bucket" in storage.lower()


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


def test_skills_for_findings_cai_portable():
    text = (
        "Passive OSINT via Shodan plus attack surface map; "
        "CORS misconfig; IMDS 169.254.169.254; public S3 bucket exposure; BFLA on admin API"
    )
    matched = skill_loader.skills_for_findings(text)
    assert "passive-osint" in matched
    assert "attack-surface-map" in matched
    assert "http-security-headers" in matched
    assert "cloud-metadata-imds" in matched
    assert "storage-exposure" in matched
    assert "api-authz-matrix" in matched


def test_format_skills_context_cap_and_disable(monkeypatch):
    monkeypatch.delenv("VIK_SKILLS", raising=False)
    ctx = skill_loader.format_skills_context(["sqli", "ssrf"], max_chars=500)
    assert "SKILL PACK" in ctx
    assert len(ctx) <= 500 + 80  # header overhead slack for truncation marker

    monkeypatch.setenv("VIK_SKILLS", "0")
    assert skill_loader.skills_enabled() is False
    assert skill_loader.format_skills_context(["sqli"]) == ""
