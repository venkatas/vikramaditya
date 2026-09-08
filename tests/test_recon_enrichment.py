#!/usr/bin/env python3
"""Tests for recon_enrichment.py — uncover/tlsx/waymore/xnLinkFinder glue."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import recon_enrichment as re_  # noqa: E402


def test_parse_uncover_plain_and_jsonl():
    text = "\n".join(
        [
            "1.2.3.4:443",
            "https://api.example.com",
            '{"ip":"5.6.7.8","port":8443,"host":"vpn.example.com"}',
            "garbage",
            "1.2.3.4:443",  # dup
        ]
    )
    hosts = re_.parse_uncover_hosts(text)
    assert "1.2.3.4:443" in hosts
    assert "api.example.com" in hosts
    assert "5.6.7.8:8443" in hosts or "vpn.example.com" in hosts
    assert hosts.count("1.2.3.4:443") == 1


def test_in_scope_hosts():
    hosts = ["api.example.com", "evil.com", "dev.api.example.com", "8.8.8.8"]
    got = re_.in_scope_hosts(hosts, "example.com")
    assert "api.example.com" in got
    assert "dev.api.example.com" in got
    assert "evil.com" not in got


def test_parse_xnlinkfinder_endpoints_dedup():
    text = "# Links found\n/api/v1/users\n[link] /api/v1/users\n/api/v1/orders\n"
    eps = re_.parse_xnlinkfinder_endpoints(text)
    assert eps == ["/api/v1/users", "/api/v1/orders"]


def test_summarize_lines_sample_cap():
    lines = [f"u{i}" for i in range(100)]
    s = re_.summarize_lines(lines, sample_n=5, tool="waymore")
    assert s["count"] == 100
    assert s["sample"] == ["u0", "u1", "u2", "u3", "u4"]
    assert s["tool"] == "waymore"


def test_cap_lines_for_merge():
    lines = [str(i) for i in range(10)]
    capped, was = re_.cap_lines_for_merge(lines, 3)
    assert was is True
    assert capped == ["0", "1", "2"]
    uncapped, was2 = re_.cap_lines_for_merge(lines, 0)
    assert was2 is False
    assert len(uncapped) == 10


def test_tlsx_scope_delta(tmp_path):
    sans = ["api.example.com", "cdn.cloudfront.net", "staging.example.com", "example.com"]
    known = ["example.com", "www.example.com"]
    delta = re_.tlsx_scope_delta(sans, known, "example.com")
    assert "api.example.com" in delta["in_scope_new"]
    assert "staging.example.com" in delta["in_scope_new"]
    assert "cdn.cloudfront.net" in delta["out_of_scope"]
    assert "example.com" not in delta["in_scope_new"]


def test_cli_cap_merge_and_summarize(tmp_path):
    src = tmp_path / "waymore.txt"
    src.write_text("\n".join(f"https://example.com/{i}" for i in range(50)) + "\n")
    merge = tmp_path / "waymore.merge.txt"
    full = tmp_path / "waymore.full.txt"
    summary = tmp_path / "waymore.summary.json"
    rc = re_.main(
        [
            "cap-merge",
            "--src",
            str(src),
            "--merge-out",
            str(merge),
            "--full-out",
            str(full),
            "--summary-out",
            str(summary),
            "--cap",
            "10",
            "--tool",
            "waymore",
        ]
    )
    assert rc == 0
    assert len(merge.read_text().splitlines()) == 10
    assert len(full.read_text().splitlines()) == 50
    payload = json.loads(summary.read_text())
    assert payload["count"] == 50
    assert payload["merged_count"] == 10
    assert payload["capped"] is True
    assert len(payload["sample"]) <= 20


def test_cli_parse_uncover(tmp_path):
    raw = tmp_path / "raw.txt"
    raw.write_text("10.0.0.1:443\napi.example.com\n")
    out = tmp_path / "hosts.txt"
    summary = tmp_path / "s.json"
    rc = re_.main(
        [
            "parse-uncover",
            "--path",
            str(raw),
            "--out-hosts",
            str(out),
            "--summary-out",
            str(summary),
            "--scope",
            "example.com",
            "--scope-filter",
        ]
    )
    assert rc == 0
    hosts = out.read_text().splitlines()
    assert hosts == ["api.example.com"]
    assert json.loads(summary.read_text())["count"] == 1


def test_cli_tlsx_feedback(tmp_path):
    sans = tmp_path / "sans.txt"
    known = tmp_path / "all.txt"
    sans.write_text("api.example.com\nother.org\n")
    known.write_text("www.example.com\n")
    in_scope = tmp_path / "in.txt"
    cands = tmp_path / "cands.txt"
    summary = tmp_path / "sum.json"
    rc = re_.main(
        [
            "tlsx-feedback",
            "--sans",
            str(sans),
            "--known",
            str(known),
            "--target",
            "example.com",
            "--out-in-scope",
            str(in_scope),
            "--out-candidates",
            str(cands),
            "--summary-out",
            str(summary),
        ]
    )
    assert rc == 0
    assert in_scope.read_text().strip() == "api.example.com"
    assert "other.org" in cands.read_text()
    payload = json.loads(summary.read_text())
    assert payload["in_scope_new_count"] == 1
