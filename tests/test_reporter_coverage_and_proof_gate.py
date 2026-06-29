"""Regression tests for reporter.py audit fixes (group reporter.py).

Covers four CONFIRMED findings, all with SYNTHETIC data only:

F0  brain_active loader: a truncated NEWEST iteration_NN.json must NOT abandon
    the whole brain_active block. The loader now walks newest→oldest and uses the
    first parseable (cumulative) iteration; if NONE parse it emits a visible
    degradation INFO marker instead of silently dropping everything.

F1  Grounded NON-passwd file reads (source/config/log/hosts/environ) must survive
    the reporter's proof gate. The narrow signature whitelist is no longer the SOLE
    proof: substantive retrieved content keeps the finding, while a bare
    `echo "[CRITICAL] accessible"` (no content) is still demoted.

F2  HAR (legacy) and Method-2 finding_*.json loaders normalize severity so the
    Executive Summary per-severity table reconciles with Total. _severity_counts
    also folds any stray severity into 'info' as defense-in-depth.

F3  Single-file loaders (email_auth/burp/exposed_credentials/brain_active) emit a
    visible WARNING instead of silently swallowing a malformed source.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from reporter import SEVERITY_COLOR, _severity_counts, load_findings


# ---------------------------------------------------------------------------
# F0 — truncated newest brain_active iteration must not drop confirmed findings
# ---------------------------------------------------------------------------
def _brain_iter(content_findings, results_blob):
    return {"findings_so_far": content_findings, "results": results_blob}


def test_brain_active_truncated_newest_falls_back_to_earlier(tmp_path):
    d = tmp_path / "brain_active"
    d.mkdir()
    # Iteration 01: a clean cumulative list with a grounded passwd read.
    passwd_proof = "root:x:0:0:root:/root:/bin/bash"
    (d / "iteration_01.json").write_text(json.dumps(_brain_iter(
        ["[CRITICAL] /etc/passwd readable via traversal"],
        f"GET /a HTTP/1.1\n{passwd_proof}\n",
    )))
    # Iteration 02 (newest): TRUNCATED / unparseable (simulates killed mid-write).
    (d / "iteration_02.json").write_text('{"findings_so_far": ["[CRI')

    findings = load_findings(str(tmp_path))
    titles = [f["title"] for f in findings]
    # The confirmed finding from the intact earlier iteration MUST appear.
    assert any("script-confirmed" in t for t in titles), \
        "truncated newest iteration silently dropped earlier confirmed findings"


def test_brain_active_all_unparseable_emits_degradation_marker(tmp_path):
    d = tmp_path / "brain_active"
    d.mkdir()
    (d / "iteration_01.json").write_text('{"findings_so_far": ["[CR')
    (d / "iteration_02.json").write_text('not json at all')

    findings = load_findings(str(tmp_path))
    assert any("UNAVAILABLE" in f["title"] for f in findings), \
        "no degradation marker emitted when all iterations unparseable"


# ---------------------------------------------------------------------------
# F1 — grounded non-passwd reads survive; bare echo claim is still demoted
# ---------------------------------------------------------------------------
def test_grounded_nonpasswd_read_is_kept_as_finding(tmp_path):
    d = tmp_path / "brain_active"
    d.mkdir()
    # A real path-traversal read of an application YAML config: the claim line
    # matches _ACCESS_CLAIM_RE ("readable"), but the printed content is NOT a
    # passwd/secret signature — it is substantive retrieved file content.
    yaml_content = (
        "database:\n"
        "  host: db.internal.example.invalid\n"
        "  name: acme_appdb\n"
        "  pool_size: 20\n"
        "logging:\n"
        "  level: debug\n"
    )
    blob = "[CRITICAL] Path traversal: config.yaml readable\n" + yaml_content
    (d / "iteration_01.json").write_text(json.dumps(_brain_iter(
        ["[CRITICAL] Path traversal: config.yaml readable"], blob)))

    findings = load_findings(str(tmp_path))
    confirmed = [f for f in findings if "script-confirmed" in f["title"]]
    assert confirmed, "grounded non-passwd file read was wrongly demoted/dropped"


def test_bare_echo_access_claim_with_no_content_is_demoted(tmp_path):
    d = tmp_path / "brain_active"
    d.mkdir()
    # A buggy PoC that only echoes the banner — NO retrieved file content.
    blob = "[CRITICAL] /etc/passwd accessible\n"
    (d / "iteration_01.json").write_text(json.dumps(_brain_iter(
        ["[CRITICAL] /etc/passwd accessible"], blob)))

    findings = load_findings(str(tmp_path))
    confirmed = [f for f in findings if "script-confirmed" in f["title"]]
    assert not confirmed, "unproven echo-only access claim leaked into findings table"
    # It should instead appear collapsed as an unconfirmed model-claim INFO row.
    assert any("model claims" in f["title"] for f in findings)


# ---------------------------------------------------------------------------
# F2 — severity normalization so the Executive Summary reconciles with Total
# ---------------------------------------------------------------------------
def test_har_loader_normalizes_severity(tmp_path):
    blob = {"vulnerabilities": [
        {"type": "XSS", "severity": "Critical", "endpoint": "https://acme.invalid/x"},
        {"type": "Info Leak", "severity": "informational", "endpoint": "https://acme.invalid/y"},
        {"type": "Weird", "severity": "none", "endpoint": "https://acme.invalid/z"},
    ]}
    (tmp_path / "har_vapt_001.json").write_text(json.dumps(blob))
    findings = load_findings(str(tmp_path))
    har = [f for f in findings if f["url"].startswith("https://acme.invalid")]
    assert len(har) == 3
    for f in har:
        assert f["severity"] in SEVERITY_COLOR, f"unnormalized severity: {f['severity']!r}"


def test_method2_loader_normalizes_severity(tmp_path):
    (tmp_path / "finding_001.json").write_text(json.dumps(
        {"type": "idor", "severity": "informational", "url": "https://acme.invalid/u",
         "detail": "synthetic", "evidence": "synthetic"}))
    findings = load_findings(str(tmp_path))
    m2 = [f for f in findings if f.get("url") == "https://acme.invalid/u"]
    assert m2 and m2[0]["severity"] == "info"


def test_severity_counts_reconcile_with_total():
    findings = [
        {"severity": "high"}, {"severity": "Critical"}, {"severity": "informational"},
        {"severity": "none"}, {"severity": "medium"}, {"severity": "low"},
    ]
    counts = _severity_counts(findings)
    assert sum(counts.values()) == len(findings), \
        "per-severity counts do not reconcile with Total"
    assert set(counts) == set(SEVERITY_COLOR)


# ---------------------------------------------------------------------------
# F3 — malformed single-file source emits a visible WARNING (not silent)
# ---------------------------------------------------------------------------
def test_malformed_burp_source_emits_warning(tmp_path, capsys):
    bd = tmp_path / "burp"
    bd.mkdir()
    (bd / "findings.json").write_text("{ this is not valid json")
    load_findings(str(tmp_path))
    out = capsys.readouterr().out
    assert "WARNING" in out and "Burp" in out, \
        "malformed burp source was swallowed silently"


def test_malformed_email_auth_source_emits_warning(tmp_path, capsys):
    ed = tmp_path / "email_auth"
    ed.mkdir()
    (ed / "findings.json").write_text("<<<not json>>>")
    load_findings(str(tmp_path))
    out = capsys.readouterr().out
    assert "WARNING" in out and "email-auth" in out, \
        "malformed email_auth source was swallowed silently"


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
