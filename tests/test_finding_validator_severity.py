#!/usr/bin/env python3
"""Regression tests for finding_validator severity parsing + strict mode.

Covers three audit findings:
  - --strict must NOT kill confirmed critical/high findings (only below HIGH).
  - Q6 downgrade branch must fire for genuinely low/info findings.
  - never-submit match must be word-boundary aware and must not silently
    discard a parsed-critical/high finding.

All data here is SYNTHETIC.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import finding_validator as fv  # noqa: E402


def _write(d, sub, name, lines):
    p = os.path.join(d, sub)
    os.makedirs(p, exist_ok=True)
    with open(os.path.join(p, name), "w") as f:
        f.write("\n".join(lines) + "\n")


def test_parse_severity_explicit_token_wins():
    assert fv.parse_severity("xss reflected [CRITICAL] at /q", "xss") == "critical"
    assert fv.parse_severity("info: banner on /", "exposure") == "info"


def test_parse_severity_vtype_default():
    # No explicit token -> falls back to per-vtype default.
    assert fv.parse_severity("boolean-based blind at /id", "sqli") == "critical"
    assert fv.parse_severity("webshell uploaded to /up", "rce") == "critical"
    assert fv.parse_severity("idor on /api/user", "idor") == "high"
    assert fv.parse_severity("something", "unknown_vtype") == "medium"


def test_strict_keeps_confirmed_sqli(tmp_path):
    d = str(tmp_path)
    _write(d, "sqli", "out.txt", ["confirmed boolean-based sqli http://acme.invalid/id?x=1"])
    res = fv.validate_findings_dir(d, strict=True)
    sources = [r["source"] for r in res["pass"]]
    assert "sqli/out.txt" in sources, "confirmed SQLi must survive --strict"
    assert not res["kill"], "no kill expected for a critical finding under --strict"


def test_strict_kills_medium_and_below(tmp_path):
    d = str(tmp_path)
    # xss defaults to medium; redirect defaults to low.
    _write(d, "xss", "x.txt", ["reflected xss http://acme.invalid/q?s=1"])
    _write(d, "redirects", "r.txt", ["open redirect-ish param http://acme.invalid/go?u=x"])
    res = fv.validate_findings_dir(d, strict=True)
    assert not res["pass"], "medium/low should be killed under --strict"
    assert res["kill"], "medium/low findings should land in kill under --strict"


def test_non_strict_passes_real_findings(tmp_path):
    d = str(tmp_path)
    _write(d, "sqli", "s.txt", ["confirmed sqli http://acme.invalid/id?x=1"])
    res = fv.validate_findings_dir(d, strict=False)
    assert any(r["source"] == "sqli/s.txt" for r in res["pass"])


def test_q6_downgrade_branch_fires(tmp_path):
    d = str(tmp_path)
    # Explicit low token routes through Q6 downgrade.
    _write(d, "exposure", "e.txt", ["low: verbose error page http://acme.invalid/err"])
    res = fv.validate_findings_dir(d, strict=False)
    assert res["downgrade"], "Q6 downgrade bucket must be reachable for low/info"
    assert res["downgrade"][0]["kill_question"] == 6


def test_never_submit_word_boundary():
    # Exact never-submit phrase matches.
    assert fv.is_never_submit("missing csp header on /") == "missing csp header"
    # A phrase embedded as a non-boundary substring must NOT match.
    assert fv.is_never_submit("xtrace method enabledx exploit") is None


def test_never_submit_critical_not_silently_killed():
    # A parsed-critical finding that incidentally contains a never-submit
    # phrase is routed to review (chain_required), not killed.
    f = {"raw": "options method enabled but leads to sqli rce", "severity": "critical"}
    out = fv.validate_finding(f)
    assert out["decision"] != "kill"
    assert out["decision"] == "chain_required"


def test_never_submit_low_still_killed():
    f = {"raw": "options method enabled", "severity": "low"}
    out = fv.validate_finding(f)
    # low/info under never-submit: Q6 unreachable (Q7 runs first) -> kill.
    assert out["decision"] == "kill"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
