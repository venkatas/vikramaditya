"""Regression — a missing/weak CSP header is a LOW security-misconfiguration,
NOT a Cross-Site Scripting finding.

The scanner used to write [CSP-MISSING] lines into findings/<t>/xss/, and the
reporter maps xss/ → vtype "xss", so each line rendered as a CVSS-6.1 "Cross-Site
Scripting" finding (a false positive — a missing CSP header mitigates XSS but is
not itself an XSS vuln). v10.2.1 routes it to misconfig/ at LOW severity.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from reporter import load_findings

_REPO = os.path.join(os.path.dirname(__file__), "..")


def test_csp_missing_renders_as_low_misconfig_not_xss(tmp_path):
    md = tmp_path / "misconfig"
    md.mkdir()
    (md / "csp_missing.txt").write_text(
        "[LOW] Missing Content-Security-Policy (CSP) response header — http://x.test\n"
    )
    findings = load_findings(str(tmp_path))
    assert findings, "the CSP-missing line must produce a finding"
    # Never rendered as XSS …
    assert all(f.get("vtype") != "xss" for f in findings)
    # … and present as a LOW security-misconfiguration.
    assert any(f.get("vtype") == "misconfig" and f.get("severity") == "low" for f in findings)


def test_scanner_writes_csp_to_misconfig_not_xss():
    with open(os.path.join(_REPO, "scanner.sh"), errors="replace") as f:
        s = f.read()
    # The CSP outputs must live under misconfig/, not xss/.
    assert 'CSP_MISSING="$FINDINGS_DIR/misconfig/csp_missing.txt"' in s
    assert 'CSP_WEAK="$FINDINGS_DIR/misconfig/csp_weak.txt"' in s
    assert "/xss/csp_missing.txt" not in s
    assert "/xss/csp_weak.txt" not in s
