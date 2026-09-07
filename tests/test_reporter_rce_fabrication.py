"""Regression: reporter must NOT fabricate CRITICAL findings from scanner STATE files.

Real engagement (2026-07-19): the report rendered 16 × "Remote Code Execution / CRITICAL /
CVSS 9.8" while the scanner's own markers said `Confirmed RCE: 0` and `SKIPPED`. Root cause:
load_findings' generic Method-1 loop promotes EVERY non-comment .txt line in a mapped subdir
to a finding — so rce/summary.txt tally lines ("Java targets: 2"), rce/java_targets.txt
candidate URLs, and rce/tomcat_put_rce.txt "SKIPPED (...)" lines all became CRITICAL RCEs.

Fail-closed fix: per-subdir summary.txt + *_targets.txt candidate lists are non-findings, and
state-shaped lines (SKIPPED / N/A / "Label: <count>" tallies) are suppressed — WITHOUT dropping
a genuinely confirmed finding.
"""
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import reporter  # noqa: E402


def _rce_findings(findings):
    return [f for f in findings if f.get("vtype") == "rce"]


def test_state_files_do_not_fabricate_rce(tmp_path):
    d = tmp_path / "findings"
    rce = d / "rce"
    rce.mkdir(parents=True)
    (rce / "summary.txt").write_text(
        "Target domain: x.example\nJava targets: 2\nTomcat targets: 0\n"
        "Confirmed RCE: 0\nJBoss exposed consoles: 0\nLog4Shell OOB callbacks: 0\n"
        "Nuclei RCE hits: 0\n")
    (rce / "java_targets.txt").write_text("https://x.example\nhttps://stage.x.example\n")
    (rce / "tomcat_put_rce.txt").write_text(
        "# CVE-2017-12615 Tomcat PUT RCE\n"
        "## PUT https://x.example/test.jsp\n"
        "SKIPPED (no Tomcat marker and no PUT method advertised)\n"
        "## PUT https://stage.x.example/test.jsp\n"
        "SKIPPED (no Tomcat marker and no PUT method advertised)\n")
    (rce / "log4shell.txt").write_text("# Log4Shell probe\n# OOB: ldap://x.scan.invalid\n")

    findings = reporter.load_findings(str(d))
    fab = _rce_findings(findings)
    assert fab == [], f"fabricated {len(fab)} RCE findings from state/candidate files: {[f.get('raw') for f in fab]}"


def test_confirmed_rce_is_still_reported(tmp_path):
    d = tmp_path / "findings"
    rce = d / "rce"
    rce.mkdir(parents=True)
    # a genuinely confirmed RCE (meterpreter session / verified PoC) MUST survive the filter
    (rce / "confirmed.txt").write_text(
        "[POC-RCE-CONFIRMED] command output returned for https://x.example/shell.jsp\n")
    findings = reporter.load_findings(str(d))
    assert _rce_findings(findings), "a genuinely CONFIRMED RCE was suppressed by the fix"


def test_probe_status_lines_do_not_fabricate_rce(tmp_path):
    """Real engagement (2026-07-25): log4shell.txt / jboss_admin.txt hold HTTP-status
    PROBE-RESPONSE echoes ("[302] https://h | header=User-Agent"), not confirmations.
    hunt.py writes the real signal elsewhere (the '# OOB CALLBACKS' section /
    JBOSS_EXPOSED_*.txt / named [POC-RCE-CONFIRMED] markers). The reporter promoted each
    [NNN]-prefixed probe echo to a CRITICAL 9.8 RCE — 10 fake criticals on one host —
    despite the phase's own 'Confirmed RCE: 0' / 'Log4Shell OOB callbacks: 0'."""
    d = tmp_path / "findings"
    rce = d / "rce"
    rce.mkdir(parents=True)
    (rce / "log4shell.txt").write_text(
        "# Log4Shell (CVE-2021-44228) — x.example\n# OOB: ldap://x.oast.invalid\n\n"
        "[302] https://helpdesk.x.example | header=User-Agent\n"
        "[302] https://helpdesk.x.example | header=X-Forwarded-For\n"
        "[404] https://helpdesk.x.example/login | POST body log4shell\n"
        "[200] https://helpdesk.x.example/j_security_check | POST body log4shell\n")
    (rce / "jboss_admin.txt").write_text(
        "# JBoss Admin Console Exposure — x.example\n"
        "[200] https://helpdesk.x.example/web-console/\n"
        "[401] https://helpdesk.x.example/admin-console/ — auth required (try default creds)\n")
    findings = reporter.load_findings(str(d))
    fab = _rce_findings(findings)
    assert fab == [], f"fabricated {len(fab)} RCE findings from probe-status echoes: {[f.get('raw') for f in fab]}"


def test_summary_txt_never_a_finding_any_subdir(tmp_path):
    # summary.txt is a per-phase tally in EVERY subdir — never a finding
    d = tmp_path / "findings"
    sqli = d / "sqli"
    sqli.mkdir(parents=True)
    (sqli / "summary.txt").write_text("SQLi candidates: 5\nVerified SQLi: 0\n")
    findings = reporter.load_findings(str(d))
    assert not any(f.get("vtype") == "sqli" for f in findings), "summary.txt tally promoted to a finding"
