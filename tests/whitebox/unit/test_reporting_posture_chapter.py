from pathlib import Path
from whitebox.reporting.posture_chapter import render
from whitebox.models import Finding, Severity, CloudContext


def test_render_returns_html_with_account_summary():
    findings = [Finding(id="f1", source="prowler", rule_id="iam_root_mfa_enabled",
                        severity=Severity.CRITICAL, title="Root MFA off",
                        description="...", asset=None, evidence_path=Path("x"),
                        cloud_context=CloudContext(account_id="111", region="us-east-1",
                                                   service="iam", arn=""))]
    html = render(account_id="111", findings=findings, executive_summary="All good.")
    assert "<h2" in html
    assert "111" in html
    assert "Critical" in html or "critical" in html
    assert "Root MFA off" in html


def test_render_handles_no_findings():
    html = render(account_id="111", findings=[], executive_summary="")
    assert "111" in html
    assert "no findings" in html.lower() or "0 findings" in html.lower()
