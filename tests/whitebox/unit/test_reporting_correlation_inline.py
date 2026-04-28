from pathlib import Path
from whitebox.reporting.correlation_inline import render_for_finding
from whitebox.models import Finding, Severity, Chain, CloudContext, BlastRadius


def test_render_inline_includes_blast_radius_and_chain():
    ctx = CloudContext(account_id="1", region="us-east-1", service="ec2",
                       arn="arn:ec2:i-1", iam_role_arn="arn:role/web",
                       blast_radius=BlastRadius(principal_arn="arn:role/web",
                                                s3_buckets=["b1"], kms_keys=[],
                                                lambdas=[], assumable_roles=["arn:role/admin"],
                                                assumable_users=[], regions=[]))
    chain = Chain(trigger_finding_id="bb1", cloud_asset_arn="arn:ec2:i-1",
                  iam_path=["arn:role/web", "arn:role/admin"],
                  promoted_severity=Severity.CRITICAL,
                  promotion_rule="chain.ssrf+pmapper.1_hop",
                  narrative="SSRF → role → admin")
    f = Finding(id="bb1", source="blackbox", rule_id="ssrf.basic",
                severity=Severity.MEDIUM, title="SSRF", description="x",
                asset=None, evidence_path=Path("/tmp"),
                cloud_context=ctx, chain=chain)
    html = render_for_finding(f)
    assert "Cloud context" in html
    assert "arn:role/web" in html
    assert "Critical" in html or "critical" in html
    assert "blast" in html.lower()
