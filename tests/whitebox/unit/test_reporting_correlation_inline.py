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


def test_render_inline_compacts_full_port_range():
    """SG analyzer emits 65536 ports for IpProtocol=-1; renderer must compact, not bloat."""
    ctx = CloudContext(account_id="1", region="us-east-1", service="ec2",
                       arn="arn:ec2:i-2", exposed_ports=list(range(0, 65536)))
    f = Finding(id="x", source="exposure", rule_id="exposure.public_all_traffic",
                severity=Severity.HIGH, title="t", description="d",
                asset=None, evidence_path=Path("/tmp"), cloud_context=ctx)
    html = render_for_finding(f)
    assert "all ports" in html
    # Must not embed 65,536 individual numbers
    assert len(html) < 5_000


def test_render_inline_compacts_contiguous_port_range():
    ctx = CloudContext(account_id="1", region="us-east-1", service="ec2",
                       arn="arn:ec2:i-3", exposed_ports=[80, 81, 82, 443, 8080, 8081])
    f = Finding(id="x", source="exposure", rule_id="exposure.test",
                severity=Severity.HIGH, title="t", description="d",
                asset=None, evidence_path=Path("/tmp"), cloud_context=ctx)
    html = render_for_finding(f)
    assert "80-82" in html
    assert "443" in html
    assert "8080-8081" in html


def test_render_inline_escapes_malformed_port_strings():
    """If exposed_ports somehow contains a string with HTML, must be escaped."""
    ctx = CloudContext(account_id="1", region="us-east-1", service="ec2",
                       arn="arn:ec2:i-4", exposed_ports=["<script>alert(1)</script>"])
    f = Finding(id="x", source="exposure", rule_id="exposure.test",
                severity=Severity.HIGH, title="t", description="d",
                asset=None, evidence_path=Path("/tmp"), cloud_context=ctx)
    html = render_for_finding(f)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_render_inline_escapes_malformed_exposed_cidrs():
    ctx = CloudContext(account_id="1", region="us-east-1", service="ec2",
                       arn="arn:ec2:i-5", exposed_cidrs=["<img onerror=alert(1)>"])
    f = Finding(id="x", source="exposure", rule_id="exposure.test",
                severity=Severity.HIGH, title="t", description="d",
                asset=None, evidence_path=Path("/tmp"), cloud_context=ctx)
    html = render_for_finding(f)
    assert "<img" not in html
    assert "&lt;img" in html
