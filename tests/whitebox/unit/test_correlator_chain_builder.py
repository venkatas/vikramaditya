from pathlib import Path
from whitebox.correlator.chain_builder import build_chains
from whitebox.correlator.severity import promote
from whitebox.models import Finding, Severity, Asset, CloudContext
from whitebox.iam.graph import IAMGraph

FIX = Path(__file__).parents[1] / "integration" / "fixtures" / "pmapper_graph_sample.json"


def test_promote_returns_critical_for_path_to_admin():
    promoted = promote(base=Severity.MEDIUM, has_imds=True, reaches_admin=True)
    assert promoted == Severity.CRITICAL


def test_promote_keeps_base_when_no_chain():
    promoted = promote(base=Severity.MEDIUM, has_imds=False, reaches_admin=False)
    assert promoted == Severity.MEDIUM


def test_build_chains_emits_chain_when_ssrf_on_ec2_with_role_to_admin():
    graph = IAMGraph.load(FIX)
    asset = Asset(arn="arn:aws:ec2:us-east-1:111:instance/i-1", service="ec2",
                  account_id="111", region="us-east-1", name="i-1",
                  tags={"iam_role_arn": "arn:aws:iam::111:role/web-prod"},
                  public_ip="1.2.3.4")
    bb = Finding(id="bb1", source="blackbox", rule_id="ssrf.imds",
                 severity=Severity.MEDIUM, title="SSRF on web.example.com",
                 description="server fetches user URL",
                 asset=asset, evidence_path=Path("/tmp"))
    chains = build_chains([bb], cloud_assets=[asset], iam_graph=graph,
                          host_to_asset={"web.example.com": asset})
    assert len(chains) == 1
    c = chains[0]
    assert c.promoted_severity == Severity.CRITICAL
    assert "admin" in c.iam_path[-1]
    assert c.promotion_rule.startswith("chain.")


def test_build_chains_ssrf_basic_promotes_to_high_not_critical():
    graph = IAMGraph.load(FIX)
    asset = Asset(arn="arn:aws:ec2:us-east-1:111:instance/i-2", service="ec2",
                  account_id="111", region="us-east-1", name="i-2",
                  tags={"iam_role_arn": "arn:aws:iam::111:role/web-prod"},
                  public_ip="2.3.4.5")
    bb = Finding(id="bb2", source="blackbox", rule_id="ssrf.basic",
                 severity=Severity.MEDIUM, title="generic SSRF", description="x",
                 asset=asset, evidence_path=Path("/tmp"))
    chains = build_chains([bb], cloud_assets=[asset], iam_graph=graph,
                          host_to_asset={"2.3.4.5": asset})
    assert len(chains) == 1
    # ssrf.basic without IMDS evidence promotes to HIGH, not CRITICAL
    assert chains[0].promoted_severity == Severity.HIGH
