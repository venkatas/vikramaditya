from unittest.mock import patch
import pytest
from pathlib import Path
from whitebox.orchestrator import (
    run_for_profile, _persist_phase_findings, _load_phase_findings,
)
from whitebox.models import (
    Finding, Severity, CloudContext, Asset, BlastRadius, Chain,
)


def test_run_for_profile_requires_allowlist():
    with pytest.raises(ValueError, match="authorized_allowlist"):
        run_for_profile(profile_name="x", session_dir=Path("/tmp/none"),
                        authorized_allowlist=None)


def test_refresh_cleans_stale_phase_artifacts(tmp_path):
    """--refresh must wipe stale phase artifact dirs, not just bust the cache."""
    import boto3

    account_dir = tmp_path / "session" / "cloud" / "123456789012"
    # Seed stale artifacts
    (account_dir / "secrets").mkdir(parents=True)
    (account_dir / "secrets" / "stale_secret.json").write_text("{}")
    (account_dir / "prowler").mkdir()
    (account_dir / "prowler" / "old_output.json").write_text("[]")
    (account_dir / "phase_prowler_findings.json").write_text("[]")

    def fake_validate(profile):
        profile.account_id = "123456789012"
        profile.arn = "arn:aws:iam::123456789012:user/test"
        profile.regions = []
        profile._session = boto3.Session(region_name="us-east-1")
        profile.permission_probe = {"simulate_principal_policy": True}
        return profile

    with patch("whitebox.orchestrator.validate", side_effect=fake_validate), \
         patch("whitebox.orchestrator.collector.collect_all"), \
         patch("whitebox.orchestrator.prowler_runner.run", side_effect=Exception("skip")), \
         patch("whitebox.orchestrator.build_graph", side_effect=Exception("skip")), \
         patch("whitebox.orchestrator.run_secrets", return_value=[]), \
         patch("whitebox.orchestrator.route53.in_scope_domains", return_value=["test.local"]):
        run_for_profile(profile_name="test", session_dir=tmp_path / "session",
                        refresh=True, brain=None, authorized_allowlist=["*"])

    # Stale files must be gone
    assert not (account_dir / "secrets" / "stale_secret.json").exists()
    assert not (account_dir / "prowler" / "old_output.json").exists()
    assert not (account_dir / "phase_prowler_findings.json").exists()


def test_phase_findings_full_roundtrip(tmp_path):
    """Cached re-run must NOT lose asset, blast_radius, chain, brain_narrative.

    Regression for the silent fidelity drop in _load_phase_findings: it used to
    reconstruct findings with asset=None and strip blast_radius/chain/narrative,
    so a re-run within the 24h cache TTL produced a weaker report than the first
    run with no marker that context had been dropped.
    """
    account_dir = tmp_path / "cloud" / "123456789012"
    account_dir.mkdir(parents=True)

    blast = BlastRadius(
        principal_arn="arn:aws:iam::123456789012:role/acme-admin",
        s3_buckets=["acme-bucket-a", "acme-bucket-b"],
        kms_keys=["arn:aws:kms:us-east-1:123456789012:key/abc"],
        lambdas=["arn:aws:lambda:us-east-1:123456789012:function:f1"],
        assumable_roles=["arn:aws:iam::123456789012:role/other"],
        assumable_users=["arn:aws:iam::123456789012:user/u1"],
        regions=["us-east-1", "ap-south-1"],
    )
    ctx = CloudContext(
        account_id="123456789012", region="us-east-1", service="iam",
        arn="arn:aws:iam::123456789012:role/acme-admin",
        iam_role_arn="arn:aws:iam::123456789012:role/acme-admin",
        blast_radius=blast, behind_waf=False,
        exposed_cidrs=["0.0.0.0/0"], exposed_ports=[22, 3389],
    )
    asset = Asset(
        arn="arn:aws:iam::123456789012:role/acme-admin", service="iam",
        account_id="123456789012", region="us-east-1", name="acme-admin",
        tags={"internet_reachable": True}, public_dns="host.example.invalid",
        public_ip="203.0.113.10",
    )
    chain = Chain(
        trigger_finding_id="prowler-imdsv1",
        cloud_asset_arn="arn:aws:ec2:us-east-1:123456789012:instance/i-0abc",
        iam_path=["arn:aws:iam::123456789012:role/acme-admin"],
        promoted_severity=Severity.CRITICAL,
        promotion_rule="chain.imdsv1+pass_role_to_admin",
        narrative="IMDSv1 + PassRole to admin yields account takeover.",
    )
    finding = Finding(
        id="f1", source="pmapper", rule_id="iam_privesc_pass_role",
        severity=Severity.HIGH, title="PassRole privesc",
        description="role can pass an admin role",
        asset=asset, evidence_path=Path("pmapper/iam_privesc.json"),
        cloud_context=ctx, chain=chain,
        brain_narrative="Operator should rotate keys immediately.",
    )

    _persist_phase_findings(account_dir, "iam", [finding])
    reloaded = _load_phase_findings(account_dir, "iam")

    assert len(reloaded) == 1
    rf = reloaded[0]
    # Scalar + severity round-trip
    assert rf.id == "f1"
    assert rf.severity is Severity.HIGH
    assert rf.brain_narrative == "Operator should rotate keys immediately."
    # Asset must survive
    assert rf.asset is not None
    assert rf.asset.name == "acme-admin"
    assert rf.asset.public_ip == "203.0.113.10"
    assert rf.asset.tags == {"internet_reachable": True}
    # CloudContext + blast_radius must survive
    assert rf.cloud_context is not None
    assert rf.cloud_context.exposed_ports == [22, 3389]
    assert rf.cloud_context.blast_radius is not None
    assert rf.cloud_context.blast_radius.total_resources() == 6
    assert rf.cloud_context.blast_radius.s3_buckets == ["acme-bucket-a", "acme-bucket-b"]
    # Chain (severity promotion) must survive
    assert rf.chain is not None
    assert rf.chain.promoted_severity is Severity.CRITICAL
    assert rf.chain.promotion_rule == "chain.imdsv1+pass_role_to_admin"


def test_phase_findings_roundtrip_minimal(tmp_path):
    """Findings with no asset/context/chain still reload cleanly (no crash)."""
    account_dir = tmp_path / "cloud" / "123456789012"
    account_dir.mkdir(parents=True)
    f = Finding(
        id="m1", source="prowler", rule_id="s3_bucket_public",
        severity=Severity.MEDIUM, title="public bucket",
        description="bucket is public", asset=None,
        evidence_path=Path("prowler/s3.json"),
    )
    _persist_phase_findings(account_dir, "prowler", [f])
    reloaded = _load_phase_findings(account_dir, "prowler")
    assert len(reloaded) == 1
    assert reloaded[0].asset is None
    assert reloaded[0].cloud_context is None
    assert reloaded[0].chain is None
    assert reloaded[0].severity is Severity.MEDIUM
