from pathlib import Path
import pytest
from whitebox.models import (
    Severity, Asset, CloudContext, Finding, Chain, BlastRadius
)


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO


def test_finding_requires_rule_id():
    with pytest.raises(ValueError, match="rule_id"):
        Finding(
            id="f1", source="prowler", rule_id="",
            severity=Severity.HIGH, title="t", description="d",
            asset=None, evidence_path=Path("/tmp/x"),
        )


def test_finding_round_trip_to_dict():
    f = Finding(
        id="f1", source="prowler", rule_id="check_iam_root_mfa",
        severity=Severity.HIGH, title="Root MFA disabled",
        description="root user lacks MFA",
        asset=None, evidence_path=Path("/tmp/x"),
    )
    d = f.to_dict()
    assert d["rule_id"] == "check_iam_root_mfa"
    assert d["severity"] == "High"
    assert d["source"] == "prowler"


def test_chain_severity_promotion_documents_rule():
    c = Chain(
        trigger_finding_id="f1", cloud_asset_arn="arn:aws:ec2:...",
        iam_path=["arn:role/web", "arn:role/admin"],
        promoted_severity=Severity.CRITICAL,
        promotion_rule="chain.imdsv1+pass_role_to_admin",
        narrative="",
    )
    assert c.promotion_rule.startswith("chain.")


def test_blast_radius_aggregates():
    b = BlastRadius(
        principal_arn="arn:aws:iam::1:role/r",
        s3_buckets=["a", "b"], kms_keys=["k1"],
        lambdas=[], assumable_roles=["arn:role/admin"], regions=["us-east-1"],
    )
    assert b.total_resources() == 4


def test_asset_internet_reachable_default_false():
    a = Asset(arn="arn:aws:ec2:...", service="ec2", account_id="1",
              region="us-east-1", name="i-0abc", tags={})
    assert a.tags.get("internet_reachable") is None
