from unittest.mock import MagicMock, patch
import pytest
from whitebox.profiles import CloudProfile, validate, probe_permissions


def _build_fake_session(account="123456789012", enabled_regions=None):
    """Return a fake boto3 Session whose ec2.describe_regions returns
    the requested enabled-regions list (default: us-east-1, ap-south-1).
    Also wires sts.get_caller_identity, secretsmanager.list_secrets,
    logs.describe_log_groups, iam.simulate_principal_policy."""
    if enabled_regions is None:
        enabled_regions = ["us-east-1", "ap-south-1"]

    fake_session = MagicMock()
    fake_sts = MagicMock()
    fake_sts.get_caller_identity.return_value = {
        "UserId": "AID", "Account": account,
        "Arn": f"arn:aws:iam::{account}:user/audit",
    }
    fake_ec2 = MagicMock()
    fake_ec2.describe_regions.return_value = {
        "Regions": [{"RegionName": r, "OptInStatus": "opted-in" if r in ("ap-east-1", "me-south-1") else "opt-in-not-required"} for r in enabled_regions]
    }
    fake_iam = MagicMock()
    fake_iam.simulate_principal_policy.return_value = {"EvaluationResults": []}
    fake_secrets = MagicMock()
    fake_secrets.list_secrets.return_value = {"SecretList": []}
    fake_logs = MagicMock()
    fake_logs.describe_log_groups.return_value = {"logGroups": []}

    def fake_client(svc, **kw):
        return {
            "sts": fake_sts, "ec2": fake_ec2, "iam": fake_iam,
            "secretsmanager": fake_secrets, "logs": fake_logs,
        }[svc]

    fake_session.client.side_effect = fake_client
    # Legacy fallback path for envs where describe_regions fails:
    fake_session.get_available_regions.return_value = ["us-east-1", "ap-south-1", "me-south-1"]
    return fake_session


def test_validate_calls_sts(tmp_path):
    fake_session = _build_fake_session()
    with patch("boto3.Session", return_value=fake_session):
        prof = validate(CloudProfile(name="adf-erp"))

    assert prof.account_id == "123456789012"
    assert prof.arn.endswith("audit")
    assert "us-east-1" in prof.regions


def test_validate_raises_on_sts_failure():
    fake_session = MagicMock()
    fake_session.client.return_value.get_caller_identity.side_effect = Exception("denied")
    with patch("boto3.Session", return_value=fake_session):
        with pytest.raises(RuntimeError, match="STS"):
            validate(CloudProfile(name="bad"))


def test_probe_permissions_records_each():
    fake_session = MagicMock()
    fake_iam = MagicMock()
    fake_iam.simulate_principal_policy.return_value = {"EvaluationResults": [{"EvalDecision": "allowed"}]}
    fake_secrets = MagicMock()
    fake_secrets.list_secrets.return_value = {"SecretList": []}
    fake_logs = MagicMock()
    fake_logs.describe_log_groups.return_value = {"logGroups": []}

    fake_session.client.side_effect = lambda svc, **kw: {
        "iam": fake_iam, "secretsmanager": fake_secrets, "logs": fake_logs,
    }[svc]

    probe = probe_permissions(fake_session, principal_arn="arn:aws:iam::1:user/u")
    assert probe["simulate_principal_policy"] is True
    assert probe["secretsmanager_list"] is True
    assert probe["logs_describe"] is True


def test_probe_permissions_lazy_flags_default_false():
    """secretsmanager_get_value and kms_decrypt are lazy — start False, set later."""
    fake_session = MagicMock()
    fake_session.client.return_value.simulate_principal_policy.side_effect = Exception("denied")
    fake_session.client.return_value.list_secrets.side_effect = Exception("denied")
    fake_session.client.return_value.describe_log_groups.side_effect = Exception("denied")

    probe = probe_permissions(fake_session, principal_arn="arn:aws:iam::1:user/u")
    assert probe["secretsmanager_get_value"] is False  # lazy — never probed here
    assert probe["kms_decrypt"] is False               # lazy — never probed here
    # And the eager probes correctly recorded denial:
    assert probe["simulate_principal_policy"] is False
    assert probe["secretsmanager_list"] is False
    assert probe["logs_describe"] is False


def test_normalize_to_iam_arn_strips_assumed_role_session():
    from whitebox.profiles import _normalize_to_iam_arn
    sts_arn = "arn:aws:sts::123456789012:assumed-role/AdminRole/i-0abc"
    assert _normalize_to_iam_arn(sts_arn) == "arn:aws:iam::123456789012:role/AdminRole"


def test_normalize_to_iam_arn_passes_through_iam_user():
    from whitebox.profiles import _normalize_to_iam_arn
    iam_arn = "arn:aws:iam::123456789012:user/audit"
    assert _normalize_to_iam_arn(iam_arn) == iam_arn


def test_validate_filters_to_enabled_regions_via_describe_regions(monkeypatch):
    """profile.regions must contain only regions returned by ec2 describe-regions
    with opt-in-status in (opt-in-not-required, opted-in). Opt-in regions the
    account has NOT enabled hang boto3 in SYN_SENT and must not appear."""
    monkeypatch.delenv("WHITEBOX_REGIONS", raising=False)
    fake_session = _build_fake_session(enabled_regions=["us-east-1", "ap-south-1", "eu-west-1"])
    with patch("boto3.Session", return_value=fake_session):
        prof = validate(CloudProfile(name="t"))
    assert sorted(prof.regions) == ["ap-south-1", "eu-west-1", "us-east-1"]
    # The unsafe opt-in region from get_available_regions must NOT have leaked in
    assert "me-south-1" not in prof.regions


def test_validate_honours_WHITEBOX_REGIONS_env_override(monkeypatch):
    """WHITEBOX_REGIONS comma-separated env var is the authoritative override —
    operators can pin to a specific region set regardless of account opt-in state."""
    monkeypatch.setenv("WHITEBOX_REGIONS", "us-east-1, ap-south-1 , eu-west-1")
    fake_session = _build_fake_session(enabled_regions=["us-east-1", "ap-south-1", "eu-west-1", "us-west-2"])
    with patch("boto3.Session", return_value=fake_session):
        prof = validate(CloudProfile(name="t"))
    assert sorted(prof.regions) == ["ap-south-1", "eu-west-1", "us-east-1"]
    # describe_regions must NOT be called when WHITEBOX_REGIONS is set
    assert not fake_session.client("ec2").describe_regions.called


def test_validate_falls_back_when_describe_regions_denied(monkeypatch):
    """If ec2 describe-regions is denied (rare on read-only audit profiles, but
    possible), fall back to session.get_available_regions to preserve liveness."""
    monkeypatch.delenv("WHITEBOX_REGIONS", raising=False)
    fake_session = _build_fake_session()
    fake_session.client("ec2").describe_regions.side_effect = Exception("AccessDenied")
    with patch("boto3.Session", return_value=fake_session):
        prof = validate(CloudProfile(name="t"))
    # Falls back to get_available_regions content
    assert "us-east-1" in prof.regions
    assert "ap-south-1" in prof.regions
