from unittest.mock import MagicMock, patch
import pytest
from whitebox.profiles import CloudProfile, validate, probe_permissions


def test_validate_calls_sts(tmp_path):
    fake_session = MagicMock()
    fake_sts = MagicMock()
    fake_sts.get_caller_identity.return_value = {
        "UserId": "AID", "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:user/audit",
    }
    fake_session.client.return_value = fake_sts
    fake_session.get_available_regions.return_value = ["us-east-1", "ap-south-1"]

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
