from unittest.mock import MagicMock, patch
import pytest
from whitebox.profiles import CloudProfile, validate, probe_permissions


def test_validate_calls_sts(tmp_path):
    fake_session = MagicMock()
    fake_sts = MagicMock()
    fake_sts.get_caller_identity.return_value = {
        "UserId": "AID", "Account": "443370705278",
        "Arn": "arn:aws:iam::443370705278:user/venkata.satish-audit",
    }
    fake_session.client.return_value = fake_sts
    fake_session.get_available_regions.return_value = ["us-east-1", "ap-south-1"]

    with patch("boto3.Session", return_value=fake_session):
        prof = validate(CloudProfile(name="adf-erp"))

    assert prof.account_id == "443370705278"
    assert prof.arn.endswith("venkata.satish-audit")
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
