from unittest.mock import patch, MagicMock
from pathlib import Path
from whitebox.profiles import CloudProfile
from whitebox.secrets.scanner import run_all


def test_run_all_dispatches_to_all_sources(tmp_path):
    profile = CloudProfile(name="t", account_id="111", arn="a", regions=["us-east-1"])
    with patch("whitebox.secrets.scanner.lambda_env.scan", return_value=[]) as p_l, \
         patch("whitebox.secrets.scanner.ssm.scan", return_value=[]) as p_s, \
         patch("whitebox.secrets.scanner.secretsmanager.scan", return_value=[]) as p_sm, \
         patch("whitebox.secrets.scanner.ec2_userdata.scan", return_value=[]) as p_ud, \
         patch("whitebox.secrets.scanner.s3.scan", return_value=[]) as p_s3, \
         patch("whitebox.secrets.scanner.cloudwatch_logs.scan", return_value=[]) as p_lg:
        run_all(profile, tmp_path, target_buckets=["b"], target_log_groups=["g"])
        p_l.assert_called_once_with(profile, secrets_dir=tmp_path)
        p_s.assert_called_once_with(profile, secrets_dir=tmp_path)
        p_sm.assert_called_once_with(profile, secrets_dir=tmp_path)
        p_ud.assert_called_once_with(profile, secrets_dir=tmp_path)
        p_s3.assert_called_once_with(profile, target_buckets=["b"], secrets_dir=tmp_path)
        p_lg.assert_called_once_with(profile, target_groups=["g"], secrets_dir=tmp_path)


def test_run_all_skips_optional_sources_when_no_targets(tmp_path):
    profile = CloudProfile(name="t", account_id="111", arn="a", regions=["us-east-1"])
    with patch("whitebox.secrets.scanner.lambda_env.scan", return_value=[]), \
         patch("whitebox.secrets.scanner.ssm.scan", return_value=[]), \
         patch("whitebox.secrets.scanner.secretsmanager.scan", return_value=[]), \
         patch("whitebox.secrets.scanner.ec2_userdata.scan", return_value=[]), \
         patch("whitebox.secrets.scanner.s3.scan", return_value=[]) as p_s3, \
         patch("whitebox.secrets.scanner.cloudwatch_logs.scan", return_value=[]) as p_lg:
        run_all(profile, tmp_path)
        p_s3.assert_not_called()
        p_lg.assert_not_called()


def test_run_all_creates_secrets_dir(tmp_path):
    profile = CloudProfile(name="t", account_id="111", arn="a", regions=["us-east-1"])
    secrets_dir = tmp_path / "new_secrets"
    with patch("whitebox.secrets.scanner.lambda_env.scan", return_value=[]), \
         patch("whitebox.secrets.scanner.ssm.scan", return_value=[]), \
         patch("whitebox.secrets.scanner.secretsmanager.scan", return_value=[]), \
         patch("whitebox.secrets.scanner.ec2_userdata.scan", return_value=[]):
        run_all(profile, secrets_dir)
    assert secrets_dir.exists()
