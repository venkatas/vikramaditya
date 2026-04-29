import boto3
import pytest
from moto import mock_aws
from whitebox.profiles import CloudProfile
from whitebox.secrets.sources.ssm import scan as scan_ssm


@pytest.fixture
def profile(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    return CloudProfile(name="t", account_id="111", arn="a", regions=["us-east-1"])


@mock_aws
def test_scan_ssm_finds_aws_key_in_string_param(profile):
    ssm = boto3.client("ssm", region_name="us-east-1")
    ssm.put_parameter(Name="/app/AWS_KEY", Type="String",
                      Value="AKIAIOSFODNN7EXAMPLE")
    profile._session = boto3.Session(region_name="us-east-1")
    findings = scan_ssm(profile)
    assert any("/app/AWS_KEY" in f.description for f in findings)


@mock_aws
def test_scan_ssm_handles_secure_string_with_decrypt_permission(profile):
    ssm = boto3.client("ssm", region_name="us-east-1")
    ssm.put_parameter(Name="/secret/key", Type="SecureString",
                      Value="AKIAIOSFODNN7EXAMPLE")
    profile._session = boto3.Session(region_name="us-east-1")
    findings = scan_ssm(profile)
    assert any("/secret/key" in f.description for f in findings)


@mock_aws
def test_scan_ssm_skips_non_secret_values(profile):
    ssm = boto3.client("ssm", region_name="us-east-1")
    ssm.put_parameter(Name="/app/log_level", Type="String", Value="INFO")
    profile._session = boto3.Session(region_name="us-east-1")
    findings = scan_ssm(profile)
    assert findings == []
