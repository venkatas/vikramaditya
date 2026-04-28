import boto3
import pytest
from moto import mock_aws
from whitebox.profiles import CloudProfile
from whitebox.secrets.sources.secretsmanager import scan as scan_sm


@pytest.fixture
def profile(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    return CloudProfile(name="t", account_id="111", arn="a", regions=["us-east-1"])


@mock_aws
def test_scan_secretsmanager_with_get_value_permission(profile):
    sm = boto3.client("secretsmanager", region_name="us-east-1")
    sm.create_secret(Name="prod/db", SecretString="AKIAIOSFODNN7EXAMPLE")
    profile._session = boto3.Session(region_name="us-east-1")
    profile.permission_probe = {"secretsmanager_get_value": True}
    findings = scan_sm(profile)
    assert any("prod/db" in f.description for f in findings)


@mock_aws
def test_scan_secretsmanager_metadata_only_when_no_permission(profile):
    sm = boto3.client("secretsmanager", region_name="us-east-1")
    sm.create_secret(Name="prod/db", SecretString="AKIAIOSFODNN7EXAMPLE")
    profile._session = boto3.Session(region_name="us-east-1")
    profile.permission_probe = {"secretsmanager_get_value": False}
    findings = scan_sm(profile)
    # Should emit info finding documenting permission gap, no values pulled
    assert any(f.rule_id == "secrets.secretsmanager.permission_gap" for f in findings)
