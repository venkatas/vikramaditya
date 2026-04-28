import boto3
import pytest
from moto import mock_aws
from whitebox.profiles import CloudProfile
from whitebox.secrets.sources.lambda_env import scan as scan_lambda


@pytest.fixture
def profile(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    return CloudProfile(name="t", account_id="111", arn="a", regions=["us-east-1"])


@mock_aws
def test_scan_lambda_finds_aws_key_in_env(profile):
    iam = boto3.client("iam")
    iam.create_role(RoleName="r", AssumeRolePolicyDocument="{}")
    role_arn = iam.get_role(RoleName="r")["Role"]["Arn"]
    lam = boto3.client("lambda", region_name="us-east-1")
    lam.create_function(
        FunctionName="leaky", Runtime="python3.11", Role=role_arn,
        Handler="x.handler",
        Code={"ZipFile": b"def handler(e,c):pass"},
        Environment={"Variables": {"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"}},
    )
    profile._session = boto3.Session(region_name="us-east-1")
    findings = scan_lambda(profile)
    assert len(findings) >= 1
    f = findings[0]
    assert f.source == "secrets"
    assert f.rule_id.startswith("secrets.lambda_env.")
    assert "leaky" in f.description
