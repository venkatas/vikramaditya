import boto3
import pytest
import time
from moto import mock_aws
from whitebox.profiles import CloudProfile
from whitebox.secrets.sources.cloudwatch_logs import scan as scan_logs


@pytest.fixture
def profile(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    return CloudProfile(name="t", account_id="111", arn="a", regions=["us-east-1"])


@mock_aws
def test_scan_logs_finds_aws_key_in_event(profile):
    logs = boto3.client("logs", region_name="us-east-1")
    logs.create_log_group(logGroupName="/aws/lambda/leaky")
    logs.create_log_stream(logGroupName="/aws/lambda/leaky", logStreamName="s1")
    logs.put_log_events(
        logGroupName="/aws/lambda/leaky", logStreamName="s1",
        logEvents=[{"timestamp": int(time.time() * 1000),
                    "message": "key=AKIAIOSFODNN7EXAMPLE"}],
    )
    profile._session = boto3.Session(region_name="us-east-1")
    findings = scan_logs(profile, target_groups=["/aws/lambda/leaky"])
    assert any("AKIA" in f.description or "/aws/lambda/leaky" in f.description for f in findings)
