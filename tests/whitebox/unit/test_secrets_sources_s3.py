import boto3
import pytest
from moto import mock_aws
from whitebox.profiles import CloudProfile
from whitebox.secrets.sources.s3 import scan as scan_s3


@pytest.fixture
def profile(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    return CloudProfile(name="t", account_id="111", arn="a", regions=["us-east-1"])


@mock_aws
def test_scan_s3_finds_secret_in_targeted_bucket(profile):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="config-backups")
    s3.put_object(Bucket="config-backups", Key="db.env",
                  Body=b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
    profile._session = boto3.Session(region_name="us-east-1")
    findings = scan_s3(profile, target_buckets=["config-backups"])
    assert any("config-backups/db.env" in f.description for f in findings)


@mock_aws
def test_scan_s3_skips_buckets_not_in_targets(profile):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="random")
    s3.put_object(Bucket="random", Key="x", Body=b"AKIAIOSFODNN7EXAMPLE")
    profile._session = boto3.Session(region_name="us-east-1")
    findings = scan_s3(profile, target_buckets=["different"])
    assert findings == []
