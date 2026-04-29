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


@mock_aws
def test_scan_s3_skips_generic_high_entropy(profile):
    """High-entropy random data in S3 (e.g. image bytes, request IDs) must
    NOT be flagged — only named-detector hits should emit findings."""
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="binary-bucket")
    # 200 chars of base64-shaped high-entropy noise; passes high_entropy regex
    # but is NOT a real secret. Should NOT produce a finding.
    s3.put_object(Bucket="binary-bucket", Key="image.bin",
                  Body=b"qN3p2k1vDjZ8m4tyWGq7hFB6cvL9aXrI5sP0nEoK3uYTMjC1lVxRhB4dgaQHfeUsZ7w8DjPN6m4tyWGq7hFB6cvL9aXrI5sP0nEoK3uYTMjC1lVxRhB4dgaQHfeUsZ7w8DjPNqN3p2k1vDjZ8m4tyWGq7hFB6cvL9aXrI5sP0nEoK3uYTMjC1lVxRhB4dgaQHfeUsZ7w8")
    profile._session = boto3.Session(region_name="us-east-1")
    findings = scan_s3(profile, target_buckets=["binary-bucket"])
    # No high_entropy findings should leak through for S3 source
    assert not any("high_entropy" in f.rule_id for f in findings), \
        f"S3 should suppress generic high_entropy: got {[f.rule_id for f in findings]}"


@mock_aws
def test_scan_s3_still_finds_named_detectors(profile):
    """Named detectors (aws_access_key_id, jwt, etc.) must still fire on S3 contents."""
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="cred-bucket")
    s3.put_object(Bucket="cred-bucket", Key="creds.txt",
                  Body=b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
    profile._session = boto3.Session(region_name="us-east-1")
    findings = scan_s3(profile, target_buckets=["cred-bucket"])
    assert any(f.rule_id == "secrets.s3.aws_access_key_id" for f in findings)
