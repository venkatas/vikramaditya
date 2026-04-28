import json
import boto3
import pytest
from moto import mock_aws
from whitebox.inventory.collector import collect_service, collect_all
from whitebox.profiles import CloudProfile


@pytest.fixture
def aws_profile(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    profile = CloudProfile(name="test", account_id="123456789012",
                           arn="arn:aws:iam::123456789012:user/test",
                           regions=["us-east-1"])
    return profile


@mock_aws
def test_collect_ec2_writes_per_region_file(tmp_path, aws_profile):
    boto3.client("ec2", region_name="us-east-1").run_instances(
        ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t2.micro",
    )
    aws_profile._session = boto3.Session(region_name="us-east-1")

    out = collect_service(aws_profile, "ec2", tmp_path)
    f = tmp_path / "ec2" / "us-east-1.json"
    assert f.exists()
    data = json.loads(f.read_text())
    assert "Reservations" in data
    assert out["service"] == "ec2"


@mock_aws
def test_collect_s3_lists_buckets(tmp_path, aws_profile):
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="test-bucket")
    aws_profile._session = boto3.Session(region_name="us-east-1")

    out = collect_service(aws_profile, "s3", tmp_path)
    f = tmp_path / "s3" / "global.json"
    assert f.exists()
    data = json.loads(f.read_text())
    assert any(b["Name"] == "test-bucket" for b in data["Buckets"])


@mock_aws
def test_collect_all_returns_summary(tmp_path, aws_profile):
    boto3.client("s3").create_bucket(Bucket="bkt1")
    aws_profile._session = boto3.Session(region_name="us-east-1")

    summary = collect_all(aws_profile, tmp_path, services=["s3", "iam_users"])
    assert "s3" in summary["services"]
    assert "iam_users" in summary["services"]
    # iam_users is global scope — confirm the file was actually written
    assert (tmp_path / "iam_users" / "global.json").exists()
    assert summary["account_id"] == "123456789012"


@mock_aws
def test_collect_all_with_empty_services_does_nothing(tmp_path, aws_profile):
    aws_profile._session = boto3.Session(region_name="us-east-1")
    summary = collect_all(aws_profile, tmp_path, services=[])
    assert summary["services"] == {}


@mock_aws
def test_collect_wafv2_passes_scope_arg(tmp_path, aws_profile):
    aws_profile._session = boto3.Session(region_name="us-east-1")
    out = collect_service(aws_profile, "wafv2", tmp_path)
    # No Scope error — moto returns ok even with empty WAFs
    assert out["regions"]["us-east-1"] == "ok"
