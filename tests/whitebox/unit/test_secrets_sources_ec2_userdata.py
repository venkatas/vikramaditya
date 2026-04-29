import base64
import boto3
import pytest
from moto import mock_aws
from whitebox.profiles import CloudProfile
from whitebox.secrets.sources.ec2_userdata import scan as scan_ud


@pytest.fixture
def profile(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    return CloudProfile(name="t", account_id="111", arn="a", regions=["us-east-1"])


@mock_aws
def test_scan_userdata_decodes_b64_and_detects_secret(profile):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    user_data = base64.b64encode(b"#!/bin/bash\nexport SK=AKIAIOSFODNN7EXAMPLE\n").decode()
    res = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1,
                            InstanceType="t2.micro", UserData=user_data)
    profile._session = boto3.Session(region_name="us-east-1")
    findings = scan_ud(profile)
    assert any("user-data" in f.title.lower() or "user-data" in f.description.lower() for f in findings)
