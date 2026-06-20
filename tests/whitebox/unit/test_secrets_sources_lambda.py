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


@mock_aws
def test_lambda_writes_evidence_file_when_secrets_dir_given(tmp_path, profile):
    iam = boto3.client("iam")
    iam.create_role(RoleName="r3", AssumeRolePolicyDocument="{}")
    role_arn = iam.get_role(RoleName="r3")["Role"]["Arn"]
    lam = boto3.client("lambda", region_name="us-east-1")
    lam.create_function(
        FunctionName="ev", Runtime="python3.11", Role=role_arn,
        Handler="x.handler",
        Code={"ZipFile": b"def handler(e,c):pass"},
        Environment={"Variables": {"K": "AKIAIOSFODNN7EXAMPLE"}},
    )
    profile._session = boto3.Session(region_name="us-east-1")
    findings = scan_lambda(profile, secrets_dir=tmp_path)
    assert findings, "expected at least one finding"
    f = findings[0]
    assert f.evidence_path.exists(), f"expected evidence file at {f.evidence_path}"
    assert f.evidence_path.parent == tmp_path
    import os, stat
    mode = stat.S_IMODE(os.stat(f.evidence_path).st_mode)
    assert mode == 0o600


@mock_aws
def test_lambda_finding_id_includes_account_and_region(profile):
    iam = boto3.client("iam")
    iam.create_role(RoleName="r2", AssumeRolePolicyDocument="{}")
    role_arn = iam.get_role(RoleName="r2")["Role"]["Arn"]
    lam = boto3.client("lambda", region_name="us-east-1")
    lam.create_function(
        FunctionName="dup", Runtime="python3.11", Role=role_arn,
        Handler="x.handler",
        Code={"ZipFile": b"def handler(e,c):pass"},
        Environment={"Variables": {"K": "AKIAIOSFODNN7EXAMPLE"}},
    )
    profile._session = boto3.Session(region_name="us-east-1")
    findings = scan_lambda(profile)
    assert findings, "expected at least one finding"
    # Finding ID must include account + region to avoid cross-region collision
    assert "111" in findings[0].id
    assert "us-east-1" in findings[0].id


def test_lambda_pagination_failure_emits_coverage_gap(profile):
    """A throttling/transient failure mid-enumeration must surface as an INFO
    coverage-gap Finding, not be silently swallowed (false-negative)."""
    from whitebox.models import Severity

    class _BoomPaginator:
        def paginate(self):
            raise RuntimeError("ThrottlingException: Rate exceeded")

    class _FakeClient:
        def get_paginator(self, name):
            return _BoomPaginator()

    class _FakeSession:
        def client(self, service, region_name=None):
            return _FakeClient()

    profile._session = _FakeSession()
    findings = scan_lambda(profile)
    assert len(findings) == 1, "expected exactly one coverage-gap finding"
    f = findings[0]
    assert f.severity == Severity.INFO
    assert f.rule_id == "secrets.lambda_env.scan_failed"
    assert "us-east-1" in f.id and "111" in f.id
    assert "ThrottlingException" in f.description or "Throttling" in f.description


def test_lambda_client_creation_failure_emits_coverage_gap(profile):
    """If the lambda client cannot even be created for a region, that region's
    coverage gap must be recorded rather than dropped."""
    from whitebox.models import Severity

    class _FakeSession:
        def client(self, service, region_name=None):
            raise RuntimeError("could not connect")

    profile._session = _FakeSession()
    findings = scan_lambda(profile)
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert findings[0].rule_id == "secrets.lambda_env.scan_failed"
