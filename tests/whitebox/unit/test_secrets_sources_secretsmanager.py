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
def test_scan_secretsmanager_probe_false_still_scans(profile):
    """Lazy probe: probe=False is 'not yet checked', scanner should still attempt GetSecretValue.

    With moto the call succeeds, so the scanner should find the secret and flip
    the probe flag to True — NOT emit a permission-gap finding.
    """
    sm = boto3.client("secretsmanager", region_name="us-east-1")
    sm.create_secret(Name="prod/db", SecretString="AKIAIOSFODNN7EXAMPLE")
    profile._session = boto3.Session(region_name="us-east-1")
    profile.permission_probe = {"secretsmanager_get_value": False}
    findings = scan_sm(profile)
    # Scanner must attempt GetSecretValue and find the secret
    assert any("prod/db" in f.description for f in findings), \
        "probe=False should not skip — scanner must attempt GetSecretValue"
    # Permission-gap must NOT be emitted when the call succeeded
    assert not any(f.rule_id == "secrets.secretsmanager.permission_gap" for f in findings)
    # Flag should be set True after success
    assert profile.permission_probe.get("secretsmanager_get_value") is True


@mock_aws
def test_scan_secretsmanager_default_probe_state_still_scans(profile):
    """Lazy probe: when permission_probe is empty (production default), scanner should still attempt GetSecretValue."""
    sm = boto3.client("secretsmanager", region_name="us-east-1")
    sm.create_secret(Name="prod/db", SecretString="AKIAIOSFODNN7EXAMPLE")
    profile._session = boto3.Session(region_name="us-east-1")
    profile.permission_probe = {}  # production default after validate()
    findings = scan_sm(profile)
    # Must scan and find — not gate on the absent flag
    assert any("prod/db" in f.description for f in findings), \
        "Empty probe state should not skip — scanner must attempt GetSecretValue"
    # And should have set the flag True after success
    assert profile.permission_probe.get("secretsmanager_get_value") is True


class _DenyAllSession:
    """Stub session whose secretsmanager client lists one secret but denies
    GetSecretValue on it (simulates a region where the audit role lacks the
    value-read permission)."""

    def client(self, service, region_name=None):
        return _DenyAllClient()


class _DenyAllClient:
    def get_paginator(self, _op):
        return self

    def paginate(self):
        return [{"SecretList": [{"Name": "prod/db", "ARN": "arn:aws:secretsmanager:ap-south-1:111:secret:prod/db"}]}]

    def get_secret_value(self, SecretId=None):
        class _Err(Exception):
            response = {"Error": {"Code": "AccessDeniedException"}}

        raise _Err("AccessDeniedException: not authorized to perform secretsmanager:GetSecretValue")


def test_permission_gap_emitted_per_region_despite_global_probe_flag(monkeypatch):
    """Regression: a region where ALL GetSecretValue is denied must still emit a
    permission-gap marker even if another region already flipped the cross-region
    permission_probe flag True. The marker is gated on per-region success, not the
    account-wide flag (matches ssm.py). Without the fix this was a silent
    coverage false-negative.
    """
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-south-1")
    prof = CloudProfile(name="t", account_id="111", arn="a", regions=["ap-south-1"])
    prof._session = _DenyAllSession()
    # Simulate: another region already succeeded and flipped the global flag.
    prof.permission_probe = {"secretsmanager_get_value": True}

    findings = scan_sm(prof)

    gap = [f for f in findings if f.rule_id == "secrets.secretsmanager.permission_gap"]
    assert gap, "deny-all region must emit a permission-gap marker even when the global probe flag is True"
    assert gap[0].cloud_context.region == "ap-south-1"
    # The global probe flag was True on entry and must remain untouched here.
    assert prof.permission_probe.get("secretsmanager_get_value") is True


@mock_aws
def test_scan_secretsmanager_handles_secret_binary(profile):
    sm = boto3.client("secretsmanager", region_name="us-east-1")
    sm.create_secret(Name="prod/binkey", SecretBinary=b"AKIAIOSFODNN7EXAMPLE")
    profile._session = boto3.Session(region_name="us-east-1")
    findings = scan_sm(profile)
    assert any("prod/binkey" in f.description for f in findings)
