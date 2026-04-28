import boto3
import pytest
from moto import mock_aws
from whitebox.inventory.route53 import enumerate_zones, in_scope_domains, candidate_domains
from whitebox.profiles import CloudProfile


@pytest.fixture
def profile(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    p = CloudProfile(name="test", account_id="111", arn="arn:test", regions=["us-east-1"])
    return p


@mock_aws
def test_enumerate_returns_zone_names(profile):
    r = boto3.client("route53")
    r.create_hosted_zone(Name="adfactorspr.com.", CallerReference="x")
    r.create_hosted_zone(Name="pranapr.com.", CallerReference="y")
    profile._session = boto3.Session(region_name="us-east-1")

    zones = enumerate_zones(profile)
    names = sorted(z["name"] for z in zones)
    assert names == ["adfactorspr.com", "pranapr.com"]


@mock_aws
def test_in_scope_domains_requires_allowlist(profile):
    r = boto3.client("route53")
    r.create_hosted_zone(Name="example.com.", CallerReference="x")
    profile._session = boto3.Session(region_name="us-east-1")

    # Without an allowlist, must refuse
    import pytest as _pt
    with _pt.raises(ValueError, match="authorized_allowlist"):
        in_scope_domains(profile)


@mock_aws
def test_in_scope_domains_intersects_with_allowlist(profile):
    r = boto3.client("route53")
    r.create_hosted_zone(Name="example.com.", CallerReference="x")
    r.create_hosted_zone(Name="other.com.", CallerReference="y")
    profile._session = boto3.Session(region_name="us-east-1")

    domains = in_scope_domains(profile, authorized_allowlist=["example.com"])
    assert "example.com" in domains
    assert "other.com" not in domains  # explicitly NOT in allowlist
    assert "example.com." not in domains


@mock_aws
def test_in_scope_domains_wildcard_disables_scope_lock(profile):
    r = boto3.client("route53")
    r.create_hosted_zone(Name="example.com.", CallerReference="x")
    r.create_hosted_zone(Name="other.com.", CallerReference="y")
    profile._session = boto3.Session(region_name="us-east-1")

    domains = in_scope_domains(profile, authorized_allowlist=["*"])
    assert "example.com" in domains
    assert "other.com" in domains
