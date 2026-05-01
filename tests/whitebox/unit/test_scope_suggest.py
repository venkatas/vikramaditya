"""v9.0 P23 — Route53 → blackbox scope auto-suggest tests."""
from __future__ import annotations
import json
from pathlib import Path

from whitebox.correlator.scope_suggest import build_scope_suggestion, write_scope_suggestion


def _make_inventory(tmp_path: Path,
                    route53_zones: list[str] | None = None,
                    cloudfront_aliases: list[list[str]] | None = None,
                    elb_lbs: list[dict] | None = None) -> Path:
    """Build a minimal AWS inventory directory matching what the
    real cloud_hunt collector produces."""
    inv = tmp_path / "inventory"
    inv.mkdir()

    # Route53
    (inv / "route53").mkdir()
    if route53_zones is not None:
        zones = [{"Name": z + ".", "Config": {"PrivateZone": False}} for z in route53_zones]
        (inv / "route53" / "global.json").write_text(json.dumps({"HostedZones": zones}))

    # CloudFront
    (inv / "cloudfront").mkdir()
    if cloudfront_aliases is not None:
        items = [{"DomainName": f"d{i}.cloudfront.net",
                  "Aliases": {"Items": aliases}}
                 for i, aliases in enumerate(cloudfront_aliases)]
        (inv / "cloudfront" / "global.json").write_text(json.dumps({"DistributionList": {"Items": items}}))

    # ELBv2
    (inv / "elbv2").mkdir()
    if elb_lbs is not None:
        (inv / "elbv2" / "ap-south-1.json").write_text(json.dumps({"LoadBalancers": elb_lbs}))

    return inv


def test_route53_zones_extracted_and_dedup_trailing_dot(tmp_path):
    inv = _make_inventory(tmp_path,
                          route53_zones=["example.com", "client.io", "example.com"])
    s = build_scope_suggestion(inv)
    assert s["route53_zones"] == ["client.io", "example.com"]


def test_private_zones_excluded(tmp_path):
    """Private hosted zones are internal-only — should NOT be suggested as
    blackbox scope candidates."""
    inv = tmp_path / "inventory"
    (inv / "route53").mkdir(parents=True)
    (inv / "route53" / "global.json").write_text(json.dumps({"HostedZones": [
        {"Name": "public.example.com.", "Config": {"PrivateZone": False}},
        {"Name": "internal.example.com.", "Config": {"PrivateZone": True}},
    ]}))
    s = build_scope_suggestion(inv)
    assert s["route53_zones"] == ["public.example.com"]


def test_cloudfront_aliases_collected(tmp_path):
    inv = _make_inventory(tmp_path,
                          cloudfront_aliases=[["www.client.io", "client.io"], ["assets.client.io"]])
    s = build_scope_suggestion(inv)
    assert s["cloudfront_aliases"] == ["assets.client.io", "client.io", "www.client.io"]


def test_internet_facing_elb_only(tmp_path):
    """Internal ELBs must NOT leak into scope suggestion."""
    inv = _make_inventory(tmp_path, elb_lbs=[
        {"Scheme": "internet-facing", "DNSName": "ext-1.elb.amazonaws.com", "LoadBalancerName": "ext-prod"},
        {"Scheme": "internal", "DNSName": "int-1.elb.amazonaws.com", "LoadBalancerName": "int-private"},
    ])
    s = build_scope_suggestion(inv)
    assert s["elb_dns"] == ["ext-1.elb.amazonaws.com"]
    assert s["elb_product_names"] == ["ext-prod"]


def test_summary_string(tmp_path):
    inv = _make_inventory(tmp_path,
                          route53_zones=["example.com", "client.io"],
                          cloudfront_aliases=[["www.client.io"]],
                          elb_lbs=[{"Scheme": "internet-facing", "DNSName": "x.elb.amazonaws.com",
                                    "LoadBalancerName": "Adf-Prod-merryspiders"}])
    s = build_scope_suggestion(inv)
    assert "client-owned domains" in s["summary"]
    # Total should be 2 zones + 1 alias + 1 elb dns + 1 lb name = 5
    assert "5 candidates" in s["summary"]


def test_engagement_scenario_finds_merryspiders(tmp_path):
    """Engagement reproduction: an account has a Route53 zone for the
    primary client domain, plus an ELB whose name is the third client
    product. P23's whole point is that this product domain shouldn't
    require manual investigation to surface."""
    inv = _make_inventory(tmp_path,
                          route53_zones=["adfactorspr.com", "ad-factors.com"],
                          elb_lbs=[
                              {"Scheme": "internet-facing",
                               "DNSName": "Adf-Prod-UI-merryspiders-2072239192.ap-south-1.elb.amazonaws.com",
                               "LoadBalancerName": "Adf-Prod-UI-merryspiders"},
                          ])
    s = build_scope_suggestion(inv)
    # Operator can spot "merryspiders" in the LB name list
    assert any("merryspiders" in n for n in s["elb_product_names"])


def test_write_scope_suggestion_creates_directory(tmp_path):
    inv = _make_inventory(tmp_path, route53_zones=["x.com"])
    out = tmp_path / "session" / "cloud" / "111" / "scope-suggestion.json"
    s = write_scope_suggestion(inv, out)
    assert out.exists()
    on_disk = json.loads(out.read_text())
    assert on_disk == s
    assert on_disk["route53_zones"] == ["x.com"]


def test_missing_inventory_dir_returns_empty(tmp_path):
    """If a service inventory file is missing (e.g. CloudFront not pulled),
    the module should not crash — just emit an empty list for that source."""
    inv = tmp_path / "inventory"
    (inv / "route53").mkdir(parents=True)
    (inv / "route53" / "global.json").write_text(json.dumps({"HostedZones": [
        {"Name": "only.example.com.", "Config": {"PrivateZone": False}}
    ]}))
    # No cloudfront/, no elbv2/ subdirs
    s = build_scope_suggestion(inv)
    assert s["route53_zones"] == ["only.example.com"]
    assert s["cloudfront_aliases"] == []
    assert s["elb_dns"] == []
