"""v9.0 P23 — Route 53 → blackbox scope auto-suggest.

Reads the inventory directory of an audited AWS account and emits a single
JSON file enumerating every domain / DNS endpoint the client owns inside
that account, labeled by source (Route53 hosted zone, CloudFront alias,
ELB DNS, ACM cert SAN). The output goes into
`<session_dir>/cloud/<account_id>/scope-suggestion.json` so that
`vikramaditya.py` (or any future operator) can see at a glance what
domains the engagement scope sheet might have missed.

Engagement context that motivated this: the original blackbox scope
covered 2 domains. Cloud inventory had 5 additional client-owned
Route53 zones plus a third client product (`merryspiders.com`)
referenced via an ELB name. All five were discovered manually mid-engagement.
"""
from __future__ import annotations
import json
from pathlib import Path


def build_scope_suggestion(inventory_dir: Path) -> dict:
    """Walk the inventory and return a structured scope suggestion.

    The dict shape is intentionally simple so JSON output is human-skimmable:
      {
        "route53_zones": [...],     # client-owned hosted zones
        "cloudfront_aliases": [...], # custom domains fronting CloudFront
        "elb_dns": [...],           # internet-facing LB DNS names
        "elb_product_names": [...], # LB-name fragments suggesting product/domain
        "summary": "Found N candidates; M are obvious client-product domains",
      }
    """
    inventory_dir = Path(inventory_dir)
    out: dict = {
        "route53_zones": [],
        "cloudfront_aliases": [],
        "elb_dns": [],
        "elb_product_names": [],
        "summary": "",
    }

    # Route 53 hosted zones — apex client domains
    r53_file = inventory_dir / "route53" / "global.json"
    if r53_file.exists():
        try:
            data = json.loads(r53_file.read_text())
            for z in data.get("HostedZones", []) or []:
                name = (z.get("Name") or "").rstrip(".")
                private = (z.get("Config") or {}).get("PrivateZone", False)
                if name and not private:
                    out["route53_zones"].append(name)
        except Exception:
            pass
    out["route53_zones"] = sorted(set(out["route53_zones"]))

    # CloudFront alternate domain names (CNAMEs)
    cf_file = inventory_dir / "cloudfront" / "global.json"
    if cf_file.exists():
        try:
            data = json.loads(cf_file.read_text())
            for dist in (data.get("DistributionList") or {}).get("Items", []) or []:
                aliases = (dist.get("Aliases") or {}).get("Items", []) or []
                for a in aliases:
                    if a:
                        out["cloudfront_aliases"].append(a)
        except Exception:
            pass
    out["cloudfront_aliases"] = sorted(set(out["cloudfront_aliases"]))

    # ELB internet-facing DNS — capture both the autogen DNS and any
    # name-fragment that might map to a product / brand domain
    elb_dir = inventory_dir / "elbv2"
    if elb_dir.exists():
        for f in elb_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text())
                for lb in data.get("LoadBalancers", []) or []:
                    if lb.get("Scheme") != "internet-facing":
                        continue
                    dns = lb.get("DNSName")
                    if dns:
                        out["elb_dns"].append(dns)
                    name = lb.get("LoadBalancerName")
                    if name:
                        out["elb_product_names"].append(name)
            except Exception:
                continue
    out["elb_dns"] = sorted(set(out["elb_dns"]))
    out["elb_product_names"] = sorted(set(out["elb_product_names"]))

    total = (
        len(out["route53_zones"])
        + len(out["cloudfront_aliases"])
        + len(out["elb_dns"])
        + len(out["elb_product_names"])
    )
    domains_only = len(out["route53_zones"]) + len(out["cloudfront_aliases"])
    out["summary"] = (
        f"{total} candidates ({domains_only} client-owned domains, "
        f"{len(out['elb_dns'])} internet-facing LBs, "
        f"{len(out['elb_product_names'])} LB names that may map to product domains)"
    )
    return out


def write_scope_suggestion(inventory_dir: Path, out_path: Path) -> dict:
    """Build + write to disk. Returns the dict for callers that want it."""
    suggestion = build_scope_suggestion(inventory_dir)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(suggestion, indent=2))
    return suggestion
