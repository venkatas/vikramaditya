from __future__ import annotations
from whitebox.models import Asset


def tag_assets(assets: list[Asset],
               instance_sg_map: dict[str, list[str]],
               sg_analysis: dict[str, dict],
               waf_protected_arns: set[str]) -> list[Asset]:
    """Mutate and return assets with exposure tags."""
    for a in assets:
        if a.service == "ec2":
            sg_ids = instance_sg_map.get(a.name, [])
            public = any(sg_analysis.get(sg, {}).get("public") for sg in sg_ids)
            ports: set[int] = set()
            cidrs: set[str] = set()
            for sg in sg_ids:
                ports.update(sg_analysis.get(sg, {}).get("exposed_ports", []))
                cidrs.update(sg_analysis.get(sg, {}).get("exposed_cidrs", []))
            a.tags["internet_reachable"] = bool(public and a.public_ip)
            a.tags["exposed_ports"] = sorted(ports)
            a.tags["exposed_cidrs"] = sorted(cidrs)
            a.tags["behind_waf"] = a.arn in waf_protected_arns
        elif a.service == "s3":
            # Placeholder — bucket-policy/public-access-block check happens in Prowler;
            # here we just mark default values. Refined when bucket policy data fed in.
            a.tags.setdefault("internet_reachable", False)
            a.tags.setdefault("behind_waf", False)
    return assets
