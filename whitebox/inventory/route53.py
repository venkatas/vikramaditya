from __future__ import annotations
from whitebox.profiles import CloudProfile


def enumerate_zones(profile: CloudProfile) -> list[dict]:
    """Return list of {id, name, private} for every hosted zone in the account."""
    client = profile._session.client("route53")
    out: list[dict] = []
    paginator = client.get_paginator("list_hosted_zones")
    for page in paginator.paginate():
        for z in page.get("HostedZones", []):
            out.append({
                "id": z["Id"].split("/")[-1],
                "name": z["Name"].rstrip("."),
                "private": z.get("Config", {}).get("PrivateZone", False),
            })
    return out


def in_scope_domains(profile: CloudProfile) -> list[str]:
    """Public-zone domain names treated as in-scope for this account."""
    return [z["name"] for z in enumerate_zones(profile) if not z["private"]]
