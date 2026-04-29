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


def candidate_domains(profile: CloudProfile) -> list[str]:
    """Public-zone domain names CANDIDATE for in-scope. NOT authorized scope by themselves —
    must be intersected with the engagement's authorized allowlist via in_scope_domains()."""
    return [z["name"] for z in enumerate_zones(profile) if not z["private"]]


def in_scope_domains(profile: CloudProfile, authorized_allowlist: list[str] | None = None) -> list[str]:
    """Return the intersection of account-discovered public zones AND the engagement's
    authorized allowlist. If authorized_allowlist is None, raises — explicit scope is required.

    To opt out of scope-locking (e.g. for development), pass authorized_allowlist=["*"]."""
    if authorized_allowlist is None:
        raise ValueError(
            "in_scope_domains() requires an explicit authorized_allowlist. "
            "Pass the engagement's authorized domain list, or ['*'] to disable scope-locking."
        )
    candidates = candidate_domains(profile)
    if authorized_allowlist == ["*"]:
        return candidates
    allow = set(authorized_allowlist)
    return [d for d in candidates if d in allow or any(d.endswith("." + a) for a in allow)]
