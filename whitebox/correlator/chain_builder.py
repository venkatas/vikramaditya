from __future__ import annotations
from whitebox.models import Asset, Chain, Finding
from whitebox.iam.graph import IAMGraph
from whitebox.correlator.severity import promote

# Vuln classes that benefit from IAM chain context
_CHAINABLE_RULES = {"ssrf.basic", "ssrf.imds", "rce", "rce.code_exec", "lfi.read_imds"}


def build_chains(blackbox_findings: list[Finding],
                 cloud_assets: list[Asset],
                 iam_graph: IAMGraph,
                 host_to_asset: dict[str, Asset | None]) -> list[Chain]:
    out: list[Chain] = []
    for f in blackbox_findings:
        if f.rule_id not in _CHAINABLE_RULES:
            continue
        host = f.asset.public_dns if f.asset and f.asset.public_dns else (
            f.asset.public_ip if f.asset else None)
        cloud = (host_to_asset.get(host) if host else None) or f.asset
        if not cloud:
            continue
        role_arn = cloud.tags.get("iam_role_arn")
        if not role_arn:
            continue
        admins = iam_graph.reachable_admins(role_arn)
        if not admins:
            continue
        admin_arn = admins[0]
        path = iam_graph.can_reach(role_arn, admin_arn) or [role_arn, admin_arn]
        # IMDS evidence requires an explicit IMDS-class rule. Generic ssrf.basic
        # without confirmed IMDS reachability promotes to HIGH only, not CRITICAL.
        has_imds = f.rule_id in {"ssrf.imds", "lfi.read_imds"} or "imds" in f.rule_id
        promoted = promote(base=f.severity, has_imds=has_imds, reaches_admin=True)
        out.append(Chain(
            trigger_finding_id=f.id,
            cloud_asset_arn=cloud.arn,
            iam_path=path,
            promoted_severity=promoted,
            promotion_rule=f"chain.{f.rule_id}+pmapper.privesc_path.{len(path)-1}_hop",
            narrative=f"Blackbox {f.rule_id} on {host} → IAM role {role_arn} → admin {admin_arn} ({len(path)-1} hop(s)).",
        ))
    return out
