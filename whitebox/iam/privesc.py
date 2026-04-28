from __future__ import annotations
from pathlib import Path
from whitebox.models import Finding, Severity, CloudContext
from whitebox.iam.graph import IAMGraph


def detect_paths(graph: IAMGraph, account_id: str) -> list[Finding]:
    findings: list[Finding] = []
    for arn, node in graph.nodes.items():
        if node.get("is_admin"):
            continue
        for admin_arn in graph.reachable_admins(arn):
            path = graph.can_reach(arn, admin_arn) or []
            short_src = arn.split(":")[-1].split("/")[-1]
            short_dst = admin_arn.split(":")[-1].split("/")[-1]
            findings.append(Finding(
                id=f"pmapper-{short_src}-to-{short_dst}",
                source="pmapper",
                rule_id=f"pmapper.privesc_path.{len(path)-1}_hop",
                severity=Severity.HIGH if len(path) > 2 else Severity.CRITICAL,
                title=f"{short_src} → {short_dst} (privilege escalation, {len(path)-1} hop)",
                description=f"Principal {arn} can reach admin {admin_arn} via {' → '.join(path)}",
                asset=None,
                evidence_path=Path("pmapper") / f"{short_src}-to-{short_dst}.json",
                cloud_context=CloudContext(
                    account_id=account_id, region="global", service="iam", arn=arn,
                ),
            ))
    return findings
