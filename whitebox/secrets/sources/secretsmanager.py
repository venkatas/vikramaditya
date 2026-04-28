from __future__ import annotations
from pathlib import Path
from whitebox.models import Finding, Severity, CloudContext
from whitebox.profiles import CloudProfile
from whitebox.secrets.detectors import scan_text


def scan(profile: CloudProfile) -> list[Finding]:
    findings: list[Finding] = []
    can_get = profile.permission_probe.get("secretsmanager_get_value", False)
    for region in profile.regions:
        try:
            client = profile._session.client("secretsmanager", region_name=region)
        except Exception:
            continue
        secret_arns: list[tuple[str, str]] = []
        try:
            paginator = client.get_paginator("list_secrets")
            for page in paginator.paginate():
                for s in page.get("SecretList", []):
                    secret_arns.append((s["Name"], s["ARN"]))
        except Exception:
            continue
        if not secret_arns:
            continue
        if not can_get:
            findings.append(Finding(
                id=f"secrets-permission-gap-{region}",
                source="secrets",
                rule_id="secrets.secretsmanager.permission_gap",
                severity=Severity.INFO,
                title=f"Secrets Manager scan limited to metadata in {region}",
                description=f"{len(secret_arns)} secrets present but secretsmanager:GetSecretValue is not granted. Add the permission to enable value scanning.",
                asset=None,
                evidence_path=Path("secrets") / f"permission-gap-{region}.json",
                cloud_context=CloudContext(
                    account_id=profile.account_id, region=region, service="secretsmanager", arn="",
                ),
            ))
            continue
        for name, arn in secret_arns:
            try:
                value = client.get_secret_value(SecretId=arn).get("SecretString", "")
            except Exception:
                continue
            for hit in scan_text(f"{name}={value}", source=f"secretsmanager:{name}"):
                fid = f"secret-sm-{name.replace('/', '_')}-{hit['detector']}"
                findings.append(Finding(
                    id=fid,
                    source="secrets",
                    rule_id=f"secrets.secretsmanager.{hit['detector']}",
                    severity=Severity.CRITICAL,
                    title=f"Secret value in Secrets Manager ({name})",
                    description=f"{hit['detector']} matched in secret {name} (region {region}). Preview: {hit['preview']}",
                    asset=None,
                    evidence_path=Path("secrets") / f"{fid}.json",
                    cloud_context=CloudContext(
                        account_id=profile.account_id, region=region, service="secretsmanager", arn=arn,
                    ),
                ))
    return findings
