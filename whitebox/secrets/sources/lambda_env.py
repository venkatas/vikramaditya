from __future__ import annotations
from pathlib import Path
from whitebox.models import Finding, Severity, CloudContext
from whitebox.profiles import CloudProfile
from whitebox.secrets.detectors import scan_text


def scan(profile: CloudProfile) -> list[Finding]:
    findings: list[Finding] = []
    for region in profile.regions:
        try:
            client = profile._session.client("lambda", region_name=region)
        except Exception:
            continue
        try:
            paginator = client.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page.get("Functions", []):
                    env_vars = (fn.get("Environment") or {}).get("Variables") or {}
                    for key, value in env_vars.items():
                        text = f"{key}={value}"
                        for hit in scan_text(text, source=f"lambda_env:{fn['FunctionName']}"):
                            fid = f"secret-lambda-{fn['FunctionName']}-{key}-{hit['detector']}"
                            findings.append(Finding(
                                id=fid,
                                source="secrets",
                                rule_id=f"secrets.lambda_env.{hit['detector']}",
                                severity=Severity.HIGH,
                                title=f"Secret in Lambda env var ({fn['FunctionName']}.{key})",
                                description=f"{hit['detector']} matched in env var {key} of Lambda {fn['FunctionName']} (region {region}). Preview: {hit['preview']}",
                                asset=None,
                                evidence_path=Path("secrets") / f"{fid}.json",
                                cloud_context=CloudContext(
                                    account_id=profile.account_id, region=region,
                                    service="lambda", arn=fn["FunctionArn"],
                                ),
                            ))
        except Exception:
            continue
    return findings
