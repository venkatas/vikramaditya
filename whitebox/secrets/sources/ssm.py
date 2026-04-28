from __future__ import annotations
from pathlib import Path
from whitebox.models import Finding, Severity, CloudContext
from whitebox.profiles import CloudProfile
from whitebox.secrets.detectors import scan_text


def scan(profile: CloudProfile) -> list[Finding]:
    findings: list[Finding] = []
    for region in profile.regions:
        try:
            client = profile._session.client("ssm", region_name=region)
        except Exception:
            continue
        try:
            paginator = client.get_paginator("describe_parameters")
            param_names: list[tuple[str, str]] = []
            for page in paginator.paginate():
                for p in page.get("Parameters", []):
                    param_names.append((p["Name"], p["Type"]))
        except Exception:
            continue

        for name, ptype in param_names:
            try:
                resp = client.get_parameter(Name=name, WithDecryption=True)
                value = resp["Parameter"]["Value"]
            except Exception:
                continue
            for hit in scan_text(f"{name}={value}", source=f"ssm:{name}"):
                fid = f"secret-ssm-{name.strip('/').replace('/', '_')}-{hit['detector']}"
                findings.append(Finding(
                    id=fid,
                    source="secrets",
                    rule_id=f"secrets.ssm.{hit['detector']}",
                    severity=Severity.HIGH,
                    title=f"Secret in SSM parameter ({name})",
                    description=f"{hit['detector']} matched in SSM {ptype} parameter {name} (region {region}). Preview: {hit['preview']}",
                    asset=None,
                    evidence_path=Path("secrets") / f"{fid}.json",
                    cloud_context=CloudContext(
                        account_id=profile.account_id, region=region, service="ssm",
                        arn=f"arn:aws:ssm:{region}:{profile.account_id}:parameter{name}",
                    ),
                ))
    return findings
