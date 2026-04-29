from __future__ import annotations
from pathlib import Path
from whitebox.models import Finding, Severity, CloudContext
from whitebox.profiles import CloudProfile
from whitebox.secrets.detectors import scan_text


def scan(profile: CloudProfile, secrets_dir: Path | None = None) -> list[Finding]:
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

        denied_count = 0
        for name, ptype in param_names:
            try:
                resp = client.get_parameter(Name=name, WithDecryption=True)
                value = resp["Parameter"]["Value"]
            except Exception as e:
                err_code = getattr(getattr(e, "response", None), "get", lambda *_: {})("Error", {}).get("Code", "")
                if "AccessDenied" in err_code or "AccessDenied" in str(e):
                    denied_count += 1
                continue
            for hit in scan_text(f"{name}={value}", source=f"ssm:{name}"):
                fid = f"secret-ssm-{profile.account_id}-{region}-{name.strip('/').replace('/', '_')}-{hit['offset']}-{hit['detector']}"
                if secrets_dir is not None:
                    from whitebox.secrets.redactor import write_evidence as _we
                    evidence = _we(secrets_dir, fid, [hit])
                else:
                    evidence = Path("secrets") / f"{fid}.json"
                findings.append(Finding(
                    id=fid,
                    source="secrets",
                    rule_id=f"secrets.ssm.{hit['detector']}",
                    severity=Severity.HIGH,
                    title=f"Secret in SSM parameter ({name})",
                    description=f"{hit['detector']} matched in SSM {ptype} parameter {name} (region {region}, account {profile.account_id}). Preview: {hit['preview']}",
                    asset=None,
                    evidence_path=evidence,
                    cloud_context=CloudContext(
                        account_id=profile.account_id, region=region, service="ssm",
                        arn=f"arn:aws:ssm:{region}:{profile.account_id}:parameter{name}",
                    ),
                ))
        if denied_count > 0:
            findings.append(Finding(
                id=f"secrets-ssm-permission-gap-{profile.account_id}-{region}",
                source="secrets",
                rule_id="secrets.ssm.permission_gap",
                severity=Severity.INFO,
                title=f"SSM SecureString scan limited in {region}",
                description=f"{denied_count} SSM parameter(s) returned AccessDenied on GetParameter (likely missing kms:Decrypt). Add the relevant KMS key permission to enable value scanning.",
                asset=None,
                evidence_path=Path("secrets") / f"ssm-permission-gap-{region}.json",
                cloud_context=CloudContext(
                    account_id=profile.account_id, region=region, service="ssm", arn="",
                ),
            ))
    return findings
