from __future__ import annotations
from pathlib import Path
from whitebox.models import Finding, Severity, CloudContext
from whitebox.profiles import CloudProfile
from whitebox.secrets.detectors import scan_text


def scan(profile: CloudProfile) -> list[Finding]:
    findings: list[Finding] = []
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
        denied_count = 0
        for name, arn in secret_arns:
            try:
                resp = client.get_secret_value(SecretId=arn)
                # Lazy probe: first success flips the flag
                profile.permission_probe["secretsmanager_get_value"] = True
            except Exception as e:
                # Distinguish AccessDenied from other errors
                err_code = getattr(getattr(e, "response", None), "get", lambda *_: {})("Error", {}).get("Code", "")
                if "AccessDenied" in err_code or "AccessDenied" in str(e):
                    denied_count += 1
                continue
            # Read SecretString OR decode SecretBinary
            value = resp.get("SecretString")
            if value is None and resp.get("SecretBinary"):
                try:
                    raw = resp["SecretBinary"]
                    value = raw.decode("utf-8", errors="ignore") if isinstance(raw, (bytes, bytearray)) else str(raw)
                except Exception:
                    value = ""
            if not value:
                continue
            for hit in scan_text(f"{name}={value}", source=f"secretsmanager:{name}"):
                fid = f"secret-sm-{profile.account_id}-{region}-{name.replace('/', '_')}-{hit['detector']}"
                findings.append(Finding(
                    id=fid,
                    source="secrets",
                    rule_id=f"secrets.secretsmanager.{hit['detector']}",
                    severity=Severity.CRITICAL,
                    title=f"Secret value in Secrets Manager ({name})",
                    description=f"{hit['detector']} matched in secret {name} (region {region}, account {profile.account_id}). Preview: {hit['preview']}",
                    asset=None,
                    evidence_path=Path("secrets") / f"{fid}.json",
                    cloud_context=CloudContext(
                        account_id=profile.account_id, region=region, service="secretsmanager", arn=arn,
                    ),
                ))
        # Emit permission-gap finding only when GetSecretValue was actually denied
        if denied_count > 0 and not profile.permission_probe.get("secretsmanager_get_value"):
            findings.append(Finding(
                id=f"secrets-sm-permission-gap-{profile.account_id}-{region}",
                source="secrets",
                rule_id="secrets.secretsmanager.permission_gap",
                severity=Severity.INFO,
                title=f"Secrets Manager scan limited to metadata in {region}",
                description=f"{denied_count} secret(s) returned AccessDenied on GetSecretValue. Add secretsmanager:GetSecretValue to enable value scanning.",
                asset=None,
                evidence_path=Path("secrets") / f"permission-gap-{region}.json",
                cloud_context=CloudContext(
                    account_id=profile.account_id, region=region, service="secretsmanager", arn="",
                ),
            ))
    return findings
