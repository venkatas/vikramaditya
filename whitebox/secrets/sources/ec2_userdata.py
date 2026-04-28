from __future__ import annotations
import base64
from pathlib import Path
from whitebox.models import Finding, Severity, CloudContext
from whitebox.profiles import CloudProfile
from whitebox.secrets.detectors import scan_text


def scan(profile: CloudProfile, secrets_dir: Path | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for region in profile.regions:
        try:
            ec2 = profile._session.client("ec2", region_name=region)
            instances = ec2.describe_instances()
        except Exception:
            continue
        for resv in instances.get("Reservations", []):
            for inst in resv.get("Instances", []):
                iid = inst["InstanceId"]
                try:
                    attr = ec2.describe_instance_attribute(InstanceId=iid, Attribute="userData")
                    raw = attr.get("UserData", {}).get("Value", "")
                    if not raw:
                        continue
                    text = base64.b64decode(raw).decode("utf-8", errors="ignore")
                except Exception:
                    continue
                for hit in scan_text(text, source=f"ec2_userdata:{iid}"):
                    fid = f"secret-userdata-{profile.account_id}-{region}-{iid}-{hit['offset']}-{hit['detector']}"
                    if secrets_dir is not None:
                        from whitebox.secrets.redactor import write_evidence as _we
                        evidence = _we(secrets_dir, fid, [hit])
                    else:
                        evidence = Path("secrets") / f"{fid}.json"
                    findings.append(Finding(
                        id=fid,
                        source="secrets",
                        rule_id=f"secrets.ec2_userdata.{hit['detector']}",
                        severity=Severity.HIGH,
                        title=f"Secret in EC2 user-data ({iid})",
                        description=f"{hit['detector']} matched in user-data of instance {iid} (region {region}, account {profile.account_id}). Preview: {hit['preview']}",
                        asset=None,
                        evidence_path=evidence,
                        cloud_context=CloudContext(
                            account_id=profile.account_id, region=region, service="ec2",
                            arn=f"arn:aws:ec2:{region}:{profile.account_id}:instance/{iid}",
                        ),
                    ))
    return findings
