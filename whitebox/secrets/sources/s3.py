from __future__ import annotations
from pathlib import Path
from whitebox.models import Finding, Severity, CloudContext
from whitebox.profiles import CloudProfile
from whitebox.secrets.detectors import scan_text

MAX_OBJECT_SIZE = 1_000_000   # 1 MB
MAX_OBJECTS_PER_BUCKET = 200


def scan(profile: CloudProfile, target_buckets: list[str],
         secrets_dir: Path | None = None) -> list[Finding]:
    if not target_buckets:
        return []
    findings: list[Finding] = []
    s3 = profile._session.client("s3")
    for bucket in target_buckets:
        try:
            paginator = s3.get_paginator("list_objects_v2")
            count = 0
            stop = False
            for page in paginator.paginate(Bucket=bucket, PaginationConfig={"MaxItems": MAX_OBJECTS_PER_BUCKET}):
                if stop:
                    break
                for obj in page.get("Contents", []):
                    if count >= MAX_OBJECTS_PER_BUCKET:
                        stop = True
                        break
                    if obj.get("Size", 0) > MAX_OBJECT_SIZE:
                        continue
                    count += 1
                    try:
                        body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
                    except Exception:
                        continue
                    try:
                        text = body.decode("utf-8", errors="ignore")
                    except Exception:
                        continue
                    for hit in scan_text(text, source=f"s3:{bucket}/{obj['Key']}"):
                        safe_key = obj['Key'].replace('/', '_').replace('..', '_')
                        fid = f"secret-s3-{profile.account_id}-global-{bucket}-{safe_key}-{hit['offset']}-{hit['detector']}"
                        if secrets_dir is not None:
                            from whitebox.secrets.redactor import write_evidence as _we
                            evidence = _we(secrets_dir, fid, [hit])
                        else:
                            evidence = Path("secrets") / f"{fid}.json"
                        findings.append(Finding(
                            id=fid,
                            source="secrets",
                            rule_id=f"secrets.s3.{hit['detector']}",
                            severity=Severity.HIGH,
                            title=f"Secret in S3 object ({bucket}/{obj['Key']})",
                            description=f"{hit['detector']} matched in s3://{bucket}/{obj['Key']} (account {profile.account_id}). Preview: {hit['preview']}",
                            asset=None,
                            evidence_path=evidence,
                            cloud_context=CloudContext(
                                account_id=profile.account_id, region="global",
                                service="s3", arn=f"arn:aws:s3:::{bucket}/{obj['Key']}",
                            ),
                        ))
        except Exception:
            continue
    return findings
