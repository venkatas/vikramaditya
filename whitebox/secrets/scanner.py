from __future__ import annotations
from pathlib import Path
from whitebox.models import Finding
from whitebox.profiles import CloudProfile
from whitebox.secrets.sources import lambda_env, ssm, secretsmanager, s3, cloudwatch_logs, ec2_userdata
from whitebox.secrets.redactor import write_evidence


def run_all(profile: CloudProfile, secrets_dir: Path,
            target_buckets: list[str] | None = None,
            target_log_groups: list[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    findings += lambda_env.scan(profile)
    findings += ssm.scan(profile)
    findings += secretsmanager.scan(profile)
    findings += ec2_userdata.scan(profile)
    if target_buckets:
        findings += s3.scan(profile, target_buckets=target_buckets)
    if target_log_groups:
        findings += cloudwatch_logs.scan(profile, target_groups=target_log_groups)
    secrets_dir.mkdir(parents=True, exist_ok=True)
    return findings
