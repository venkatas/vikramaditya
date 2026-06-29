from __future__ import annotations
import logging
from pathlib import Path
from whitebox.models import Finding, Severity, CloudContext
from whitebox.profiles import CloudProfile
from whitebox.secrets.detectors import scan_text

_log = logging.getLogger(__name__)


def _coverage_gap(profile: CloudProfile, region: str, exc: Exception) -> Finding:
    """Build an INFO coverage-degradation Finding for a region whose Lambda
    enumeration failed (throttling, transient 5xx, partial pagination, denied
    client). Without this the failure is indistinguishable from 'nothing
    found' and a secret in the failed region is a silent false-negative."""
    fid = f"secrets-lambda-scan-failed-{profile.account_id}-{region}"
    return Finding(
        id=fid,
        source="secrets",
        rule_id="secrets.lambda_env.scan_failed",
        severity=Severity.INFO,
        title=f"Lambda env secret scan coverage gap ({region})",
        description=(
            f"Enumeration of Lambda functions in region {region} (account "
            f"{profile.account_id}) failed and was not exhaustive: "
            f"{type(exc).__name__}: {exc}. A secret in an unscanned Lambda "
            f"env var in this region is a false-negative this scan cannot "
            f"rule out (e.g. throttling/RequestLimitExceeded or a transient "
            f"error mid-pagination)."
        ),
        asset=None,
        evidence_path=Path("secrets") / f"{fid}.json",
        cloud_context=CloudContext(
            account_id=profile.account_id, region=region,
            service="lambda",
            arn=f"arn:aws:lambda:{region}:{profile.account_id}:function:*",
        ),
    )


def scan(profile: CloudProfile, secrets_dir: Path | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for region in profile.regions:
        try:
            client = profile._session.client("lambda", region_name=region)
        except Exception as exc:
            _log.warning(
                "lambda_env: could not create lambda client for region %s "
                "(account %s): %s", region, profile.account_id, exc)
            findings.append(_coverage_gap(profile, region, exc))
            continue
        try:
            paginator = client.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page.get("Functions", []):
                    env_vars = (fn.get("Environment") or {}).get("Variables") or {}
                    for key, value in env_vars.items():
                        text = f"{key}={value}"
                        for hit in scan_text(text, source=f"lambda_env:{fn['FunctionName']}"):
                            fid = f"secret-lambda-{profile.account_id}-{region}-{fn['FunctionName']}-{key}-{hit['offset']}-{hit['detector']}"
                            if secrets_dir is not None:
                                from whitebox.secrets.redactor import write_evidence as _we
                                evidence = _we(secrets_dir, fid, [hit])
                            else:
                                evidence = Path("secrets") / f"{fid}.json"
                            findings.append(Finding(
                                id=fid,
                                source="secrets",
                                rule_id=f"secrets.lambda_env.{hit['detector']}",
                                severity=Severity.HIGH,
                                title=f"Secret in Lambda env var ({fn['FunctionName']}.{key})",
                                description=f"{hit['detector']} matched in env var {key} of Lambda {fn['FunctionName']} (region {region}, account {profile.account_id}). Preview: {hit['preview']}",
                                asset=None,
                                evidence_path=evidence,
                                cloud_context=CloudContext(
                                    account_id=profile.account_id, region=region,
                                    service="lambda", arn=fn["FunctionArn"],
                                ),
                            ))
        except Exception as exc:
            _log.warning(
                "lambda_env: list_functions enumeration failed for region %s "
                "(account %s): %s", region, profile.account_id, exc)
            findings.append(_coverage_gap(profile, region, exc))
            continue
    return findings
