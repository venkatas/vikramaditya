from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
import boto3
import logging

_log = logging.getLogger(__name__)


def _normalize_to_iam_arn(arn: str) -> str:
    """Convert an STS assumed-role ARN to its underlying IAM role ARN.
    arn:aws:sts::ACCT:assumed-role/ROLE/SESSION → arn:aws:iam::ACCT:role/ROLE
    Other ARN shapes returned unchanged."""
    if ":sts::" in arn and ":assumed-role/" in arn:
        try:
            account = arn.split(":")[4]
            tail = arn.split(":assumed-role/", 1)[1]
            role_name = tail.split("/", 1)[0]
            return f"arn:aws:iam::{account}:role/{role_name}"
        except (IndexError, ValueError):
            return arn
    return arn


@dataclass
class CloudProfile:
    name: str
    account_id: str = ""
    arn: str = ""
    regions: list[str] = field(default_factory=list)
    in_scope_domains: list[str] = field(default_factory=list)
    permission_probe: dict = field(default_factory=dict)
    _session: Any = None  # boto3.Session — set after validate()


def validate(profile: CloudProfile) -> CloudProfile:
    """Validate profile by calling STS. Raises RuntimeError on failure."""
    try:
        session = boto3.Session(profile_name=profile.name)
    except Exception as e:
        raise RuntimeError(f"failed to load AWS profile {profile.name!r}: {e}") from e

    try:
        ident = session.client("sts").get_caller_identity()
    except Exception as e:
        raise RuntimeError(f"STS GetCallerIdentity failed for {profile.name!r}: {e}") from e

    profile.account_id = ident["Account"]
    profile.arn = ident["Arn"]
    profile.regions = list(session.get_available_regions("ec2"))
    profile._session = session
    profile.permission_probe = probe_permissions(session, principal_arn=_normalize_to_iam_arn(profile.arn))
    return profile


def probe_permissions(session, principal_arn: str, probe_region: str = "us-east-1") -> dict:
    """Soft-probe each optional permission. Never raises.

    Returns a dict with five keys:
      - simulate_principal_policy: probed eagerly via IAM SimulatePrincipalPolicy
      - secretsmanager_list:       probed eagerly via SecretsManager ListSecrets (in probe_region)
      - logs_describe:             probed eagerly via CloudWatch Logs DescribeLogGroups (in probe_region)
      - secretsmanager_get_value:  initialised False; downstream secrets/secretsmanager.py
                                   updates this on first GetSecretValue attempt.
      - kms_decrypt:               initialised False; downstream secret-decrypt code
                                   updates this lazily per KMS key.

    Lazy keys reflect "not yet probed" until set; consumers MUST treat False
    as "unknown / no decrypt yet attempted", not "definitively denied".
    Regional probes target probe_region (default us-east-1) — they are coarse
    yes/no signals, not per-region authority.
    """
    probe = {
        "simulate_principal_policy": False,
        "secretsmanager_list": False,
        "secretsmanager_get_value": False,  # set later by source code on first GetSecretValue
        "logs_describe": False,
        "kms_decrypt": False,                # per-key, set lazily
    }
    try:
        session.client("iam").simulate_principal_policy(
            PolicySourceArn=principal_arn,
            ActionNames=["iam:ListUsers"],
        )
        probe["simulate_principal_policy"] = True
    except Exception as e:
        _log.debug("probe simulate_principal_policy failed: %s", e)
    try:
        session.client("secretsmanager", region_name=probe_region).list_secrets(MaxResults=1)
        probe["secretsmanager_list"] = True
    except Exception as e:
        _log.debug("probe secretsmanager_list failed: %s", e)
    try:
        session.client("logs", region_name=probe_region).describe_log_groups(limit=1)
        probe["logs_describe"] = True
    except Exception as e:
        _log.debug("probe logs_describe failed: %s", e)
    return probe
