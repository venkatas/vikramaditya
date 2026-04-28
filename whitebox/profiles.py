from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
import boto3


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
    profile.permission_probe = probe_permissions(session, principal_arn=profile.arn)
    return profile


def probe_permissions(session, principal_arn: str) -> dict:
    """Soft-probe each optional permission. Never raises."""
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
    except Exception:
        pass
    try:
        session.client("secretsmanager").list_secrets(MaxResults=1)
        probe["secretsmanager_list"] = True
    except Exception:
        pass
    try:
        session.client("logs").describe_log_groups(limit=1)
        probe["logs_describe"] = True
    except Exception:
        pass
    return probe
