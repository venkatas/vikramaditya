"""IAM MFA hardware-vs-virtual distinction (CIS 1.5 / 1.6).

Prowler's default IAM checks treat any MFA as compliant. CIS AWS Foundations
1.5 (root) and 1.6 (IAM users) explicitly require *hardware* MFA — virtual
MFA apps (Google Authenticator, Authy, etc.) leave the second factor on a
device that may itself be compromised. This module fills the gap:

  - For each IAM user, list MFA devices via ``iam.list_mfa_devices``. The
    device ``SerialNumber`` ARN encodes the type:
        arn:aws:iam::ACCOUNT:mfa/USER       → virtual TOTP    (MEDIUM finding)
        arn:aws:iam::ACCOUNT:u2f/USER       → U2F / WebAuthn  (no finding)
        arn:aws:iam::ACCOUNT:smsmfa/USER    → SMS hardware    (no finding)
  - For root, ``iam.get_account_summary`` only reports a boolean
    ``AccountMFAEnabled``. We cross-reference
    ``iam.list_virtual_mfa_devices(AssignmentStatus='Assigned')`` to detect
    virtual MFA on the root principal — this is CRITICAL per CIS 1.5.

Returns finding dicts (same shape as ``waf_count_check``) so the orchestrator
can wrap them into ``Finding`` models.
"""
from __future__ import annotations

import logging
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

_log = logging.getLogger(__name__)

_CHECK_USER = "iam_user_mfa_hardware"
_CHECK_ROOT = "iam_root_mfa_hardware"


def _is_virtual(serial: str) -> bool:
    return ":mfa/" in (serial or "")


def _is_root_virtual_mfa(serial: str, account_id: str) -> bool:
    # Root virtual MFA serial: arn:aws:iam::ACCT:mfa/root-account-mfa-device
    return serial == f"arn:aws:iam::{account_id}:mfa/root-account-mfa-device"


def check_mfa_hardware(profile) -> list[dict[str, Any]]:
    """Enumerate IAM users + root and emit findings for non-hardware MFA.

    Args:
        profile: A whitebox CloudProfile (with ``_session`` and ``account_id``)
            OR a plain boto3.Session (account_id resolved via STS).

    Returns:
        List of finding dicts. Empty list if IAM access is denied.
    """
    session = getattr(profile, "_session", None) or profile
    if not isinstance(session, boto3.Session):
        session = boto3.Session()
    account_id = getattr(profile, "account_id", "") or ""
    if not account_id:
        try:
            account_id = session.client("sts").get_caller_identity()["Account"]
        except (BotoCoreError, ClientError) as e:
            _log.debug("STS get_caller_identity failed: %s", e)
            return []

    iam = session.client("iam")
    out: list[dict[str, Any]] = []

    # ── Per-user MFA scan ──
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                uname = user.get("UserName")
                if not uname:
                    continue
                try:
                    devs = iam.list_mfa_devices(UserName=uname).get("MFADevices", [])
                except (BotoCoreError, ClientError) as e:
                    _log.debug("list_mfa_devices(%s) failed: %s", uname, e)
                    continue
                if not devs:
                    continue  # no-MFA case is covered by Prowler's existing check
                for dev in devs:
                    serial = dev.get("SerialNumber", "")
                    if _is_virtual(serial):
                        out.append({
                            "title": "IAM user MFA is virtual, not hardware-based (CIS 1.6)",
                            "severity": "MEDIUM",
                            "check_id": _CHECK_USER,
                            "resource_id": user.get("Arn", uname),
                            "resource_type": "AWS::IAM::User",
                            "region": "us-east-1",
                            "details": (
                                f"IAM user '{uname}' has a virtual MFA device "
                                f"({serial}). CIS AWS Foundations 1.6 recommends "
                                "hardware MFA (U2F/WebAuthn) for all human users."
                            ),
                            "remediation": (
                                "Replace virtual MFA with a U2F/WebAuthn key "
                                "(YubiKey, Titan) via IAM console → user → "
                                "Security credentials → Assign MFA → Security key."
                            ),
                            "framework": "CIS AWS Foundations 1.6",
                        })
    except (BotoCoreError, ClientError) as e:
        _log.debug("list_users paginator failed: %s", e)

    # ── Root MFA hardware-vs-virtual ──
    try:
        vdevs = iam.list_virtual_mfa_devices(AssignmentStatus="Assigned").get(
            "VirtualMFADevices", []
        )
        for v in vdevs:
            serial = v.get("SerialNumber", "")
            if _is_root_virtual_mfa(serial, account_id):
                out.append({
                    "title": "Root account uses virtual MFA, not hardware (CIS 1.5)",
                    "severity": "CRITICAL",
                    "check_id": _CHECK_ROOT,
                    "resource_id": f"arn:aws:iam::{account_id}:root",
                    "resource_type": "AWS::IAM::Root",
                    "region": "us-east-1",
                    "details": (
                        "The AWS account root user has a virtual MFA device "
                        f"({serial}) instead of a hardware token. CIS AWS "
                        "Foundations 1.5 requires hardware MFA for the root "
                        "account because root compromise is unrecoverable."
                    ),
                    "remediation": (
                        "Sign in as root → My Security Credentials → "
                        "Multi-factor authentication → Manage MFA → Hardware "
                        "MFA device. Store the device offline in a safe."
                    ),
                    "framework": "CIS AWS Foundations 1.5",
                })
    except (BotoCoreError, ClientError) as e:
        _log.debug("list_virtual_mfa_devices failed: %s", e)

    return out


__all__ = ["check_mfa_hardware"]
