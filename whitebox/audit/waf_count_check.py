"""WAFv2 COUNT-mode misconfiguration check.

Prowler 4.5 does not ship a check for WAF rules left in COUNT (logging-only)
mode. Operationally, COUNT-mode rules are a silent failure: the WebACL is
attached, CloudWatch metrics tick up on every match, but nothing is actually
blocked. This module fills the gap by enumerating every regional and
CloudFront WebACL in the account and inspecting each rule's Action /
OverrideAction.

A rule is flagged when EITHER:
  - top-level Rules[].Action.Count is set (instead of Block / Allow), OR
  - Rules[].OverrideAction.Count is set on a managed rule group (instead
    of None).

Both conditions break the WebACL's stated protective intent (CWE-1004,
CIS AWS Foundations 5.x).

Returned finding dicts mirror the shape used elsewhere in the whitebox
pipeline so callers can append directly to the orchestrator findings list
after wrapping in a Finding model.
"""
from __future__ import annotations

import logging
from typing import Iterable

import boto3
from botocore.exceptions import BotoCoreError, ClientError

_log = logging.getLogger(__name__)

_FINDING_TITLE = "AWS WAF rule in COUNT mode (not blocking)"
_CHECK_ID = "wafv2_rule_action_count"
_RESOURCE_TYPE = "AWS::WAFv2::WebACL"
_REMEDIATION = (
    "Change Rule.Action.Count → Rule.Action.Block, OR change "
    "OverrideAction.Count → OverrideAction.None for managed rule groups."
)


def _scan_scope(client, scope: str, region: str) -> list[dict]:
    """Enumerate WebACLs in one scope/region and emit findings for COUNT rules."""
    findings: list[dict] = []
    try:
        acls = client.list_web_acls(Scope=scope).get("WebACLs", [])
    except (BotoCoreError, ClientError) as e:
        _log.debug("list_web_acls(%s, %s) failed: %s", scope, region, e)
        return findings

    for acl in acls:
        name = acl.get("Name")
        acl_id = acl.get("Id")
        arn = acl.get("ARN", "")
        if not (name and acl_id):
            continue
        try:
            detail = client.get_web_acl(Name=name, Scope=scope, Id=acl_id)
        except (BotoCoreError, ClientError) as e:
            _log.debug("get_web_acl(%s) failed: %s", name, e)
            continue
        rules = (detail.get("WebACL") or {}).get("Rules", []) or []
        for rule in rules:
            rule_name = rule.get("Name", "<unnamed>")
            action = rule.get("Action") or {}
            override = rule.get("OverrideAction") or {}
            count_on_action = "Count" in action
            count_on_override = "Count" in override
            if not (count_on_action or count_on_override):
                continue
            why = ("Action.Count is set on top-level rule"
                   if count_on_action
                   else "OverrideAction.Count is set on managed rule group")
            findings.append({
                "title": _FINDING_TITLE,
                "severity": "HIGH",
                "check_id": _CHECK_ID,
                "resource_id": arn,
                "resource_type": _RESOURCE_TYPE,
                "region": region if scope == "REGIONAL" else "us-east-1",
                "details": (
                    f"Rule '{rule_name}' set to Count action — matches are "
                    f"logged but not blocked ({why}). CWE-1004 / CIS AWS 5.x."
                ),
                "remediation": _REMEDIATION,
                "framework": "AWS WAF",
            })
    return findings


def check_waf_count_mode(profile, regions: Iterable[str]) -> list[dict]:
    """Enumerate WAFv2 WebACLs and flag COUNT-mode rules.

    Args:
        profile: A whitebox CloudProfile (with ``_session`` set) OR a plain
            boto3.Session. Both are accepted.
        regions: Iterable of region names. CloudFront scope is ALWAYS scanned
            once via us-east-1 regardless of the regions list.

    Returns:
        List of finding dicts (see module docstring for schema).
    """
    session = getattr(profile, "_session", None) or profile
    if not isinstance(session, boto3.Session):
        # Fallback for unusual call sites — treat as default chain.
        session = boto3.Session()

    out: list[dict] = []

    # REGIONAL scope — one WAFv2 client per region.
    for region in regions or []:
        try:
            client = session.client("wafv2", region_name=region)
        except (BotoCoreError, ClientError) as e:
            _log.debug("wafv2 client (%s) init failed: %s", region, e)
            continue
        out.extend(_scan_scope(client, scope="REGIONAL", region=region))

    # CLOUDFRONT scope — pinned to us-east-1.
    try:
        cf_client = session.client("wafv2", region_name="us-east-1")
        out.extend(_scan_scope(cf_client, scope="CLOUDFRONT", region="us-east-1"))
    except (BotoCoreError, ClientError) as e:
        _log.debug("wafv2 CLOUDFRONT scope scan failed: %s", e)

    return out


__all__ = ["check_waf_count_mode"]
