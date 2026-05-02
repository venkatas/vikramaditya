"""Post-process Prowler findings to drop common false positives.

Three FP gating checks are applied (v9.x):

P0-1  rds_snapshots_public_access — FAIL only when DBSnapshotAttributes for the
      snapshot contains "all" in AttributeValues. Empty AttributeValues means
      Prowler flagged a snapshot whose public-restore is NOT actually granted.
P0-2  s3_bucket_policy_grants_write_access — FAIL only when at least one
      Statement with Principal:* (or Principal.AWS:*) has NO Condition. If
      ALL public-principal statements are gated by a Condition, the finding
      is a false positive.
P0-3  awslambda_function_url_public / public-policy — FAIL only when a
      Statement has Principal:* or Principal.AWS:*. AWS-service principals
      (events.amazonaws.com etc.) are normal and not public exposure.

Findings that fail the verification check are dropped from the returned list.
"""
from __future__ import annotations

import json
import re
from typing import Iterable

from whitebox.models import Finding

# check_id substrings that trigger each verifier
_RDS_PUBLIC = ("rds_snapshots_public_access",)
_S3_WRITE = ("s3_bucket_policy_grants_write_access",)
_LAMBDA_PUBLIC = (
    "awslambda_function_url_public",
    "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
)
_LAMBDA_TITLE_HINT = "lambda functions have resource-based policy set as public"
_RDS_TITLE_HINT = "rds snapshots and cluster snapshots are public"
_S3_TITLE_HINT = "s3 buckets have policies which allow write access"


def _arn_tail(arn: str) -> str:
    """Return final segment after the last ':' or '/' (snapshot id, bucket name, fn name)."""
    if not arn:
        return ""
    tail = arn.rsplit(":", 1)[-1]
    return tail.rsplit("/", 1)[-1]


def _matches(check_id: str, title: str, ids: Iterable[str], title_hint: str) -> bool:
    cid = (check_id or "").lower()
    if any(needle in cid for needle in ids):
        return True
    return title_hint in (title or "").lower()


def _verify_rds_snapshot_public(boto3_session, snapshot_id: str) -> bool:
    """Return True if snapshot is genuinely public (AttributeValues contains 'all')."""
    try:
        rds = boto3_session.client("rds")
        resp = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=snapshot_id)
        attrs = resp.get("DBSnapshotAttributesResult", {}).get("DBSnapshotAttributes", [])
        # Older boto schema returns the list at the top-level too
        if not attrs:
            attrs = resp.get("DBSnapshotAttributes", [])
        for a in attrs:
            if a.get("AttributeName") == "restore" and "all" in (a.get("AttributeValues") or []):
                return True
        return False
    except Exception:
        # On any error (perm, missing snapshot, cluster vs db) keep finding
        return True


def _verify_s3_write_public(boto3_session, bucket_name: str) -> bool:
    """Return True if bucket has a public-Principal write Statement WITHOUT a Condition."""
    try:
        s3 = boto3_session.client("s3")
        pol = s3.get_bucket_policy(Bucket=bucket_name)
        doc = json.loads(pol["Policy"])
    except Exception:
        return True  # cannot verify → keep finding to be safe

    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    public_stmts = []
    for st in statements:
        if st.get("Effect") != "Allow":
            continue
        princ = st.get("Principal")
        is_public = False
        if princ == "*":
            is_public = True
        elif isinstance(princ, dict):
            aws = princ.get("AWS")
            if aws == "*" or (isinstance(aws, list) and "*" in aws):
                is_public = True
        if is_public:
            public_stmts.append(st)
    if not public_stmts:
        return False  # no public stmt → FP
    # Real exposure if at least one public stmt has NO Condition
    for st in public_stmts:
        if not st.get("Condition"):
            return True
    return False


def _verify_lambda_public(boto3_session, fn_name: str) -> bool:
    """Return True if Lambda policy has a Principal:* or Principal.AWS:* Statement."""
    try:
        lam = boto3_session.client("lambda")
        resp = lam.get_policy(FunctionName=fn_name)
        doc = json.loads(resp["Policy"])
    except Exception:
        return True

    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for st in statements:
        princ = st.get("Principal")
        if princ == "*":
            return True
        if isinstance(princ, dict):
            if "Service" in princ and not any(k in princ for k in ("AWS", "Federated", "CanonicalUser")):
                continue  # service-only → not public
            aws = princ.get("AWS")
            if aws == "*" or (isinstance(aws, list) and "*" in aws):
                return True
    return False


def filter_prowler_fps(findings: list[Finding], boto3_session) -> list[Finding]:
    """Drop Prowler findings that fail post-process verification.

    boto3_session: a boto3.Session bound to the same profile that ran Prowler.
    Returns a new list containing only verified-real findings.
    """
    if boto3_session is None:
        return findings
    kept: list[Finding] = []
    for f in findings:
        if f.source != "prowler":
            kept.append(f)
            continue
        cid = f.rule_id or ""
        title = f.title or ""
        arn = f.cloud_context.arn if f.cloud_context else ""
        tail = _arn_tail(arn)

        try:
            if _matches(cid, title, _RDS_PUBLIC, _RDS_TITLE_HINT):
                if not _verify_rds_snapshot_public(boto3_session, tail):
                    continue  # drop FP
            elif _matches(cid, title, _S3_WRITE, _S3_TITLE_HINT):
                # bucket name is the resource tail or arn:aws:s3:::<bucket>
                bucket = tail or re.sub(r"^arn:aws:s3:::", "", arn)
                if bucket and not _verify_s3_write_public(boto3_session, bucket):
                    continue
            elif _matches(cid, title, _LAMBDA_PUBLIC, _LAMBDA_TITLE_HINT):
                if tail and not _verify_lambda_public(boto3_session, tail):
                    continue
        except Exception:
            # Verification crashed → keep finding (fail-open)
            pass
        kept.append(f)
    return kept
