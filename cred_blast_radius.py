"""Discovered-credential blast-radius assessment (STRICTLY READ-ONLY).

Wired into the secret-hunt phase: when TruffleHog flags a *verified* cloud credential in a
discovered artifact (e.g. an AWS key hard-coded in a public JS bundle), this module turns that
into impact — it enumerates, read-only, what the key can actually reach (identity, IAM-policy
reach, account-wide S3 visibility, downloadable DB backups, a PII-indicator scan) and emits a
report finding.

Born from a real 2026-06-10 engagement where a verified live AWS key in a SPA bundle gave
anonymous read of ~460 GB of production DB backups + Terraform state — and the whole assessment
had to be done by hand via boto3, OUTSIDE the tool.

SAFETY: every AWS call is asserted read-only before it is issued (`assert_readonly`). The module
NEVER mutates. Live enumeration is opt-in at the caller (hunt.py `--assess-creds`) because
auto-using a third-party credential is engagement-scope-sensitive.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field

try:  # botocore is a boto3 dep; guard so the pure helpers import without it
    from botocore.exceptions import ClientError as _ClientError
except Exception:  # pragma: no cover
    class _ClientError(Exception):
        pass


# ── discovered credential model ──────────────────────────────────────────────────

@dataclass
class DiscoveredCred:
    provider: str
    access_key_id: str
    secret: str
    source_file: str
    verified: bool
    extra: dict = field(default_factory=dict)
    session_token: str = ""  # set for temporary STS creds (AWSSessionKey detector)


# Exact, well-known TruffleHog detector names that map to a provider. Kept for clarity,
# but matching is intentionally NOT limited to this allowlist — see _aws_family() below.
_DETECTOR_PROVIDER = {"aws": "aws", "amazon": "aws"}


def _aws_family(detector_name: str) -> bool:
    """True if a TruffleHog DetectorName belongs to the AWS family.

    TruffleHog ships several distinct AWS detectors ("AWS" for long-lived AKIA keys,
    "AWSSessionKey" for temporary STS ASIA creds, etc.). An exact two-key allowlist silently
    dropped every detector except "AWS"/"Amazon" — including VERIFIED live session keys, which
    is exactly the high-impact case this module exists to surface. Match the whole family.
    """
    det = (detector_name or "").lower()
    return "aws" in det or "amazon" in det


def _extract_session_token(rec: dict) -> str:
    """Pull an STS session token out of a TruffleHog record, if present.

    TruffleHog's AWSSessionKey detector reports the temporary access-key-id + secret in
    Raw/RawV2 and the session token in ExtraData (key varies by version, hence the scan).
    Long-lived AKIA keys have no token and return "".
    """
    extra = rec.get("ExtraData") or {}
    if isinstance(extra, dict):
        for k, v in extra.items():
            kl = str(k).lower().replace("_", "")
            if "sessiontoken" in kl or "securitytoken" in kl:
                if v:
                    return str(v)
    return ""


def parse_verified_creds(trufflehog_json_path: str, log=None) -> list[DiscoveredCred]:
    """Extract VERIFIED cloud credentials from a TruffleHog ``--json`` (JSON-lines) file.

    Unverified hits (TruffleHog ``Verified: false``) are skipped — only keys proven live by
    the detector are worth a blast-radius assessment. Deduplicated by access-key-id.

    A VERIFIED hit whose detector is *not* AWS-family is skipped, but emits a degradation
    marker via ``log`` (if supplied) so a dropped live cloud cred is visible rather than
    vanishing silently.
    """
    out: dict[str, DiscoveredCred] = {}
    try:
        lines = open(trufflehog_json_path, encoding="utf-8", errors="ignore").read().splitlines()
    except OSError:
        return []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not rec.get("Verified"):
            continue
        det_name = str(rec.get("DetectorName", ""))
        if not _aws_family(det_name):
            # A VERIFIED, non-AWS cred — out of this module's scope, but DO NOT drop it
            # silently: mark the coverage gap so it can be triaged by hand.
            if log:
                log("degraded", f"verified non-AWS credential skipped by blast-radius "
                                f"assessment (detector={det_name!r}); handle manually")
            continue
        akid = rec.get("Raw") or ""
        rawv2 = rec.get("RawV2") or ""
        secret = rawv2.split(":", 1)[1] if ":" in rawv2 else ""
        token = _extract_session_token(rec)
        src = ""
        try:
            src = rec["SourceMetadata"]["Data"]["Filesystem"]["file"]
        except (KeyError, TypeError):
            src = ""
        if not akid or akid in out:
            continue
        out[akid] = DiscoveredCred(
            provider="aws", access_key_id=akid, secret=secret,
            source_file=src, verified=True, extra=rec.get("ExtraData") or {},
            session_token=token,
        )
    return list(out.values())


# ── read-only guard ──────────────────────────────────────────────────────────────

# The exact API operations this module is ever allowed to issue.
READONLY_AWS_OPS = frozenset({
    "GetCallerIdentity", "GetUser", "ListAttachedUserPolicies", "ListUserPolicies",
    "GetUserPolicy", "GetPolicy", "GetPolicyVersion", "ListGroupsForUser", "ListUsers",
    "ListBuckets", "ListObjectsV2", "HeadObject", "GetBucketLocation",
    "ListSecrets", "DescribeParameters", "ListFunctions", "DescribeInstances",
})
def assert_readonly(op: str) -> None:
    """Raise ``PermissionError`` unless ``op`` is an EXACT member of the read-only allowlist.

    Defence in depth: the enumerator only references read-only ops. An exact allowlist (no
    verb-prefix heuristic) is required — a prefix check would wave through a mutating op
    smuggled behind a read-only-looking verb (e.g. ``GetThenDeleteObject``).
    """
    if op in READONLY_AWS_OPS:
        return
    raise PermissionError(f"refusing non-read-only AWS operation: {op!r}")


# ── backup classification + PII-indicator scan (pure) ────────────────────────────

_BACKUP_EXT = (".bak", ".sql", ".dump", ".dmp", ".tfstate", ".bacpac")


def classify_backups(objects: list[dict]) -> list[dict]:
    """From S3 object dicts ({Key, Size, ...}) keep the backup/DB/IaC-state files, largest first."""
    baks = []
    for o in objects:
        k = (o.get("Key") or "").lower()
        if k.endswith(_BACKUP_EXT) or "backup" in k:
            baks.append(o)
    return sorted(baks, key=lambda o: o.get("Size", 0), reverse=True)


# Strong PII indicators only — deliberately NOT generic words like "client"/"user"/"account"
# (those false-positived heavily on media-intel prompt filenames in the live run).
_PII_RE = re.compile(
    r"(?i)(aadhaar|aadhar|pancard|\bpan\b|passport|\bkyc\b|\bssn\b|payroll|salary|"
    r"employe|emp[_-]?id|resume|\bdob\b|voter[_-]?id|gstin|\bifsc\b|credit[_-]?card|"
    r"\bcvv\b|bank[_-]?acc|nominee|beneficiary|biometric)"
)


def scan_pii_indicators(keys: list[str]) -> list[dict]:
    """Flag object keys whose *name* contains a strong PII indicator (filenames only)."""
    hits = []
    for k in keys:
        m = _PII_RE.search(k)
        if m:
            hits.append({"key": k, "indicator": m.group(1).lower()})
    return hits


# ── JS url <-> downloaded-file mapping ───────────────────────────────────────────

def js_source_url(downloaded_file: str, recon_dir: str) -> str | None:
    """Resolve the public URL a downloaded JS file came from.

    Primary: ``js/downloaded/manifest.tsv`` (``name<TAB>url``) written by the downloader.
    Fallback (old sessions w/o manifest): the downloader names files ``md5(url+"\\n").js``
    (``echo "$url" | md5sum``), so recompute over ``js/js_urls.txt`` to recover the URL.
    """
    name = os.path.basename(downloaded_file)
    manifest = os.path.join(recon_dir, "js", "downloaded", "manifest.tsv")
    try:
        for line in open(manifest, encoding="utf-8", errors="ignore"):
            parts = line.rstrip("\n").split("\t", 1)
            if len(parts) == 2 and parts[0] == name:
                return parts[1]
    except OSError:
        pass
    # fallback: recompute md5(url+"\n") over the discovered URL list
    for urls_file in (os.path.join(recon_dir, "js", "js_urls.txt"),
                      os.path.join(recon_dir, "urls", "js_files.txt")):
        try:
            for url in open(urls_file, encoding="utf-8", errors="ignore"):
                url = url.strip()
                if not url:
                    continue
                if hashlib.md5((url + "\n").encode()).hexdigest() + ".js" == name:
                    return url
        except OSError:
            continue
    return None


# ── AWS read-only blast-radius enumeration ───────────────────────────────────────

_SWEEP = [
    ("s3", "list_buckets", "ListBuckets", "s3:ListAllMyBuckets", {}),
    ("iam", "get_user", "GetUser", "iam:GetUser", None),  # UserName filled at runtime
    ("iam", "list_attached_user_policies", "ListAttachedUserPolicies",
     "iam:ListAttachedUserPolicies", None),
    ("secretsmanager", "list_secrets", "ListSecrets", "secretsmanager:ListSecrets", {"MaxResults": 1}),
    ("ssm", "describe_parameters", "DescribeParameters", "ssm:DescribeParameters", {"MaxResults": 1}),
    ("lambda", "list_functions", "ListFunctions", "lambda:ListFunctions", {"MaxItems": 1}),
    ("ec2", "describe_instances", "DescribeInstances", "ec2:DescribeInstances", {"MaxResults": 5}),
]


def _ro_call(client, method: str, api: str, **kw):
    """Issue a single read-only call; return (ok, response). Never raises on AWS errors."""
    assert_readonly(api)
    try:
        return True, getattr(client, method)(**kw)
    except _ClientError:
        return False, None
    except Exception:
        return False, None


def assess_aws_cred(cred: DiscoveredCred, session=None, region: str = "ap-south-1",
                    bucket_cap: int = 80, per_bucket_keys: int = 1000) -> dict:
    """READ-ONLY blast-radius assessment of a discovered AWS credential.

    ``session`` may be injected (tests / a pre-built boto3 Session); otherwise one is built from
    the credential. Returns a structured result dict. Issues only non-mutating API calls.
    """
    if session is None:  # pragma: no cover - exercised live, not in unit tests
        import boto3
        from botocore.config import Config
        session = boto3.Session(aws_access_key_id=cred.access_key_id,
                                aws_secret_access_key=cred.secret,
                                aws_session_token=cred.session_token or None,
                                region_name=region)
        session._vik_cfg = Config(connect_timeout=8, read_timeout=30,
                                  retries={"max_attempts": 2}, region_name=region)

    result: dict = {
        "access_key_id": cred.access_key_id, "account": cred.extra.get("account"),
        "source_file": cred.source_file, "identity": None, "capabilities": {},
        "buckets": [], "bucket_count": 0, "backups": [], "pii_indicators": [],
        "get_object": False, "is_admin": False, "severity": "info",
    }

    sts = session.client("sts")
    ok, ident = _ro_call(sts, "get_caller_identity", "GetCallerIdentity")
    if ok and ident:
        ident.pop("ResponseMetadata", None)
        result["identity"] = ident
    result["capabilities"]["sts:GetCallerIdentity"] = ok

    user = None
    if result["identity"] and result["identity"].get("Arn", "").count("/"):
        user = result["identity"]["Arn"].split("/")[-1]

    # capability sweep (read-only)
    for svc, method, api, capkey, kw in _SWEEP:
        client = session.client(svc)
        call_kw = dict(kw) if kw is not None else {}
        if kw is None and "user" in capkey.lower():
            if not user:
                result["capabilities"][capkey] = False
                continue
            call_kw["UserName"] = user
        ok, resp = _ro_call(client, method, api, **call_kw)
        result["capabilities"][capkey] = ok
        if svc == "s3" and method == "list_buckets" and ok and resp:
            result["buckets"] = [b["Name"] for b in resp.get("Buckets", [])]
            result["bucket_count"] = len(result["buckets"])

    # admin signal: could the key read its own IAM policy AND is an admin policy attached?
    iam = session.client("iam")
    if result["capabilities"].get("iam:ListAttachedUserPolicies") and user:
        ok, resp = _ro_call(iam, "list_attached_user_policies", "ListAttachedUserPolicies",
                            UserName=user)
        names = [p.get("PolicyName", "") for p in (resp or {}).get("AttachedPolicies", [])]
        result["is_admin"] = any("Administrator" in n or "PowerUser" in n for n in names)

    # S3 reach: list objects per bucket (capped), collect backups + PII indicators
    s3 = session.client("s3")
    all_keys: list[str] = []
    for b in result["buckets"][:bucket_cap]:
        ok, resp = _ro_call(s3, "list_objects_v2", "ListObjectsV2", Bucket=b, MaxKeys=per_bucket_keys)
        if not ok or not resp:
            continue
        objs = resp.get("Contents", []) or []
        for o in objs:
            o["_bucket"] = b
        for o in classify_backups(objs):
            result["backups"].append({"bucket": b, "Key": o.get("Key"), "Size": o.get("Size")})
        all_keys.extend((o.get("Key") or "") for o in objs)
    result["pii_indicators"] = scan_pii_indicators(all_keys)
    result["backups"].sort(key=lambda x: x.get("Size", 0), reverse=True)

    # prove read-CONTENT access via HeadObject metadata (no body) on one backup, else any key
    probe = None
    if result["backups"]:
        probe = (result["backups"][0]["bucket"], result["backups"][0]["Key"])
    if probe:
        ok, _ = _ro_call(s3, "head_object", "HeadObject", Bucket=probe[0], Key=probe[1])
        result["get_object"] = ok

    result["severity"] = _severity(result)
    return result


def _severity(r: dict) -> str:
    if r.get("is_admin"):
        return "critical"
    if r.get("get_object") and (r.get("backups") or r.get("bucket_count")):
        return "critical"
    if r.get("capabilities", {}).get("s3:ListAllMyBuckets") or r.get("bucket_count"):
        return "high"
    if r.get("identity"):
        return "medium"
    return "info"


# ── finding emitter (reporter-consumable) ────────────────────────────────────────

def write_finding(result: dict, findings_dir: str) -> str:
    """Write ``findings/exposed_credentials/findings.json`` for the HTML/MD reporter."""
    out_dir = os.path.join(findings_dir, "exposed_credentials")
    os.makedirs(out_dir, exist_ok=True)
    ident = result.get("identity") or {}
    finding = {
        "title": "Verified cloud credential exposed — confirmed blast radius",
        "severity": result.get("severity", "high"),
        "category": "Sensitive Data Exposure / Hard-coded Credentials (CWE-798)",
        "access_key_id": result.get("access_key_id"),
        "account": result.get("account") or ident.get("Account"),
        "principal": ident.get("Arn"),
        "source_url": result.get("source_url"),
        "source_file": result.get("source_file"),
        "is_admin": result.get("is_admin"),
        "get_object": result.get("get_object"),
        "bucket_count": result.get("bucket_count"),
        "capabilities": result.get("capabilities"),
        "backups": result.get("backups", [])[:50],
        "pii_indicators": result.get("pii_indicators", [])[:50],
        "remediation": ("Disable/rotate the access key immediately; review CloudTrail for use; "
                        "remove from source and re-architect to short-lived/scoped credentials."),
    }
    out = os.path.join(out_dir, "findings.json")
    # Accumulate: run() assesses multiple creds, each calling write_finding — merge into the
    # one file (dedup by access-key-id) so earlier creds aren't overwritten by the last.
    existing: list = []
    if os.path.exists(out):
        try:
            data = json.load(open(out, encoding="utf-8"))
            existing = data.get("findings", []) if isinstance(data, dict) else (data or [])
        except (ValueError, OSError):
            existing = []
    existing = [f for f in existing if f.get("access_key_id") != finding.get("access_key_id")]
    existing.append(finding)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"findings": existing}, fh, indent=2, default=str)
    return out


def _passive_result(cred: DiscoveredCred) -> dict:
    """A finding built purely from the TruffleHog metadata — NO boto3, NO network.

    A TruffleHog *verified* cloud credential is already a confirmed critical exposure; it must
    reach the report regardless of whether the active blast-radius sweep is enabled.
    """
    ex = cred.extra or {}
    return {
        "access_key_id": cred.access_key_id,
        "account": ex.get("account"),
        "source_file": cred.source_file,
        "identity": {"Account": ex.get("account"), "Arn": ex.get("arn")},
        "capabilities": {}, "buckets": [], "bucket_count": 0,
        "backups": [], "pii_indicators": [], "get_object": False,
        "is_admin": False, "severity": "critical", "passive": True,
    }


# ── orchestrator (called UNCONDITIONALLY from hunt.py run_secret_hunt) ────────────

def run(recon_dir: str, findings_dir: str, active: bool = False,
        session_factory=None, region: str = "ap-south-1", log=None) -> dict | None:
    """Report TruffleHog-verified cloud creds and (optionally) assess their blast radius.

    PASSIVE (always): emit a report finding for each verified credential — purely from the
    TruffleHog metadata, no network. ACTIVE (``active=True``, i.e. --assess-creds): additionally
    run the READ-ONLY boto3 blast-radius enumeration. Returns a summary, or None if no verified
    creds. ``session_factory(cred)`` lets a caller inject a boto3 session (tests / active mode).
    """
    def _log(level, msg):
        if log:
            log(level, msg)

    creds: dict[str, DiscoveredCred] = {}
    for rel in ("secrets/trufflehog_recon.json", "js/trufflehog.json"):
        for c in parse_verified_creds(os.path.join(recon_dir, rel), log=_log):
            creds.setdefault(c.access_key_id, c)
    if not creds:
        return None

    findings = []
    for c in creds.values():
        # ALWAYS start from the passive finding so a VERIFIED secret can never be lost — even if
        # the active enumeration errors (boto3 missing / session or client creation failure).
        result = _passive_result(c)
        if active:
            _log("crit", f"verified {c.provider.upper()} credential {c.access_key_id} — "
                         f"running READ-ONLY blast-radius assessment")
            try:
                session = session_factory(c) if session_factory else None
                result = assess_aws_cred(c, session=session, region=region)
            except Exception as e:
                _log("warn", f"  active blast-radius failed for {c.access_key_id}: {e} "
                             f"— keeping passive report")
        else:
            _log("crit", f"verified {c.provider.upper()} credential {c.access_key_id} exposed "
                         f"in {os.path.basename(c.source_file)} — reporting (run --assess-creds "
                         f"for read-only blast-radius)")
        result["source_url"] = js_source_url(c.source_file, recon_dir)
        path = write_finding(result, findings_dir)
        findings.append({"access_key_id": c.access_key_id, "severity": result["severity"],
                         "bucket_count": result.get("bucket_count", 0), "finding": path})
    return {"creds_assessed": len(findings), "active": active, "findings": findings}
