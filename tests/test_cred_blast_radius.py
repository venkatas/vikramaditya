"""Discovered-credential blast-radius assessment (wired into the secret-hunt phase).

GAP (real 2026-06-10 engagement): TruffleHog flagged a VERIFIED live AWS key in a public JS
bundle, but Vikramaditya had no way to turn that into impact — there was no module to take a
DISCOVERED key and (read-only) enumerate what it can reach. The whole blast-radius assessment
(identity, IAM-policy reach, account-wide S3 visibility, ~460 GB of downloadable DB backups,
PII-indicator scan) had to be done by hand via boto3, OUTSIDE the tool.

This module wires that in: parse verified cloud creds from TruffleHog output, run a STRICTLY
READ-ONLY blast-radius assessment, and emit a report finding. Live enumeration is opt-in
(--assess-creds) because auto-using a 3rd-party credential is scope-sensitive.

Also covers the JS url->file manifest gap: the JS downloader names files md5(url+"\\n").js with
no URL map, so a finding couldn't carry its public URL without a live re-fetch.
"""
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import cred_blast_radius as cbr  # noqa: E402


# ── parse verified creds from TruffleHog JSON-lines ──────────────────────────────

def _th_record(detector, verified, akid, secret, **extra):
    rec = {
        "DetectorName": detector,
        "Verified": verified,
        "Raw": akid,
        "RawV2": f"{akid}:{secret}",
        "ExtraData": extra,
        "SourceMetadata": {"Data": {"Filesystem": {"file": "/x/js/downloaded/abc.js", "line": 22}}},
    }
    return json.dumps(rec)


def test_parse_extracts_only_verified_aws(tmp_path):
    p = tmp_path / "trufflehog.json"
    p.write_text("\n".join([
        _th_record("AWS", True, "AKIAEXAMPLE000000001", "secretone",
                   account="111111111111", arn="arn:aws:iam::111111111111:user/app"),
        _th_record("AWS", False, "AKIAEXAMPLE000000002", "secrettwo"),   # unverified -> skip
        _th_record("Heroku", False, "hkey", "hsecret"),                  # unverified -> skip
    ]))
    creds = cbr.parse_verified_creds(str(p))
    assert len(creds) == 1
    c = creds[0]
    assert c.provider == "aws"
    assert c.access_key_id == "AKIAEXAMPLE000000001"
    assert c.verified is True


def test_parse_dedups_same_key_across_files(tmp_path):
    p = tmp_path / "trufflehog.json"
    rec = _th_record("AWS", True, "AKIADUP000000000001", "s", account="1")
    p.write_text(rec + "\n" + rec + "\n")  # same key twice
    creds = cbr.parse_verified_creds(str(p))
    assert len(creds) == 1


def test_parse_captures_secret_and_extra(tmp_path):
    p = tmp_path / "t.json"
    p.write_text(_th_record("AWS", True, "AKIAXYZ0000000000001", "topsecret",
                            account="222222222222", arn="arn:aws:iam::222222222222:user/client-spa"))
    c = cbr.parse_verified_creds(str(p))[0]
    assert c.secret == "topsecret"
    assert c.extra.get("account") == "222222222222"
    assert c.source_file.endswith("abc.js")


# ── read-only guard ──────────────────────────────────────────────────────────────

def test_assert_readonly_allows_safe_ops():
    for op in ("GetCallerIdentity", "ListBuckets", "ListObjectsV2", "HeadObject",
               "ListAttachedUserPolicies", "DescribeInstances"):
        cbr.assert_readonly(op)  # must not raise


@pytest.mark.parametrize("op", ["PutObject", "DeleteObject", "CreateUser", "PutUserPolicy",
                                 "DeleteBucket", "AttachUserPolicy", "RunInstances"])
def test_assert_readonly_rejects_mutating(op):
    with pytest.raises(Exception):
        cbr.assert_readonly(op)


@pytest.mark.parametrize("op", ["GetThenDeleteObject", "ListAndPurge", "DescribeAndTerminate"])
def test_assert_readonly_rejects_prefix_lookalikes(op):
    """A read-only-looking PREFIX must NOT be enough — only exact allowlisted ops pass, else a
    mutating op smuggled behind a 'Get'/'List' prefix would slip through (Codex HIGH)."""
    with pytest.raises(Exception):
        cbr.assert_readonly(op)


# ── backup classification ────────────────────────────────────────────────────────

def test_classify_backups_filters_and_sorts():
    objs = [
        {"Key": "demoE.bak", "Size": 211 * 1024**3, "LastModified": "2025-07-18"},
        {"Key": "notes.txt", "Size": 10, "LastModified": "2025-01-01"},
        {"Key": "dev.tfstate", "Size": 559000, "LastModified": "2025-05-28"},
        {"Key": "small.bak", "Size": 100, "LastModified": "2024-01-01"},
    ]
    baks = cbr.classify_backups(objs)
    keys = [b["Key"] for b in baks]
    assert "notes.txt" not in keys
    assert "demoE.bak" in keys and "dev.tfstate" in keys
    # sorted by size desc
    assert keys[0] == "demoE.bak"


# ── PII-indicator filename scan (strong terms only; no generic "client" FP) ──────

def test_scan_pii_indicators_matches_strong_terms():
    keys = [
        "hr/payroll_march_2025.csv",
        "kyc/aadhaar_scan_123.pdf",
        "exports/employees_pan.xlsx",
        "Prompt/TLPMID_1/prompt_1_relevant_to_client.txt",   # must NOT match (generic 'client')
        "DOSSIER/CACHE/Online/10000477.jpg",                  # must NOT match
    ]
    hits = cbr.scan_pii_indicators(keys)
    hit_keys = {h["key"] for h in hits}
    assert "hr/payroll_march_2025.csv" in hit_keys
    assert "kyc/aadhaar_scan_123.pdf" in hit_keys
    assert "exports/employees_pan.xlsx" in hit_keys
    assert "Prompt/TLPMID_1/prompt_1_relevant_to_client.txt" not in hit_keys
    assert "DOSSIER/CACHE/Online/10000477.jpg" not in hit_keys


# ── JS url->file manifest lookup ─────────────────────────────────────────────────

def test_js_source_url_from_manifest(tmp_path):
    recon = tmp_path
    dl = recon / "js" / "downloaded"
    dl.mkdir(parents=True)
    (dl / "manifest.tsv").write_text("abc123.js\thttps://client-spa.example/assets/index-x.js\n")
    url = cbr.js_source_url("abc123.js", str(recon))
    assert url == "https://client-spa.example/assets/index-x.js"


def test_js_source_url_fallback_md5_of_urls(tmp_path):
    """Backward-compat: old sessions have NO manifest, but filename == md5(url+'\\n').js,
    so we can recover the URL by recomputing over js_urls.txt."""
    import hashlib
    recon = tmp_path
    (recon / "js").mkdir(parents=True)
    (recon / "js" / "downloaded").mkdir(parents=True)
    url = "https://client-spa.example/assets/index-a69278c9.js"
    name = hashlib.md5((url + "\n").encode()).hexdigest() + ".js"
    (recon / "js" / "js_urls.txt").write_text(url + "\n")
    got = cbr.js_source_url(name, str(recon))
    assert got == url


def test_js_source_url_returns_none_when_unknown(tmp_path):
    (tmp_path / "js" / "downloaded").mkdir(parents=True)
    assert cbr.js_source_url("nope.js", str(tmp_path)) is None


# ── assess_aws_cred with a mocked boto3 session ──────────────────────────────────

class _FakeClient:
    def __init__(self, name, behaviors):
        self._name = name
        self._b = behaviors

    def __getattr__(self, method):
        def _call(**kw):
            spec = self._b.get(method)
            if spec is None:
                from botocore.exceptions import ClientError
                raise ClientError({"Error": {"Code": "AccessDenied"}}, method)
            if isinstance(spec, Exception):
                raise spec
            return spec(**kw) if callable(spec) else spec
        return _call


class _FakeSession:
    def __init__(self, per_service):
        self._svc = per_service

    def client(self, name, **kw):
        return _FakeClient(name, self._svc.get(name, {}))


def _client_error(code):
    from botocore.exceptions import ClientError
    return ClientError({"Error": {"Code": code}}, "op")


def test_assess_aws_cred_summarizes_readonly_reach():
    sess = _FakeSession({
        "sts": {"get_caller_identity": {"Account": "222222222222", "UserId": "AID",
                                        "Arn": "arn:aws:iam::222222222222:user/client-spa"}},
        # IAM introspection denied (not admin)
        "iam": {},
        "s3": {
            "list_buckets": {"Buckets": [{"Name": "adfactor-db-backup"}, {"Name": "client-spa-ai"}]},
            "list_objects_v2": lambda **kw: {
                "Contents": [{"Key": "demoE.bak", "Size": 226492416000, "LastModified": "2025-07-18"}],
                "KeyCount": 1, "IsTruncated": False},
            "head_object": {"ContentLength": 2646016},
        },
        "secretsmanager": {}, "ssm": {}, "lambda": {}, "ec2": {},
    })
    cred = cbr.DiscoveredCred(provider="aws", access_key_id="AKIA", secret="s",
                              source_file="x.js", verified=True, extra={"account": "222222222222"})
    r = cbr.assess_aws_cred(cred, session=sess)
    assert r["identity"]["Account"] == "222222222222"
    assert r["capabilities"]["s3:ListAllMyBuckets"] is True
    assert r["capabilities"]["iam:GetUser"] is False        # denied
    assert r["capabilities"]["secretsmanager:ListSecrets"] is False
    assert r["bucket_count"] == 2
    assert any(b["Key"] == "demoE.bak" for b in r["backups"])
    assert r["get_object"] is True                           # head_object succeeded
    assert r["is_admin"] is False


# ── write_finding emits a reporter-consumable artifact ───────────────────────────

def test_run_passive_emits_finding_without_boto3(tmp_path):
    """CRITICAL: a TruffleHog-verified credential must be REPORTED even without --assess-creds
    (passive, no boto3). Before the fix, a verified live AWS key was silently dropped from the
    report unless the active flag was set."""
    recon = tmp_path / "recon"
    (recon / "secrets").mkdir(parents=True)
    (recon / "secrets" / "trufflehog_recon.json").write_text(
        _th_record("AWS", True, "AKIAPASSIVE000000001", "sek",
                   account="111111111111", arn="arn:aws:iam::111111111111:user/app") + "\n")
    findings = tmp_path / "findings"
    # no session_factory: if the passive path wrongly attempted boto3 it would blow up
    summary = cbr.run(str(recon), str(findings), active=False)
    assert summary and summary["creds_assessed"] == 1
    assert summary["active"] is False
    data = json.loads((findings / "exposed_credentials" / "findings.json").read_text())["findings"]
    assert data[0]["access_key_id"] == "AKIAPASSIVE000000001"
    assert data[0]["severity"] == "critical"
    assert data[0]["account"] == "111111111111"


def test_run_active_failure_still_writes_passive_finding(tmp_path):
    """Codex HIGH: in ACTIVE mode, if the boto3 enumeration raises, the verified secret must NOT
    be dropped — the passive finding is written first, enrichment is best-effort."""
    recon = tmp_path / "recon"
    (recon / "secrets").mkdir(parents=True)
    (recon / "secrets" / "trufflehog_recon.json").write_text(
        _th_record("AWS", True, "AKIAACTFAIL0000001", "s",
                   account="999999999999", arn="arn:aws:iam::999999999999:user/x") + "\n")
    findings = tmp_path / "findings"

    def _boom(cred):
        raise RuntimeError("boto3 unavailable")

    summary = cbr.run(str(recon), str(findings), active=True, session_factory=_boom)
    assert summary and summary["creds_assessed"] == 1
    data = json.loads((findings / "exposed_credentials" / "findings.json").read_text())["findings"]
    assert data[0]["access_key_id"] == "AKIAACTFAIL0000001"
    assert data[0]["severity"] == "critical"  # passive fallback kept it


def test_run_returns_none_when_no_verified_creds(tmp_path):
    recon = tmp_path / "recon"
    (recon / "secrets").mkdir(parents=True)
    (recon / "secrets" / "trufflehog_recon.json").write_text(
        _th_record("AWS", False, "AKIAUNVERIFIED000001", "s") + "\n")
    assert cbr.run(str(recon), str(tmp_path / "findings"), active=False) is None


def test_write_finding_accumulates_across_creds(tmp_path):
    """run() assesses multiple creds; each write_finding call must PERSIST, not overwrite the
    previous (Codex MED — only the last cred survived before)."""
    base = {"identity": {"Account": "1"}, "capabilities": {"s3:ListAllMyBuckets": True},
            "bucket_count": 1, "backups": [], "pii_indicators": [],
            "get_object": True, "is_admin": False, "severity": "critical"}
    r1 = dict(base, access_key_id="AKIA1")
    r2 = dict(base, access_key_id="AKIA2", severity="high")
    cbr.write_finding(r1, str(tmp_path))
    out = cbr.write_finding(r2, str(tmp_path))
    findings = json.loads(Path(out).read_text())["findings"]
    assert {f.get("access_key_id") for f in findings} == {"AKIA1", "AKIA2"}


def test_write_finding_emits_json(tmp_path):
    result = {"identity": {"Account": "1", "Arn": "arn:aws:iam::1:user/k"},
              "capabilities": {"s3:ListAllMyBuckets": True},
              "bucket_count": 59, "backups": [{"Key": "x.bak", "Size": 100}],
              "pii_indicators": [], "get_object": True, "is_admin": False,
              "severity": "critical", "source_url": "https://k/assets/i.js"}
    out = cbr.write_finding(result, str(tmp_path))
    assert Path(out).exists()
    data = json.loads(Path(out).read_text())
    # reporter expects a list-or-{"findings":[...]} of finding dicts
    findings = data["findings"] if isinstance(data, dict) else data
    assert findings and findings[0]["severity"] == "critical"
    assert "ListAllMyBuckets" in json.dumps(findings[0])
