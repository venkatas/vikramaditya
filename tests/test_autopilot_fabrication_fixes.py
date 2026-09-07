"""autopilot_api_hunt must not fabricate credential-leak / IDOR findings.

friends full-tool review (Group C):
  F12 — the AWS Access Key ID embedded in every SigV4 presigned URL
        (``X-Amz-Credential=AKIA...``) is PUBLIC and non-secret by design; the
        secret key signs the URL but never appears in it. Reporting the key ID as
        HIGH ``aws_key_exposed`` is a pure false positive on any working S3
        presigned-upload API.
  F11 — IDOR was declared HIGH whenever a 200 body contained a PII-named field,
        with NO owner baseline: an endpoint that ignores the supplied id and
        always returns the CALLER's own record (correct behaviour) was flagged.

All test data is SYNTHETIC (example.invalid / fake AKIA id).
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import autopilot_api_hunt as ah  # noqa: E402


class _FakeSession:
    """Minimal AuthSession stand-in for FileUploadTester."""
    base_url = "https://t.example.invalid"

    def __init__(self, presigned=True):
        self._presigned = presigned

    def request(self, method, path, data=None, **kw):
        if "get-aws-sign-upload-video" in path and self._presigned:
            return {"status": 200, "body": {
                "uploadUrl": ("https://bkt.s3.amazonaws.com/test.html?"
                              "X-Amz-Credential=AKIAFAKE000000000000%2F20260101%2F"
                              "us-east-1%2Fs3%2Faws4_request&"
                              "X-Amz-Signature=deadbeefdeadbeef")}}
        return {"status": 404, "body": {}}


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    # FileUploadTester's profile-image bypass calls requests.post directly.
    import requests

    def _boom(*a, **k):
        raise RuntimeError("network disabled in test")

    monkeypatch.setattr(requests, "post", _boom)


def test_sigv4_presigned_access_key_id_not_reported_as_credential():
    findings = ah.FileUploadTester().run(_FakeSession(presigned=True))
    types = [f.get("type") for f in findings]
    assert "aws_key_exposed" not in types, (
        "the AWS Access Key ID in a SigV4 presigned URL is public/non-secret — "
        "reporting it as a credential leak is a false positive")


class _ScriptedIdSession:
    """AuthSession stand-in for IDORScanner: maps the requested id to a record."""
    base_url = "https://t.example.invalid"

    def __init__(self, record_fn):
        self._record_fn = record_fn

    def request(self, method, path, data=None, json_body=None, **kw):
        payload = data or json_body or {}
        rid = str(payload.get("id") or payload.get("learner_id") or "")
        body = self._record_fn(rid)
        if body is None:
            return {"status": 404, "body": {}, "url": path, "method": method}
        return {"status": 200, "body": body,
                "url": f"{self.base_url}/{path}?id={rid}", "method": method}


_IDOR_EPS = [{"path": "view-profile", "method": "POST"}]


def test_idor_endpoint_ignoring_id_returns_own_record_is_benign():
    # Server ignores the id and always returns the CALLER's own record. PII is
    # present and 200 OK, but it is NOT IDOR — must not fire (F11 owner-baseline).
    sess = _ScriptedIdSession(lambda rid: {
        "data": {"id": "self-101", "email": "caller@example.invalid",
                 "first_name": "Caller"}})
    findings = ah.IDORScanner().run(sess, _IDOR_EPS)
    assert not any(f.get("type") == "idor" for f in findings), (
        "an endpoint that echoes the caller's own record for every id is not IDOR")


def test_idor_distinct_record_per_id_fires():
    # Server honors the id and returns a DIFFERENT user's record per id → genuine
    # IDOR. Must fire (exactly once for the endpoint, not once per id).
    sess = _ScriptedIdSession(lambda rid: {
        "data": {"id": rid, "email": f"user{rid}@example.invalid",
                 "first_name": f"User{rid}"}} if rid else None)
    findings = ah.IDORScanner().run(sess, _IDOR_EPS)
    idor = [f for f in findings if f.get("type") == "idor"]
    assert idor, "distinct PII records across ids is a genuine IDOR and must fire"
    assert len(idor) == 1, f"IDOR must be reported once per endpoint, got {len(idor)}"
