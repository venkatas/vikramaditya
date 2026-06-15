"""Autopilot/Web App VAPT path must also report a VERIFIED leaked credential (coverage gap).

Live-monitoring 2026-06-15: the authenticated autopilot engine never ran the secret scan, so a
TruffleHog-verified AWS key in the front-end JS (the client-spa.example case) was silently dropped
on this path — only the hunt.py path reported it. `_report_js_credentials()` closes the gap:
it writes the fetched JS, runs TruffleHog, and reuses cred_blast_radius.run(active=False).
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import autopilot_api_hunt as ah  # noqa: E402

_TH_VERIFIED = json.dumps({
    "DetectorName": "AWS", "Verified": True, "Raw": "AKIAREPORT00000001",
    "RawV2": "AKIAREPORT00000001:thesecret",
    "ExtraData": {"account": "111111111111", "arn": "arn:aws:iam::111111111111:user/app"},
    "SourceMetadata": {"Data": {"Filesystem": {"file": "x/js/downloaded/abc.js", "line": 1}}},
})


def test_reports_verified_cred_from_js(tmp_path, monkeypatch):
    out = tmp_path / "out"
    out.mkdir()
    findings = []
    monkeypatch.setattr("shutil.which", lambda n: "/usr/bin/trufflehog" if n == "trufflehog" else None)

    def _fake_run(cmd, stdout=None, **kw):
        stdout.write(_TH_VERIFIED + "\n")   # simulate trufflehog writing its JSON to the file
        class _R:
            returncode = 0
        return _R()

    monkeypatch.setattr("subprocess.run", _fake_run)
    ah._report_js_credentials(str(out), {"/assets/index.js": "var k='AKIA...'"},
                              findings, None, "https://t.example")
    assert any(f.get("type") == "exposed_credential" and f.get("severity") == "critical"
               for f in findings), "a verified leaked key must be added to autopilot findings"
    data = json.loads((out / "findings" / "exposed_credentials" / "findings.json").read_text())["findings"]
    assert data[0]["access_key_id"] == "AKIAREPORT00000001"


def test_no_trufflehog_writes_js_but_does_not_crash(tmp_path, monkeypatch):
    out = tmp_path / "out"
    out.mkdir()
    findings = []
    monkeypatch.setattr("shutil.which", lambda n: None)   # trufflehog absent
    ah._report_js_credentials(str(out), {"/a.js": "x"}, findings, None, "https://t")
    assert findings == []
    assert (out / "js" / "downloaded" / "manifest.tsv").exists()   # JS still saved for later


def test_noop_on_empty_input(tmp_path):
    ah._report_js_credentials(str(tmp_path), {}, [], None, "https://t")   # must not crash/create
    assert not (tmp_path / "js").exists()
