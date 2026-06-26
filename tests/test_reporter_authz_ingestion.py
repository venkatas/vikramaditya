"""reporter.py Method 1i — ingest authz/findings.json (BFLA/IDOR/PII detectors).

authz_audit_run writes <findings_dir>/authz/findings.json as a JSON list of
{severity,type,title,url,detail,evidence,poc,confidence,source:"authz_audit"} — the same
contract burp uses (Method 1g). Without a dedicated loader these were silently dropped.
All data here is SYNTHETIC.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from reporter import load_findings  # noqa: E402


def _seed(tmp_path, items):
    d = tmp_path / "authz"
    d.mkdir()
    (d / "findings.json").write_text(json.dumps(items))
    return d


def test_authz_findings_ingested_with_vtypes(tmp_path):
    _seed(tmp_path, [
        {"severity": "high", "type": "auth_bypass", "title": "BFLA (/AdminQueue)",
         "url": "https://app.invalid/AdminQueue", "detail": "BFLA", "evidence": "x",
         "poc": "poc", "confidence": "confirmed", "source": "authz_audit"},
        {"severity": "critical", "type": "idor", "title": "IDOR enumeration",
         "url": "https://app.invalid/RecordDetails?recordId=1", "detail": "idor",
         "evidence": "y", "poc": "poc2", "confidence": "confirmed", "source": "authz_audit"},
    ])
    fs = load_findings(str(tmp_path))
    vtypes = {f["vtype"] for f in fs}
    assert "auth_bypass" in vtypes and "idor" in vtypes
    idor = next(f for f in fs if f["vtype"] == "idor")
    assert idor["severity"] == "critical"     # authz IDOR keeps critical (NOT clamped like burp)
    assert "RecordDetails" in idor["url"]
    assert idor.get("poc")                     # poc prose preserved


def test_unknown_vtype_falls_back_to_misconfig(tmp_path):
    _seed(tmp_path, [{"severity": "medium", "type": "totally_unknown", "title": "weird",
                      "url": "u", "detail": "d", "poc": "p", "source": "authz_audit"}])
    fs = [f for f in load_findings(str(tmp_path)) if f.get("title") == "weird"]
    assert fs and fs[0]["vtype"] == "misconfig"


def test_candidate_critical_is_clamped_to_high(tmp_path):
    # anti-fabrication: an UNCONFIRMED (candidate) finding must never ship as Critical
    _seed(tmp_path, [{"severity": "critical", "type": "exposure", "title": "bulkcand",
                      "url": "u", "detail": "d", "poc": "p", "confidence": "candidate",
                      "source": "authz_audit"}])
    f = next(f for f in load_findings(str(tmp_path)) if f.get("title") == "bulkcand")
    assert f["severity"] == "high"


def test_no_authz_dir_does_not_error(tmp_path):
    assert isinstance(load_findings(str(tmp_path)), list)
