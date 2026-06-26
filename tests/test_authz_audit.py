"""authz_audit — orchestrates the authz/disclosure detectors over one authenticated
session and emits report-ready rows. Wires pii_detector + bfla_scanner + idor_scanner.
Synthetic fixtures only.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import authz_audit  # noqa: E402


def test_audit_aggregates_all_three_detectors():
    admin = {"/AdminQueue": (200, "<h1>Queue</h1><table>x</table>")}
    objs = {"/RecordDetails?id=1": (200, "PAN ABCDE1111A"),
            "/RecordDetails?id=2": (200, "PAN ABCDE2222B")}
    pages = {"/Onboard": (200, "<select>" + "".join("<option>e%d</option>" % i for i in range(40)) + "</select>")}
    alld = {**admin, **objs, **pages}
    low = lambda p: alld.get(p, (404, "", ""))
    unauth = lambda p: (302, "", "/login")
    fs = authz_audit.audit(low, unauth_get=unauth,
                           admin_paths=["/AdminQueue"],
                           object_refs=list(objs),
                           page_urls=list(pages))
    types = {f["type"] for f in fs}
    assert "broken_function_level_authorization" in types
    assert "idor_bola_enumeration" in types
    assert "bulk_list_exposure" in types


def test_audit_empty_when_everything_gated():
    fs = authz_audit.audit(lambda p: (403, "", ""), unauth_get=lambda p: (302, "", "/login"),
                           admin_paths=["/Admin"], object_refs=[], page_urls=[])
    assert fs == []


def test_to_report_rows_shape():
    rows = authz_audit.to_report_rows([
        {"type": "idor_bola_enumeration", "vuln_class": "IDOR/BOLA", "severity": "high",
         "evidence": "x", "confidence": "confirmed"},
    ])
    assert rows and "title" in rows[0] and rows[0]["severity"] == "high"


def test_to_reporter_findings_maps_to_valid_vtypes():
    findings = [
        {"type": "idor_bola_enumeration", "severity": "high", "evidence": "e", "confidence": "confirmed"},
        {"type": "broken_function_level_authorization", "severity": "high", "evidence": "e",
         "path": "/AdminQueue", "confidence": "confirmed"},
        {"type": "bulk_list_exposure", "severity": "medium", "evidence": "e", "url": "/x"},
    ]
    rows = authz_audit.to_reporter_findings(findings)
    vts = {r["type"] for r in rows}
    assert vts == {"idor", "auth_bypass", "exposure"}  # all are real reporter vtype keys
    for r in rows:
        assert {"severity", "type", "title", "url", "evidence", "poc", "confidence", "source"} <= set(r)
        assert r["source"] == "authz_audit"


def test_write_findings_json_roundtrip(tmp_path):
    import json
    p = authz_audit.write_findings_json(
        [{"type": "idor_bola_enumeration", "severity": "high", "evidence": "e", "confidence": "confirmed"}],
        str(tmp_path / "authz"))
    data = json.load(open(p))
    assert data and data[0]["type"] == "idor" and data[0]["severity"] == "high"
