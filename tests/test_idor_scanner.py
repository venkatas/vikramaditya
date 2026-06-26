"""idor_scanner — IDOR / Broken Object-Level Authorization detector.

Two modes (per friends' #1 recommendation + the proven engagement case):
  * enumeration: one session loads sequential object refs; if multiple return DISTINCT
    sensitive records => objects are not access-controlled (the the engagement /RecordDetails
    ?recordId=N case — one maker read every client's PAN/GSTIN).
  * differential: a non-owner session receives the same sensitive object data the owner
    does => cross-user access.

Composes pii_detector (sensitive-content check) + bfla_scanner.classify (gating). Synthetic data.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import idor_scanner  # noqa: E402


def _g(status, body="", location=""):
    return (status, body, location)


def test_enumeration_distinct_records_flags_bola():
    data = {
        "/RecordDetails?recordId=1": _g(200, "<td>PAN ABCDE1111A</td>"),
        "/RecordDetails?recordId=2": _g(200, "<td>PAN ABCDE2222B</td>"),
        "/RecordDetails?recordId=3": _g(200, "<td>PAN ABCDE3333C</td>"),
    }
    fs = idor_scanner.scan_enumeration(lambda r: data[r], list(data))
    assert fs and fs[0]["vuln_class"] == "IDOR/BOLA"
    assert fs[0]["refs_leaking"] == 3
    assert fs[0]["severity"] in ("medium", "high", "critical")


def test_enumeration_gated_not_flagged():
    fs = idor_scanner.scan_enumeration(lambda r: _g(403, "Forbidden"), ["/x?id=1", "/x?id=2"])
    assert fs == []


def test_enumeration_no_sensitive_data_not_flagged():
    fs = idor_scanner.scan_enumeration(lambda r: _g(200, "<p>ok</p>"), ["/x?id=1", "/x?id=2"])
    assert fs == []


def test_enumeration_same_record_not_flagged():
    # both refs return the SAME record (e.g. your own profile) -> not cross-object enumeration
    fs = idor_scanner.scan_enumeration(lambda r: _g(200, "PAN ABCDE1111A"), ["/x?id=1", "/x?id=2"])
    assert fs == []


def test_differential_cross_user_access_flagged():
    owner = lambda r: _g(200, "PAN ABCDE9999Z GSTIN 27ABCDE9999Z1Z5")
    other = lambda r: _g(200, "PAN ABCDE9999Z GSTIN 27ABCDE9999Z1Z5")
    fs = idor_scanner.scan_differential(owner, other, ["/RecordDetails?recordId=82"])
    assert fs and fs[0]["vuln_class"] == "IDOR/BOLA"
    assert fs[0]["severity"] in ("high", "critical")


def test_differential_other_denied_not_flagged():
    owner = lambda r: _g(200, "PAN ABCDE9999Z")
    other = lambda r: _g(302, "", "/login")
    fs = idor_scanner.scan_differential(owner, other, ["/x?id=1"])
    assert fs == []


def test_differential_owner_ref_invalid_skipped():
    # owner doesn't get sensitive data for this ref -> nothing to compare
    owner = lambda r: _g(404, "")
    other = lambda r: _g(200, "PAN ABCDE9999Z")
    fs = idor_scanner.scan_differential(owner, other, ["/x?id=999"])
    assert fs == []
