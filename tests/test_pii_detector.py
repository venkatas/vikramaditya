"""pii_detector — flag sensitive PII + bulk data exposure in AUTHENTICATED responses.

Closes a gap surfaced in an authenticated ASP.NET WebForms VAPT engagement: an internal directory
(a large directory) and thousands of client records (PAN/GSTIN) embedded in HTML
dropdowns/tables were invisible to the scanner — its PII_KEYS had no PAN/GSTIN/Aadhaar
and it never regex-scanned authenticated HTML for bulk disclosure.

ALL test data here is SYNTHETIC (structurally valid, never a real client/identity).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pii_detector  # noqa: E402

# --- synthetic fixtures (NOT real identities) ---
SYN_PAN = "ABCDE1234F"                 # 5 alpha + 4 num + 1 alpha
SYN_GSTIN = "27ABCDE1234F1Z5"          # 2 num + PAN + 1 num + Z + 1 alnum  (PAN embedded at offset 2)
SYN_EMAIL = "test.user@example.invalid"
SYN_MOBILE = "9876543210"


def test_detects_pan():
    r = pii_detector.scan(f"<td>PAN: {SYN_PAN}</td>")
    assert r["counts"].get("pan", 0) == 1


def test_gstin_detected_and_embedded_pan_not_double_counted():
    r = pii_detector.scan(f"<td>GSTIN {SYN_GSTIN}</td>")
    assert r["counts"].get("gstin", 0) == 1
    # chars 3-12 of a GSTIN ARE a PAN — must NOT be counted as a separate PAN
    assert r["counts"].get("pan", 0) == 0


def test_detects_email_and_indian_mobile():
    r = pii_detector.scan(f"reach {SYN_EMAIL} or call {SYN_MOBILE} today")
    assert r["counts"].get("email", 0) == 1
    assert r["counts"].get("phone", 0) == 1


def test_samples_are_masked_never_raw():
    r = pii_detector.scan(f"PAN {SYN_PAN}")
    samples = r["samples"]["pan"]
    assert samples, "expected a masked sample"
    assert all(SYN_PAN not in s for s in samples), "raw PII value must never be emitted"
    assert all("*" in s for s in samples)


def test_benign_text_yields_no_findings():
    r = pii_detector.scan("<p>Welcome to the dashboard. Nothing sensitive here.</p>")
    assert r["findings"] == []


def test_invalid_pan_structures_not_matched():
    # lowercase, too few letters, trailing digit instead of letter
    r = pii_detector.scan("abcde1234f and ABCD1234F and ABCDE12345")
    assert r["counts"].get("pan", 0) == 0


def test_bulk_directory_exposure_flagged():
    # synthetic dropdown of 60 fake employees -> bulk-list exposure finding
    opts = "".join(
        f'<option value="{i}">Emp_{i} Surname_{i} - {10000 + i}</option>' for i in range(60)
    )
    r = pii_detector.scan(f"<select name='ddlCustodian'>{opts}</select>")
    blf = [f for f in r["findings"] if f["type"] == "bulk_list_exposure"]
    assert blf, "a 60-entry embedded directory should raise bulk_list_exposure"
    assert blf[0]["count"] >= 60
    assert blf[0]["severity"] in ("medium", "high")


def test_bulk_pii_scales_severity_to_high():
    # 150 distinct synthetic GSTINs -> high-severity bulk sensitive-PII finding
    body = " ".join(f"27ABCDE{1000 + i}F1Z5" for i in range(150))
    r = pii_detector.scan(body)
    gst = next(f for f in r["findings"] if f["type"] == "gstin")
    assert gst["count"] == 150
    assert gst["severity"] == "high"
    # embedded PANs inside the 150 GSTINs must not be double-counted
    assert r["counts"].get("pan", 0) == 0


def test_scan_findings_carry_url_when_provided():
    r = pii_detector.scan(f"PAN {SYN_PAN}", url="https://app.invalid/RecordDetails?recordId=1")
    assert any(f.get("url") == "https://app.invalid/RecordDetails?recordId=1" for f in r["findings"])
