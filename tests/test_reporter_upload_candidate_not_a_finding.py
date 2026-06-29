"""reporter.py must NOT promote an unverified upload CANDIDATE to a finding.

A readable file (or merely-probed endpoint) in a web-accessible upload directory is a
DISCOVERY LEAD, not a verified unrestricted-file-upload vulnerability. The reporter
suppressed [UPLOAD-CANDIDATE-AUTH] but missed the plain [UPLOAD-CANDIDATE] / -POST /
-VALIDATION variants, so a real run turned 16 PUBLIC governance .html reports under
/wwwv3/upload/ into 16 HIGH "Unrestricted File Upload" (CVSS 8.8) findings — while the
scan's own summary.txt said "Verified Upload Only: 0". Only a confirmed write/exec
([UPLOAD-ONLY-POC], [POC-RCE-CONFIRMED], [VULN]) is a finding. (Audit HIGH — fabrication.)
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import reporter  # noqa: E402


def test_upload_candidates_are_suppressed_but_verified_poc_is_kept(tmp_path):
    upload = tmp_path / "upload"
    upload.mkdir()
    # Unverified leads — every one of these must be suppressed.
    (upload / "active_upload_probe.txt").write_text(
        "[UPLOAD-CANDIDATE] https://t.example.invalid/wwwv3/upload/governance/report_2019.html\n"
        "[UPLOAD-CANDIDATE-POST] https://t.example.invalid/upload/ (GET=200 -> POST=200)\n"
        "[UPLOAD-CANDIDATE-VALIDATION] https://t.example.invalid/upload/ (POST=415)\n"
        "[UPLOAD-CANDIDATE-AUTH] https://t.example.invalid/admin/upload/ (403)\n"
    )
    # A genuinely VERIFIED upload PoC — this one MUST survive.
    (upload / "verified_upload_pocs.txt").write_text(
        "[UPLOAD-ONLY-POC] https://t.example.invalid/upload/canary_abc123.txt :: stored + retrieved\n"
    )

    findings = reporter.load_findings(str(tmp_path))
    blob = "\n".join(str(f) for f in findings).lower()

    # No candidate line may become a finding ...
    assert "candidate" not in blob, "an unverified [UPLOAD-CANDIDATE*] line leaked into the report"
    # ... and specifically none should be scored as an Unrestricted File Upload HIGH ...
    upload_highs = [f for f in findings
                    if "unrestricted file upload" in str(f).lower() and "high" in str(f).lower()]
    assert not upload_highs, f"unverified upload candidates promoted to HIGH findings: {upload_highs}"
    # ... while the VERIFIED upload PoC is preserved.
    assert any("canary_abc123" in str(f) or "upload-only-poc" in str(f).lower()
               for f in findings), "the verified upload PoC was dropped from the report"
