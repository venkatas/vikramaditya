"""reporter.py must NOT promote unverified scanner markers to medium+ findings.

A multi-agent audit found that, besides the [UPLOAD-CANDIDATE*] leak, several other
unverified discovery/heuristic markers were shipping as medium+ findings because their
prefix/file was never registered in NON_FINDING_PREFIXES / NON_FINDING_FILES:

  - cves/exposed_configs.txt   -> CRITICAL 9.0 "Known CVE Vulnerability" (a readable config URL is not a CVE)
  - [UPLOAD-ACCEPTED-UNVERIFIED] -> HIGH 8.8 (POST accepted but canary never retrieved = no write/exec confirm)
  - [IMPORT-ENDPOINT]/[CONVERTER-ENDPOINT] -> HIGH 8.1 (endpoint discovery, fires on 403/405)
  - [JAVA-DESER]/[PHP-DESER]/[JAVA-RMI] -> HIGH 8.8 (deser fingerprints, no gadget executed)
  - supply_chain/snippets.txt  -> HIGH 7.5 per raw response-body line (real finding is [CRED-FILE])
  - xss/xsstrike_results.txt   -> MEDIUM XSS (raw `grep xss|payload|vulnerable` chatter; dalfox is the verified path)

Each must be suppressed, while EMPIRICALLY-VERIFIED markers ([UPLOAD-ONLY-POC],
[CRED-FILE], [POC-RCE-CONFIRMED], [SQLI-POC-VERIFIED], dalfox PoCs) must still surface.
(Audit: 1 CRITICAL + 6 HIGH + 1 MEDIUM fabrication class.)
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import reporter  # noqa: E402

_MEDPLUS = {"critical", "high", "medium"}


def _worst(tmp_path, relpath, line):
    fp = tmp_path / relpath
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(line + "\n")
    worst = None
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0}
    for f in reporter.load_findings(str(tmp_path)):
        s = str(f.get("severity", "")).lower() if isinstance(f, dict) else ""
        if s in order and (worst is None or order[s] > order[worst]):
            worst = s
    fp.unlink()
    return worst


SUPPRESS = [
    # NB: cves/exposed_configs.txt is NO LONGER suppressed — it is re-surfaced as a dedicated
    # MEDIUM "Exposed Configuration File" finding (friends-review). See the deep-leak test
    # test_exposed_config_is_surfaced_not_dropped. It must just never be a CRITICAL "Known CVE".
    ("upload/accepted_unverified.txt", "[UPLOAD-ACCEPTED-UNVERIFIED] https://t.example.invalid/up | canary=abc stored but not located"),
    ("import_export/endpoints.txt", "[IMPORT-ENDPOINT] https://t.example.invalid/import (GET=403)"),
    ("import_export/converters.txt", "[CONVERTER-ENDPOINT] https://t.example.invalid/convert (POST=405)"),
    ("deserialize/findings.txt", "[JAVA-DESER] https://t.example.invalid/x (Content-Type: application/x-java-serialized-object)"),
    ("deserialize/findings.txt", "[PHP-DESER] https://t.example.invalid/y (unserialize error reflected)"),
    ("deserialize/findings.txt", "[JAVA-RMI] https://t.example.invalid/z (401, JBoss/MBean banner)"),
    ("supply_chain/snippets.txt", "always-auth=true"),
    ("xss/xsstrike_results.txt", "https://t.example.invalid/s?q=FUZZ payload reflected"),
    # Fix Round 3 (hunt.py Task 9): tls_impersonation.detect_bot_management/
    # record_waf_block started actually being called from hunt.py's phases —
    # this is an operator coverage note ("this phase got blocked by a WAF"),
    # not a client-side misconfiguration.
    ("misconfig/waf_fingerprint.txt",
     "[WAF-BLOCK-DETECTED] 2026-07-06T00:00:00+00:00 | product=cloudflare | url=https://t.example.invalid/login"),
    # hunt.py run_jwt_audit writes per-token jwt_<N>.txt (the raw token) and
    # jwt_<N>_results.txt (jwt_tool decode / alg=none / crack NARRATIVE output).
    # jwt_tool `-X a` (no -t) only *generates* a forged token locally — it never
    # sends it, so it proves nothing about server acceptance. These are
    # manual-followup leads, not findings; every non-`#` line was shipping as a
    # fabricated HIGH "jwt" finding via the generic Method-1 .txt loader.
    ("jwt/jwt_1.txt", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.s5c8Rt0kA1b2C3d4E5f6G7h8I9j0K"),
    ("jwt/jwt_1_results.txt", "Original JWT: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.sig | alg=HS256 sub=admin"),
    ("jwt/jwt_2_results.txt", "[+] Testing potential signing keys... jwttool_forged=eyJ0eXAiOi...tampered token"),
    # ── friends full-tool review (Group A): MFA/SAML markers that are NOT a
    # confirmed auth bypass were shipping as CRITICAL 9.8 auth_bypass because
    # mfa/ and saml/ map to the (critical) auth_bypass template and no prefix
    # suppressed them.
    #   [MFA-RESPONSE-MANIP]: server merely returns a JSON {"success":false}
    #     for a WRONG OTP — i.e. SECURE behaviour. scanner.sh's own comment
    #     calls it "indicator only". Pure false positive.
    ("mfa/findings.txt", "[MFA-RESPONSE-MANIP] https://t.example.invalid/otp | change false->true in response"),
    #   [MFA-NO-RATE-LIMIT]: missing 429 on an OTP endpoint is (at most) a MEDIUM
    #     rate-limiting gap, NOT a CRITICAL authentication bypass.
    ("mfa/findings.txt", "[MFA-NO-RATE-LIMIT] https://t.example.invalid/otp | codes:    12 200"),
    #   [SAML-METADATA-EXPOSED]: a public SP/IdP SAML metadata document is public
    #     BY DESIGN (that is how federation works). Not an auth bypass.
    ("saml/findings.txt", "[SAML-METADATA-EXPOSED] https://t.example.invalid/saml/metadata"),
    #   saml/certs.txt: raw <X509Certificate> evidence lines were each ingested as
    #     their own CRITICAL auth_bypass finding. Evidence file, not a finding file.
    ("saml/certs.txt", "<X509Certificate>MIIDazCCAlOgAwIBAgIUABCDEF0123456789fakecertdata</X509Certificate>"),
]

KEEP = [
    ("upload/verified_upload_pocs.txt", "[UPLOAD-ONLY-POC] https://t.example.invalid/up/canary123.txt :: stored+retrieved"),
    ("supply_chain/findings.txt", "[CRED-FILE] https://t.example.invalid/.npmrc"),
    ("rce/verified.txt", "[POC-RCE-CONFIRMED] https://t.example.invalid/x cmd=id uid=0"),
    ("sqli/timebased_candidates.txt", "[SQLI-POC-VERIFIED] https://t.example.invalid/a?id=1 :: time-based confirmed"),
    # A genuinely cracked weak signing secret IS an empirically-confirmed
    # finding — run_jwt_audit writes it as a structured [JWT-WEAK-SECRET-
    # CONFIRMED] line into the canonical jwt/jwt_confirmed.txt (NOT a numbered
    # jwt_<N>*.txt narrative file), so the numbered-file exemption must not
    # swallow it.
    ("jwt/jwt_confirmed.txt", "[JWT-WEAK-SECRET-CONFIRMED] https://t.example.invalid/api :: jwt_tool -C cracked weak signing secret 'secret123'"),
    # ── friends full-tool review (Group A): the CONFIRMED auth-bypass markers in
    # the SAME mfa/ and saml/ dirs must still surface — suppression of the
    # unverified siblings above must not over-suppress these.
    #   [MFA-WORKFLOW-SKIP]: protected page reached pre-MFA with an authenticated
    #     marker AND differing from the unauth baseline (scanner.sh gates all three).
    ("mfa/findings.txt", "[MFA-WORKFLOW-SKIP] https://t.example.invalid/dashboard accessible (HTTP 200, authenticated content, differs from unauth baseline)"),
    #   [SAML-SIG-STRIP]: an UNSIGNED assertion established a real session — a
    #     genuine signature-bypass.
    ("saml/findings.txt", "[SAML-SIG-STRIP] https://t.example.invalid/saml/acs | HTTP 200 | unsigned assertion established a session"),
]


def test_unverified_markers_do_not_become_findings(tmp_path):
    for relpath, line in SUPPRESS:
        worst = _worst(tmp_path, relpath, line)
        assert worst not in _MEDPLUS, (
            f"unverified marker leaked as {worst} finding: {relpath} :: {line[:50]}")


def test_verified_markers_are_still_reported(tmp_path):
    for relpath, line in KEEP:
        worst = _worst(tmp_path, relpath, line)
        assert worst is not None, (
            f"a VERIFIED marker was over-suppressed (dropped from report): {relpath} :: {line[:50]}")


def test_idor_poc_uses_real_evidence_not_invented_pii(tmp_path):
    """friends full-tool review F10: the autopilot IDOR PoC hard-coded
    "Alice"/"victim@example.com"/"9000000000" under a "WHAT THE SERVER RETURNS
    (actual response)" header — invented PII presented as the real server
    response in a client report. The PoC must render the finding's REAL captured
    evidence instead."""
    import json as _json
    (tmp_path / "finding_001.json").write_text(_json.dumps({
        "type": "idor", "severity": "high",
        "url": "https://t.example.invalid/view-profile",
        "detail": "IDOR on view-profile",
        "evidence": "id=1 -> email=real1@corp.invalid | id=2 -> email=real2@corp.invalid",
    }))
    pocs = " ".join(str(f.get("poc", "")) for f in reporter.load_findings(str(tmp_path)))
    for invented in ("victim@example.com", "Alice", "9000000000"):
        assert invented not in pocs, f"IDOR PoC fabricates victim PII: {invented!r}"
    assert "real1@corp.invalid" in pocs or "id=1" in pocs, (
        "the PoC must use the finding's real captured evidence")


def test_reporter_ships_no_fabricated_victim_constants():
    """No PoC/narrative block may hard-code specific victim PII or timing values
    (F10). These were presented as 'ACTUAL DATA LEAKED' / 'ACTUAL TIMING DATA'."""
    src = open(reporter.__file__).read()
    for bad in ('victim@example.com', '"first_name": "Alice"', '"email": "victim',
                '9000000000', '6.6s, 6.1s, 6.4s'):
        assert bad not in src, (
            f"fabricated victim constant still hard-coded in reporter.py: {bad!r}")


def test_auth_bypass_template_not_shadowed():
    """The auth_bypass template was defined TWICE: a dead ``high/8.1``
    "Authentication Bypass on {host}" literal, silently overwritten by a
    ``critical/9.8`` "Broken Authentication on {host}" reassignment. A
    maintainer editing the dead literal would see no effect (the footgun behind
    F1-F3 shipping at 9.8). There must be exactly one live definition."""
    src = open(reporter.__file__).read()
    assert "Authentication Bypass on {host}" not in src, (
        "the dead/shadowed auth_bypass template literal is still present — "
        "editing it has no runtime effect; remove it and keep the single "
        "'Broken Authentication on {host}' definition.")
    assert reporter.VULN_TEMPLATES["auth_bypass"]["severity"] == "critical"
