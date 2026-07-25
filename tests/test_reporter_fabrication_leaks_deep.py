"""reporter.py NON-marker ingestion must not fabricate medium+ findings.

A deeper empirical audit (every leak reproduced via reporter.load_findings) found four
fabrication paths the marker-prefix suppression did not cover:

  V1 cves/*.txt bare CVE IDs            -> CRITICAL "Known CVE" 9.0 (no version/confirmation)
  V2 brain claim, no script grounding   -> CRITICAL (proof-gate only covered file-READ claims)
  V3 severity keyword in a URL PATH      -> /CONFIRMED/ => CRITICAL, /HIGH-availability/ => HIGH
  V4 Burp "Tentative" (lowest confidence)-> shipped at its raw severity (often a false positive)

Each must collapse to info/template-default, while genuinely-verified inputs survive.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import reporter  # noqa: E402

_MEDPLUS = {"critical", "high", "medium"}
_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0}


def _worst(tmp_path, relpath, content):
    fp = tmp_path / relpath
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(content if isinstance(content, str) else json.dumps(content))
    worst = None
    for f in reporter._apply_verification_gating(reporter.load_findings(str(tmp_path))):
        s = str(f.get("severity", "")).lower()
        if s in _RANK and (worst is None or _RANK[s] > _RANK[worst]):
            worst = s
    fp.unlink()
    return worst


def test_cve_bare_ids_in_txt_do_not_ship_critical(tmp_path):
    assert _worst(tmp_path, "cves/found_cves.txt", "CVE-2021-44228\nCVE-2017-5638\n") not in _MEDPLUS
    # a nuclei-confirmed (URL-bearing) CVE in the allowlisted file must STILL be critical
    assert _worst(tmp_path, "cves/nuclei_cve_confirmed.txt",
                  "[CVE-2021-44228] [critical] https://t.example.invalid/x") == "critical"


def test_brain_claim_without_grounding_does_not_ship_critical(tmp_path):
    ungrounded = {"findings_so_far": ["[CRITICAL] SQL injection confirmed at https://t.example.invalid/x?id=1"],
                  "results": "[*] running\n[*] testing\n[*] no output"}
    assert _worst(tmp_path, "brain_active/iteration_1.json", ungrounded) not in _MEDPLUS
    # a brain claim GROUNDED in real script output (a /etc/passwd dump) must survive
    grounded = {"findings_so_far": ["[CRITICAL] Read /etc/passwd"],
                "results": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin/nologin\nbin:x:2:2:bin:/usr/sbin/nologin"}
    assert _worst(tmp_path, "brain_active/iteration_1.json", grounded) == "critical"


def test_severity_keyword_in_url_path_does_not_promote(tmp_path):
    assert _worst(tmp_path, "misconfig/h.txt",
                  "https://t.example.invalid/api/CONFIRMED/status missing CSP header") not in {"critical", "high"}
    assert _worst(tmp_path, "cors/c.txt",
                  "https://t.example.invalid/HIGH-availability/x CORS wildcard") not in {"high", "critical"}
    # a genuine keyword in the NON-url evidence text must still promote
    assert _worst(tmp_path, "misconfig/h.txt",
                  "[SQLI-POC-VERIFIED] https://t.example.invalid/x?id=1 :: CONFIRMED dump") == "critical"


def test_burp_tentative_is_downgraded_to_info(tmp_path):
    tentative = [{"severity": "High", "confidence": "Tentative", "type": "sqli",
                  "title": "SQLi", "url": "https://t.example.invalid/x", "source": "burp"}]
    assert _worst(tmp_path, "burp/findings.json", tentative) not in _MEDPLUS
    certain = [{"severity": "High", "confidence": "Certain", "type": "sqli",
                "title": "SQLi", "url": "https://t.example.invalid/x", "source": "burp"}]
    assert _worst(tmp_path, "burp/findings.json", certain) == "high"


# ── friends-review follow-ups (codex + grok + agy) ──────────────────────────────

def test_cve_id_with_trailing_text_does_not_ship_critical(tmp_path):
    # prefix-only guard let "CVE-... CVSS:10 Log4Shell" through; must divert any CVE ref
    assert _worst(tmp_path, "cves/other.txt", "CVE-2021-44228 CVSS:10.0 Log4Shell RCE") not in _MEDPLUS


def test_saml_endpoint_discovery_is_not_a_finding(tmp_path):
    assert _worst(tmp_path, "saml/endpoints.txt",
                  "[SAML-ENDPOINT] https://t.example.invalid/saml | HTTP 200") not in _MEDPLUS


def test_brain_single_line_real_proof_is_not_over_suppressed(tmp_path):
    # a REAL exploit often proves itself in ONE line — must NOT be demoted (>=2 was too strict)
    grounded = {"findings_so_far": ["[CRITICAL] RCE confirmed uid=0"],
                "results": "uid=0(root) gid=0(root) groups=0(root)\n[*] done"}
    assert _worst(tmp_path, "brain_active/iteration_1.json", grounded) == "critical"
    # but pure-chatter (0 substantive lines) still collapses to a model claim
    ungrounded = {"findings_so_far": ["[CRITICAL] SQL injection confirmed"],
                  "results": "[*] running\n[*] testing\n[*] no output"}
    assert _worst(tmp_path, "brain_active/iteration_1.json", ungrounded) not in _MEDPLUS


def test_sqlmap_log_level_lines_do_not_ship_critical(tmp_path):
    """2026-07-25 engagement: sqlmap emits '[HH:MM:SS] [CRITICAL] ...' LOG lines where
    [CRITICAL] is a log LEVEL, not a vuln severity. Two such lines ('WAF/IPS identified',
    'content is heavily dynamic ... retry') were captured into findings_so_far and shipped as
    CRITICAL findings (severity CRITICAL but CVSS 5.3 / URL N/A — the tell). A tool-logger line
    is never a finding, even when the iteration ALSO produced substantive grounding output."""
    data = {
        "findings_so_far": [
            "[21:11:15] [CRITICAL] WAF/IPS identified as 'AWS WAF (Amazon)'",
            "[21:11:16] [CRITICAL] target URL content appears to be heavily dynamic. "
            "sqlmap is going to retry the request(s)",
        ],
        # substantive output → the grounding gate is satisfied, proving the log lines are
        # suppressed on their OWN merits (they are noise), not merely for lack of grounding.
        "results": "GET /Home.aspx HTTP/1.1\nServer: Microsoft-IIS/10.0\nX-AspNet-Version: 4.0.30319\n",
    }
    assert _worst(tmp_path, "brain_active/iteration_1.json", data) not in _MEDPLUS
    # regression guard: a brain self-tagged '[CRITICAL] ...' (NO timestamp) that IS grounded
    # must still survive — the fix keys on the [HH:MM:SS] logger prefix, not on '[CRITICAL]'.
    grounded = {"findings_so_far": ["[CRITICAL] RCE confirmed uid=0"],
                "results": "uid=0(root) gid=0(root) groups=0(root)\n[*] done"}
    assert _worst(tmp_path, "brain_active/iteration_1.json", grounded) == "critical"


def test_active_exploit_line_without_marker_is_demoted(tmp_path):
    """Fail-closed inversion: a bare/unknown line in an active-exploit dir (no confirmation
    marker) must NOT ship at the template's Medium+/Critical severity — it caps to a LOW lead.
    This is the durable guard against the next unknown probe/discovery/log shape."""
    assert _worst(tmp_path, "rce/newprobe.txt",
                  "POST /api/exec reached 200 at https://t.example.invalid/x") not in _MEDPLUS
    assert _worst(tmp_path, "idor/hits.txt",
                  "id=1001 returned another user's record at https://t.example.invalid/u") not in _MEDPLUS
    assert _worst(tmp_path, "sqli/notes.txt",
                  "param id looks injectable at https://t.example.invalid/x?id=1") not in _MEDPLUS
    assert _worst(tmp_path, "auth_bypass/x.txt",
                  "admin panel loaded at https://t.example.invalid/admin") not in _MEDPLUS


def test_confirmed_active_exploit_markers_survive(tmp_path):
    """No over-suppression — the three producer 'verified' grammars keep full severity:
    (1) a leading confirmation marker, (2) a leading [SEVERITY] prefix (auth_utils.FindingSaver,
    used by the API scanners for findings they already assessed), (3) a nuclei result line."""
    # (1) leading confirmation markers
    assert _worst(tmp_path, "rce/c.txt",
                  "[POC-RCE-CONFIRMED] uid=0(root) at https://t.example.invalid/s.jsp") == "critical"
    assert _worst(tmp_path, "xxe/c.txt",
                  "[XXE-OOB-CONFIRMED] callback from https://t.example.invalid/x") == "critical"
    assert _worst(tmp_path, "auth_bypass/c.txt",
                  "[LDAP-BYPASS-CONFIRMED] logged in as admin at https://t.example.invalid") == "critical"
    # (2) FindingSaver [SEVERITY]-prefixed API findings (idor/oauth/auth_bypass) must NOT be demoted
    assert _worst(tmp_path, "idor/findings.txt",
                  "[HIGH] Cross-user IDOR: read user 1001 record https://t.example.invalid/u/1001") in _MEDPLUS
    assert _worst(tmp_path, "auth_bypass/findings.txt",
                  "[CRITICAL] Endpoint accessible without auth https://t.example.invalid/admin") in _MEDPLUS
    assert _worst(tmp_path, "oauth/findings.txt",
                  "[HIGH] redirect_uri_bypass https://t.example.invalid/cb") in _MEDPLUS
    # (3) nuclei result grammar ([template-id] [proto] [severity] URL) must survive
    assert _worst(tmp_path, "rce/nuclei_rce.txt",
                  "[apache-struts-rce] [http] [critical] https://t.example.invalid/x") in _MEDPLUS


def test_negative_and_malformed_markers_do_not_survive(tmp_path):
    """codex pass-2: markers that LOOK positive but are explicitly NEGATIVE
    ([UNCONFIRMED]/[NOT-CONFIRMED]/[NO-POC]/[POC-FAILED]/[NOT-VERIFIED]/[UN-VERIFIED]) must NOT
    count as verified (they syntactically contain CONFIRMED/VERIFIED/POC); and a nuclei-shaped
    three-bracket LOG line with NO matched URL is not a nuclei hit."""
    for neg in ("[UNCONFIRMED]", "[NOT-CONFIRMED]", "[NO-POC]", "[POC-FAILED]",
                "[NOT-VERIFIED]", "[UN-VERIFIED]"):
        assert _worst(tmp_path, "rce/n.txt",
                      f"{neg} probe only at https://t.example.invalid/x") not in _MEDPLUS, neg
    # nuclei grammar with no URL after the severity bracket = a log line, not a hit
    assert _worst(tmp_path, "rce/n2.txt",
                  "[probe-log] [http] [critical] request failed") not in _MEDPLUS
    # a genuine nuclei hit (matched URL present) still survives at full severity
    assert _worst(tmp_path, "rce/n3.txt",
                  "[cve-2021-0001] [http] [critical] https://t.example.invalid/x") in _MEDPLUS


def test_bare_structural_marker_without_severity_is_a_lead(tmp_path):
    """A bracket MARKER that is neither a confirmation, a [SEVERITY] prefix, nor nuclei output
    (e.g. [SAML-METADATA-EXPOSED] mapped to the auth_bypass CRITICAL template) must NOT ship at
    CRITICAL — it caps to a LOW lead (public SAML metadata is not an auth bypass). Producers that
    want a real severity emit the FindingSaver [SEVERITY] convention."""
    assert _worst(tmp_path, "saml/x.txt",
                  "[SAML-METADATA-EXPOSED] https://t.example.invalid/saml/metadata") not in _MEDPLUS


def test_dalfox_reflected_not_verified_is_demoted(tmp_path):
    """#5: dalfox [R]/[G] = reflection with unproven executable context -> LOW lead; [V] =
    browser-verified stays a real XSS."""
    assert _worst(tmp_path, "xss/dalfox_results.txt",
                  "[POC][R][GET][inHTML-URL] https://t.example.invalid/p?q=x") not in _MEDPLUS
    assert _worst(tmp_path, "xss/dalfox_results.txt",
                  "[POC][V][GET][inHTML] https://t.example.invalid/p?q=x") in _MEDPLUS


def test_exposed_config_is_surfaced_not_dropped(tmp_path):
    # over-suppression: exposed_configs.txt was blacklisted with no loader -> real exposures lost
    assert _worst(tmp_path, "cves/exposed_configs.txt", "https://t.example.invalid/.git/config") == "medium"
