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
