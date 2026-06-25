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
]

KEEP = [
    ("upload/verified_upload_pocs.txt", "[UPLOAD-ONLY-POC] https://t.example.invalid/up/canary123.txt :: stored+retrieved"),
    ("supply_chain/findings.txt", "[CRED-FILE] https://t.example.invalid/.npmrc"),
    ("rce/verified.txt", "[POC-RCE-CONFIRMED] https://t.example.invalid/x cmd=id uid=0"),
    ("sqli/timebased_candidates.txt", "[SQLI-POC-VERIFIED] https://t.example.invalid/a?id=1 :: time-based confirmed"),
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
