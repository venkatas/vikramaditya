"""authz_audit — orchestrate the authorization / disclosure detectors over an
authenticated session and emit report-ready rows.

Ties together the three modules built to close the authorization/disclosure gaps:
  * bfla_scanner  — forced-browsing / broken function-level authorization
  * idor_scanner  — IDOR/BOLA (enumeration + cross-user differential)
  * pii_detector  — bulk PII / directory disclosure on crawled pages

The caller supplies fetch callables (so this stays transport-agnostic and testable):
  low_get(path)    -> (status, body, location)   # the low-privilege session under test
  unauth_get(path) -> (status, body, location)   # optional unauthenticated baseline (BFLA)
  owner_get/other_get(ref) -> ...                # optional 2nd session (differential IDOR)

Iteration-2 backlog: discover admin_paths/object_refs/page_urls from the crawl + site-map;
feed two real role sessions from the auth-session layer (#4); stream rows into reporter.py.
"""
import bfla_scanner
import idor_scanner
import pii_detector


def _norm(r):
    return (r[0], r[1], r[2] if len(r) > 2 else "")


def audit(low_get, unauth_get=None, owner_get=None, other_get=None,
          object_refs=None, admin_paths=None, page_urls=None):
    """Run all detectors with the supplied sessions; return a flat list of findings."""
    findings = []
    # 1) forced-browsing / BFLA over admin wordlist (default if admin_paths is None)
    findings += bfla_scanner.scan(low_get, paths=admin_paths, unauth_get=unauth_get)
    # 2) IDOR/BOLA over object references
    if object_refs:
        findings += idor_scanner.scan_enumeration(low_get, object_refs)
        if owner_get and other_get:
            findings += idor_scanner.scan_differential(owner_get, other_get, object_refs)
    # 3) PII / bulk disclosure on crawled authenticated pages
    for url in (page_urls or []):
        status, body, _ = _norm(low_get(url))
        if status == 200:
            findings += pii_detector.scan(body, url=url)["findings"]
    return findings


_TITLE = {
    "broken_function_level_authorization": "Broken Function-Level Authorization (forced browsing)",
    "idor_bola_enumeration": "IDOR / BOLA — object references not access-controlled",
    "idor_bola_differential": "IDOR / BOLA — cross-user object access",
    "bulk_list_exposure": "Bulk data / directory disclosure",
    "pan": "PAN (sensitive identifier) disclosure",
    "gstin": "GSTIN (sensitive identifier) disclosure",
    "aadhaar": "Aadhaar (sensitive identifier) disclosure",
    "email": "Email address disclosure",
    "phone": "Phone number disclosure",
}


def to_report_rows(findings):
    """Map detector findings to reporter-friendly rows (title/severity/class/evidence/location)."""
    rows = []
    for f in findings:
        rows.append({
            "title": _TITLE.get(f.get("type"), f.get("type", "finding")),
            "severity": f.get("severity", "info"),
            "vuln_class": f.get("vuln_class", f.get("type", "")),
            "confidence": f.get("confidence", "candidate"),
            "location": f.get("path") or f.get("ref") or f.get("url") or "",
            "evidence": f.get("evidence", ""),
        })
    return rows


# detector type -> reporter.py vtype template key (Method 1f ingests these)
_VTYPE = {
    "idor_bola_enumeration": "idor",
    "idor_bola_differential": "idor",
    "broken_function_level_authorization": "auth_bypass",
    "bulk_list_exposure": "exposure",
    "pan": "exposure", "gstin": "exposure", "aadhaar": "exposure",
    "email": "exposure", "phone": "exposure",
}


def to_reporter_findings(findings):
    """Project detector findings into the reporter Method-1f finding shape (same schema
    burp_scanner emits), so they fold into the report with proper vtype templates."""
    out = []
    for f in findings:
        t = f.get("type", "")
        title = _TITLE.get(t, t or "authorization finding")
        loc = f.get("path") or f.get("ref") or f.get("url") or "N/A"
        sev = f.get("severity", "info")
        ev = f.get("evidence", "")
        poc = "\n".join([
            f"Vikramaditya authz-audit finding: {title}",
            f"Severity: {sev}  |  Confidence: {f.get('confidence', 'candidate')}",
            f"Location: {loc}",
            "", "Detail:", ev,
        ])
        out.append({
            "severity": sev,
            "type": _VTYPE.get(t, "misconfig"),
            "title": f"{title} ({loc})" if loc != "N/A" else title,
            "url": loc,
            "detail": title,
            "evidence": ev[:300],
            "poc": poc,
            "confidence": f.get("confidence", "candidate"),
            "source": "authz_audit",
        })
    return out


def write_findings_json(findings, out_dir):
    """Write <out_dir>/findings.json in the schema reporter.py ingests (Method 1f)."""
    import json
    import os
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "findings.json")
    with open(path, "w") as fh:
        json.dump(to_reporter_findings(findings), fh, indent=2)
    return path
