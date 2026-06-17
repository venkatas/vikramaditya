#!/usr/bin/env python3
# Adapted from xalgorix (MIT) — internal/reporting/{risk.go,severity.go,mappings.go}
"""
report_synthesis.py — weighted risk scoring + framework-mapping inference.

Pure-stdlib helpers the reporter consumes to turn a flat list of findings
into an executive-summary risk picture:

  • risk_score(findings)      -> (score 0-10, label)
        Weighted overall score: average of the top-five CVSS scores plus a
        crit/high count penalty (capped at +1.5), clamped to [0, 10]. When a
        finding has no CVSS, a severity-band default is substituted
        (critical=9.5, high=7.5, medium=5.0, low=2.5, info=0.0).

  • rollup_severities(findings) -> dict
        Case-insensitive per-severity counts plus a total. Any severity that
        is not one of the four named bands rolls up into "informational".

  • infer_mappings(title_or_type) -> dict
        Keyword-based inference of the OWASP Top 10 (2021) category, CWE id,
        and PTES phase from a finding title or type string. Returns {} when
        nothing matches.

  • exec_summary(findings) -> str
        A short narrative combining the risk score, label, and severity
        rollup, suitable for the report's Executive Summary section.

A "finding" is a dict. Recognised keys:
    severity   : "critical" | "high" | "medium" | "low" | anything else→info
    cvss       : float (optional; 0/absent → derived from severity)
    title/type : str  (used by infer_mappings via exec_summary helpers)

This mirrors the Go reference in xalgorix's internal/reporting package so the
two tools score and map findings identically.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

# ─── Severity-band CVSS defaults ──────────────────────────────────────────────
# Used when a finding carries no explicit CVSS. Matches risk.go.
_SEVERITY_CVSS = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.0,
    "informational": 0.0,
}
_DEFAULT_CVSS = 0.0  # info / unknown band → 0.0 (was 1.0, which wrongly scored info-only as LOW)

# Penalty weights per crit/high finding, and the overall penalty cap.
_CRIT_WEIGHT = 0.15
_HIGH_WEIGHT = 0.05
_PENALTY_CAP = 1.5

_TOP_N = 5  # number of highest CVSS scores averaged


def _severity(finding: Dict[str, Any]) -> str:
    """Lower-cased severity string for a finding ('' if missing)."""
    return str(finding.get("severity", "")).strip().lower()


def _cvss_of(finding: Dict[str, Any]) -> float:
    """CVSS for a finding: explicit value if positive, else severity default."""
    try:
        cvss = float(finding.get("cvss") or 0)
    except (TypeError, ValueError):
        cvss = 0.0
    if cvss <= 0:
        cvss = _SEVERITY_CVSS.get(_severity(finding), _DEFAULT_CVSS)
    return cvss


def risk_score(findings: List[Dict[str, Any]]) -> Tuple[float, str]:
    """Weighted overall risk score and label for a list of findings.

    Score = average of the top-five CVSS scores + crit/high count penalty
    (capped at +1.5), clamped to [0, 10]. Returns (0.0, "INFORMATIONAL")
    for an empty list.
    """
    if not findings:
        return 0.0, "INFORMATIONAL"

    scores = sorted((_cvss_of(f) for f in findings), reverse=True)
    top = scores[:_TOP_N]
    avg = sum(top) / len(top)

    crit = sum(1 for f in findings if _severity(f) == "critical")
    high = sum(1 for f in findings if _severity(f) == "high")
    penalty = min(crit * _CRIT_WEIGHT + high * _HIGH_WEIGHT, _PENALTY_CAP)

    score = min(avg + penalty, 10.0)
    return score, risk_label(score)


def risk_label(score: float) -> str:
    """Map a numeric score (0-10) into a human-readable rating band."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 0.1:
        return "LOW"
    return "INFORMATIONAL"


def rollup_severities(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Case-insensitive per-severity counts plus a total.

    Any severity that is not one of the four named bands (including the
    canonical "informational"/"info" labels, empty strings, and custom
    labels) rolls up into the "informational" bucket. ``total`` always
    equals ``len(findings)``.
    """
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
        "total": 0,
    }
    for f in findings:
        sev = _severity(f)
        if sev in ("critical", "high", "medium", "low"):
            counts[sev] += 1
        else:
            counts["informational"] += 1
    counts["total"] = len(findings)
    return counts


# ─── Framework mapping tables (ported from mappings.go) ───────────────────────

# vuln-type → (CWE id, CWE name)
_TYPE_TO_CWE = {
    "xss": ("CWE-79", "Cross-site Scripting"),
    "sqli": ("CWE-89", "SQL Injection"),
    "ssrf": ("CWE-918", "Server-Side Request Forgery"),
    "idor": ("CWE-639", "Authorization Bypass Through User-Controlled Key"),
    "lfi": ("CWE-22", "Path Traversal"),
    "rfi": ("CWE-98", "Remote File Inclusion"),
    "rce": ("CWE-78", "OS Command Injection"),
    "csrf": ("CWE-352", "Cross-Site Request Forgery"),
    "xxe": ("CWE-611", "XML External Entity"),
    "open_redirect": ("CWE-601", "URL Redirection to Untrusted Site"),
    "auth_bypass": ("CWE-287", "Improper Authentication"),
    "info_disclosure": ("CWE-200", "Exposure of Sensitive Information"),
    "subdomain_takeover": ("CWE-284", "Improper Access Control"),
    "clickjacking": ("CWE-1021", "Improper Restriction of Rendered UI Layers"),
    "cors": ("CWE-942", "Permissive Cross-domain Policy"),
    "crlf": ("CWE-93", "CRLF Injection"),
    "ssti": ("CWE-1336", "Server-Side Template Injection"),
    "deserialization": ("CWE-502", "Deserialization of Untrusted Data"),
    "missing_header": ("CWE-693", "Protection Mechanism Failure"),
    "version_disclosure": ("CWE-200", "Exposure of Sensitive Information"),
    "file_upload": ("CWE-434", "Unrestricted Upload of File with Dangerous Type"),
}

# CWE id → (OWASP Top 10 2021 id, name)
_CWE_TO_OWASP = {
    # A01:2021 – Broken Access Control
    "CWE-639": ("A01", "Broken Access Control"),
    "CWE-284": ("A01", "Broken Access Control"),
    "CWE-942": ("A01", "Broken Access Control"),
    "CWE-601": ("A01", "Broken Access Control"),
    "CWE-22": ("A01", "Broken Access Control"),
    "CWE-1021": ("A01", "Broken Access Control"),
    # A03:2021 – Injection
    "CWE-79": ("A03", "Injection"),
    "CWE-89": ("A03", "Injection"),
    "CWE-78": ("A03", "Injection"),
    "CWE-93": ("A03", "Injection"),
    "CWE-611": ("A03", "Injection"),
    "CWE-1336": ("A03", "Injection"),
    "CWE-98": ("A03", "Injection"),
    # A04:2021 – Insecure Design
    "CWE-434": ("A04", "Insecure Design"),
    # A05:2021 – Security Misconfiguration
    "CWE-693": ("A05", "Security Misconfiguration"),
    "CWE-200": ("A05", "Security Misconfiguration"),
    # A07:2021 – Identification and Authentication Failures
    "CWE-287": ("A07", "Identification and Authentication Failures"),
    "CWE-352": ("A07", "Identification and Authentication Failures"),
    # A08:2021 – Software and Data Integrity Failures
    "CWE-502": ("A08", "Software and Data Integrity Failures"),
    # A10:2021 – Server-Side Request Forgery
    "CWE-918": ("A10", "Server-Side Request Forgery"),
}

# vuln-type → PTES testing phase
_TYPE_TO_PTES = {
    "xss": "Vulnerability Analysis",
    "sqli": "Exploitation",
    "ssrf": "Exploitation",
    "idor": "Exploitation",
    "lfi": "Exploitation",
    "rfi": "Exploitation",
    "rce": "Exploitation",
    "csrf": "Vulnerability Analysis",
    "xxe": "Exploitation",
    "open_redirect": "Vulnerability Analysis",
    "auth_bypass": "Exploitation",
    "info_disclosure": "Intelligence Gathering",
    "subdomain_takeover": "Intelligence Gathering",
    "clickjacking": "Vulnerability Analysis",
    "cors": "Vulnerability Analysis",
    "crlf": "Vulnerability Analysis",
    "ssti": "Exploitation",
    "deserialization": "Exploitation",
    "missing_header": "Vulnerability Analysis",
    "version_disclosure": "Intelligence Gathering",
    "file_upload": "Exploitation",
}

# Ordered keyword table — first match wins. More-specific classes (rce,
# sqli) are listed before generic ones so e.g. "command injection" maps to
# rce rather than a stray "injection" substring. Mirrors mappings.go.
_TYPE_KEYWORDS = [
    ("rce", ["remote code execution", "rce", "command injection",
             "os command", "code execution"]),
    ("sqli", ["sql injection", "sqli", "sql inject", "blind sql",
              "union select", "error-based sql"]),
    ("xss", ["xss", "cross-site scripting", "cross site scripting",
             "reflected xss", "stored xss", "dom xss", "script injection"]),
    ("ssrf", ["ssrf", "server-side request forgery",
              "server side request forgery"]),
    ("idor", ["idor", "insecure direct object", "broken access control",
              "unauthorized access"]),
    ("lfi", ["local file inclusion", "lfi", "file inclusion",
             "path traversal", "directory traversal"]),
    ("rfi", ["remote file inclusion", "rfi"]),
    ("file_upload", ["file upload", "unrestricted upload", "webshell upload",
                     "malicious file upload", "arbitrary file upload"]),
    ("csrf", ["csrf", "cross-site request forgery",
              "cross site request forgery"]),
    ("xxe", ["xxe", "xml external entity"]),
    ("open_redirect", ["open redirect", "url redirect",
                       "unvalidated redirect"]),
    ("auth_bypass", ["authentication bypass", "auth bypass", "login bypass"]),
    ("ssti", ["ssti", "server-side template injection",
              "template injection"]),
    ("deserialization", ["deserialization", "insecure deserialization",
                         "object injection"]),
    ("subdomain_takeover", ["subdomain takeover", "dangling dns",
                            "unclaimed subdomain"]),
    ("clickjacking", ["clickjacking", "ui redressing"]),
    ("cors", ["cors", "cross-origin resource sharing"]),
    ("crlf", ["crlf injection", "http response splitting"]),
    ("info_disclosure", ["information disclosure", "info disclosure",
                         "sensitive data exposure", "data leak",
                         "credential leak", "password leak",
                         "exposed secret", "token leak"]),
    ("missing_header", ["missing header", "security header",
                        "x-frame-options", "content-security-policy", "hsts"]),
    ("version_disclosure", ["version disclosure", "server header",
                            "x-powered-by", "technology disclosure"]),
]


def _infer_vuln_type(text: str) -> str:
    """Return the vuln-type class for a free-form title/type string ('' if none)."""
    lower = text.lower()
    for type_name, keywords in _TYPE_KEYWORDS:
        for kw in keywords:
            if kw in lower:
                return type_name
    return ""


def infer_mappings(title_or_type: str) -> Dict[str, str]:
    """Infer OWASP/CWE/PTES framework references from a title or type string.

    Returns a dict ``{"owasp": "A0x:2021-Name", "cwe": "CWE-xx",
    "ptes": "<phase>"}``. Returns an empty dict when no keyword matches.
    """
    if not title_or_type:
        return {}

    vuln_type = _infer_vuln_type(title_or_type)
    if not vuln_type:
        return {}

    mapping: Dict[str, str] = {}

    cwe = _TYPE_TO_CWE.get(vuln_type)
    if cwe:
        mapping["cwe"] = cwe[0]
        owasp = _CWE_TO_OWASP.get(cwe[0])
        if owasp:
            # Render as "A0x:2021-Name" to match the requested format.
            mapping["owasp"] = f"{owasp[0]}:2021-{owasp[1]}"

    ptes = _TYPE_TO_PTES.get(vuln_type)
    if ptes:
        mapping["ptes"] = ptes

    return mapping


def exec_summary(findings: List[Dict[str, Any]]) -> str:
    """A short narrative combining the risk score, label, and severity rollup."""
    score, label = risk_score(findings)
    roll = rollup_severities(findings)
    total = roll["total"]

    if total == 0:
        return (
            "No vulnerabilities were identified during this assessment. "
            "The overall residual risk rating is INFORMATIONAL (0.0/10)."
        )

    # Build a human-readable severity breakdown, omitting empty buckets.
    parts = []
    for band in ("critical", "high", "medium", "low", "informational"):
        n = roll[band]
        if n:
            parts.append(f"{n} {band}")
    breakdown = ", ".join(parts)

    noun = "finding" if total == 1 else "findings"
    return (
        f"This assessment identified {total} {noun} "
        f"({breakdown}). The overall risk rating is {label} "
        f"({score:.1f}/10), driven by the highest-severity issues. "
        f"Remediation should prioritise the critical and high-severity "
        f"findings first to reduce residual risk."
    )


__all__ = [
    "risk_score",
    "risk_label",
    "rollup_severities",
    "infer_mappings",
    "exec_summary",
]
