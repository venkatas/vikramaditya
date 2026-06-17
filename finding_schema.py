#!/usr/bin/env python3
"""
finding_schema.py — verification-method enum + evidence-based severity.

Adapted from xalgorix (MIT) — internal/tools/reporting/reporting.go
(validVerificationMethods, evidenceKeywords, the auto-downgrade matrix in
reportVulnWithContextID, severityRank, and hasStrongEvidence).

Purpose
-------
Vikramaditya's brain/agent engines emit raw "vulnerability" claims. Many are
unproven scanner echoes or self-declared verdicts. This module gives every
finding a single source of truth for:

  1. HOW a finding was verified  → :class:`VerificationMethod`
  2. HOW STRONG that proof is     → :func:`is_proven` / :func:`proof_strength`
  3. WHAT the tool output proves  → :func:`classify_evidence` against
     :data:`EVIDENCE_KEYWORDS`
  4. WHETHER to keep the declared severity → :func:`adjust_severity`
  5. WHETHER the finding is worth reporting at all → :func:`should_report`

The reporter and brain_scanner wire into these so an UNVERIFIED "critical"
never ships at critical, and an unproven medium-or-higher is dropped before
the client-facing report is rendered.

Pure stdlib — no Ollama, no network, no third-party deps.

Usage
-----
    from finding_schema import (
        VerificationMethod, is_proven, classify_evidence,
        adjust_severity, should_report,
    )

    method = VerificationMethod.from_string(tool_tag)   # tolerant parse
    sev = adjust_severity(declared_sev, method)          # auto-downgrade
    if should_report(sev, method):
        record(sev, method)
"""

from __future__ import annotations

import enum
from typing import Optional, Union

__all__ = [
    "VerificationMethod",
    "is_proven",
    "proof_strength",
    "classify_evidence",
    "adjust_severity",
    "should_report",
    "EVIDENCE_KEYWORDS",
    "SEVERITY_RANK",
]


# ── Verification methods ──────────────────────────────────────────────────────
# The 9 ways a finding can be verified, plus an UNVERIFIED sentinel for raw
# scanner/model claims. Values mirror xalgorix's validVerificationMethods so
# findings round-trip between the two tools' JSON.
class VerificationMethod(enum.Enum):
    EXPLOITED = "exploited"                 # full exploitation with proof
    TIME_BASED = "time_based"               # time-based blind (SQLi, cmd injection)
    DATA_EXTRACTED = "data_extracted"       # actual data was pulled out
    CALLBACK_RECEIVED = "callback_received"  # SSRF/XXE/RCE OAST callback landed
    ERROR_BASED = "error_based"             # SQL error / stack trace confirmation
    BLIND_CONFIRMED = "blind_confirmed"     # blind vuln via side-channel
    REFLECTED = "reflected"                 # payload reflected in response (XSS)
    AUTHENTICATED = "authenticated"         # auth bypass / IDOR with session evidence
    MANUAL_VERIFIED = "manual_verified"     # hand-verified via browser / curl
    UNVERIFIED = "unverified"               # raw scanner echo / model claim — no proof

    @classmethod
    def from_string(cls, value: Union[str, "VerificationMethod", None]) -> "VerificationMethod":
        """Tolerant parse. Unknown / empty / None → UNVERIFIED (never raises)."""
        if isinstance(value, cls):
            return value
        if not value or not isinstance(value, str):
            return cls.UNVERIFIED
        key = value.strip().lower()
        for member in cls:
            if member.value == key:
                return member
        return cls.UNVERIFIED


# Strength buckets. "strong" = directly proven impact; "weak" = evidence of a
# vuln but not proven impact; "context" = an access state, not proof on its own;
# "unproven" = no verification at all.
_STRONG = frozenset({
    VerificationMethod.EXPLOITED,
    VerificationMethod.DATA_EXTRACTED,
    VerificationMethod.CALLBACK_RECEIVED,
    VerificationMethod.TIME_BASED,
})
_WEAK = frozenset({
    VerificationMethod.REFLECTED,
    VerificationMethod.ERROR_BASED,
    VerificationMethod.BLIND_CONFIRMED,
})
_CONTEXT = frozenset({
    VerificationMethod.AUTHENTICATED,
    VerificationMethod.MANUAL_VERIFIED,
})


def _coerce(method: Union[str, VerificationMethod, None]) -> VerificationMethod:
    return VerificationMethod.from_string(method)


def proof_strength(method: Union[str, VerificationMethod, None]) -> str:
    """Return one of 'strong' | 'weak' | 'context' | 'unproven'."""
    m = _coerce(method)
    if m in _STRONG:
        return "strong"
    if m in _WEAK:
        return "weak"
    if m in _CONTEXT:
        return "context"
    return "unproven"


def is_proven(method: Union[str, VerificationMethod, None]) -> bool:
    """True only for STRONGLY proven methods (exploited / data_extracted /
    callback_received / time_based). Weak, context and unverified are False —
    they are evidence or state, not proof of impact."""
    return _coerce(method) in _STRONG


# ── Severity ranks ────────────────────────────────────────────────────────────
SEVERITY_RANK = {"none": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_RANK_TO_LABEL = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


# ── Evidence keywords ─────────────────────────────────────────────────────────
# Per-vuln-type keyword lists that indicate the severity an actual tool/exploit
# output PROVES. classify_evidence() scans output text for the strongest bucket
# whose keywords appear. Lowercase; matched case-insensitively as substrings.
EVIDENCE_KEYWORDS = {
    "sqli": {
        "critical": ["dumped", "dump the", "database dump", "all rows", "password hash",
                     "password_hash", "extracted credentials", "users table", "admin password",
                     "load_file", "into outfile", "xp_cmdshell"],
        "high": ["union select", "data extract", "extracted", "version()", "@@version",
                 "current_user", "information_schema", "boolean-based", "blind sql"],
        "medium": ["sql syntax", "sql error", "you have an error in your sql",
                   "ora-0", "psql:", "mysql_fetch", "unclosed quotation", "warning: mysql"],
    },
    "xss": {
        "critical": ["document.cookie stolen", "session hijack", "account takeover", "cookie exfiltrated"],
        "high": ["stored", "persistent", "<script>alert", "executed in", "fired alert", "popped"],
        "medium": ["reflected", "payload reflected", "echoed back", "onerror=", "onload="],
    },
    "rce": {
        "critical": ["uid=0(root)", "uid=0", "reverse shell", "shell established", "command output",
                     "id;", "whoami returned", "/bin/sh", "/bin/bash", "remote code execution confirmed"],
        "high": ["command injection", "code execution", "executed command", "popen", "system(",
                 "sleep 10 succeeded", "blind command"],
        "medium": ["potential command", "possible injection", "argument injection"],
    },
    "ssrf": {
        "critical": ["169.254.169.254", "metadata", "iam/security-credentials", "aws key",
                     "instance-id", "cloud metadata", "internal admin", "gopher://"],
        "high": ["internal service", "internal ip", "127.0.0.1 reached", "localhost reached",
                 "port open internally", "fetched internal"],
        "medium": ["dns lookup", "callback dns", "blind ssrf", "out-of-band dns"],
    },
    "lfi": {
        "critical": ["root:x:0:0", "/etc/shadow", "proc/self/environ", "id_rsa", "private key",
                     "log poisoning", "rce via", "wrapper php://filter rce"],
        "high": ["/etc/passwd", "file inclusion", "path traversal confirmed", "../../../",
                 "directory traversal", "read arbitrary file"],
        "medium": ["traversal attempt", "possible lfi", "include() warning"],
    },
    "idor": {
        "critical": ["all users", "mass data", "dumped all", "every account", "database of users",
                     "admin record", "full enumeration"],
        "high": ["another user", "other user's", "unauthorized access", "accessed account",
                 "object id swap", "horizontal access", "pii exposed"],
        "medium": ["incrementing id", "predictable id", "object reference"],
    },
    "ssti": {
        "critical": ["7*7=49 then rce", "config.items", "os.popen", "subprocess", "lipsum",
                     "globals", "__class__", "command output via template"],
        "high": ["{{7*7}}", "49", "template injection confirmed", "rendered expression",
                 "evaluated", "jinja2", "freemarker", "twig"],
        "medium": ["template error", "expression reflected", "possible ssti"],
    },
    "xxe": {
        "critical": ["root:x:0:0", "/etc/passwd via xml", "file:///", "oob exfiltration",
                     "ssrf via xxe", "internal file read"],
        "high": ["external entity", "doctype", "entity expansion", "xml external entity confirmed"],
        "medium": ["xml parser error", "entity not allowed", "possible xxe"],
    },
    "auth_bypass": {
        "critical": ["admin access", "root access", "superuser", "all accounts", "full access",
                     "logged in as admin", "bypassed login as administrator"],
        "high": ["authentication bypass", "auth bypass", "logged in without", "bypassed login",
                 "accessed protected", "session forged"],
        "medium": ["weak auth", "default credentials", "possible bypass"],
    },
    "open_redirect": {
        "critical": ["oauth token stolen", "authorization_code stolen", "token exfiltrated via redirect"],
        "high": ["oauth", "ssrf chain", "token", "credential theft chain"],
        "medium": ["redirect to", "unvalidated redirect", "location header", "redirected off-site"],
    },
    "csrf": {
        "critical": ["password changed", "account taken over", "funds transferred", "admin role granted"],
        "high": ["state change", "email changed", "delete account", "critical action", "no csrf token"],
        "medium": ["csrf possible", "missing csrf token", "forged request"],
    },
    "cors": {
        "critical": ["cookie stolen", "token stolen", "credential exfiltrated", "data exfiltrated cross-origin"],
        "high": ["access-control-allow-credentials: true", "reflected origin with credentials",
                 "read response cross-origin", "xmlhttprequest withcredentials"],
        "medium": ["access-control-allow-origin: *", "wildcard cors", "reflected origin"],
    },
    "jwt": {
        "critical": ["forged admin token", "alg none accepted", "signature stripped accepted",
                     "rs256 to hs256", "key confusion", "signed with public key"],
        "high": ["weak secret cracked", "brute-forced secret", "token forged", "tampered claim accepted"],
        "medium": ["weak algorithm", "expired token accepted", "no expiry", "sensitive claim"],
    },
    "takeover": {
        "critical": ["claimed the subdomain", "served attacker content", "full subdomain takeover",
                     "registered the bucket", "controlled origin"],
        "high": ["dangling cname", "unclaimed", "nxdomain to provider", "fingerprint matched provider",
                 "subdomain takeover confirmed"],
        "medium": ["dangling dns", "possible takeover", "cname to deprovisioned"],
    },
    "exposure": {
        "critical": ["aws_secret_access_key", "private key", "-----begin rsa private key-----",
                     "database_url", "root password", "service account key", "credentials leaked"],
        "high": ["api key", "access token", "bearer ", "secret key", "password=",
                 "credential", ".env exposed", "exposed secret"],
        "medium": ["internal path", "stack trace", "debug enabled", "config exposed",
                   "directory listing", "git directory exposed"],
    },
    "rfi": {
        "critical": ["remote shell included", "rce via rfi", "webshell executed"],
        "high": ["remote file inclusion", "included remote", "http:// included"],
        "medium": ["possible rfi", "remote include attempt"],
    },
    "deserialization": {
        "critical": ["object injection rce", "gadget chain", "deserialization rce", "pickle rce",
                     "ysoserial"],
        "high": ["insecure deserialization", "unserialize", "magic method invoked"],
        "medium": ["serialized payload", "possible deserialization"],
    },
}


def classify_evidence(text: str, vuln_type: str) -> Optional[str]:
    """Return the strongest severity label ('critical' | 'high' | 'medium')
    whose keywords appear in ``text`` for ``vuln_type``, or None when no
    keyword matches (or the vuln type is unknown). Case-insensitive."""
    if not text or not vuln_type:
        return None
    buckets = EVIDENCE_KEYWORDS.get(vuln_type.strip().lower())
    if not buckets:
        return None
    lowered = text.lower()
    for severity in ("critical", "high", "medium"):  # strongest first
        for kw in buckets.get(severity, ()):
            if kw in lowered:
                return severity
    return None


# ── Severity adjustment ───────────────────────────────────────────────────────
def adjust_severity(
    declared_severity: str,
    verification_method: Union[str, VerificationMethod, None],
) -> str:
    """Auto-downgrade an over-claimed severity given how it was verified.

    Critical/High are dropped exactly one notch (critical→high, high→medium)
    when the verification is UNVERIFIED or only WEAK (reflected/error_based/
    blind_confirmed). Strongly-proven and context methods keep the declared
    severity. Medium and below are never auto-downgraded here — they fall to
    :func:`should_report` for gating instead.

    Mirrors xalgorix's "drop by one severity level (not nuclear to info)"
    rule so downstream CVSS enforcement can still correct it.
    """
    label = (declared_severity or "").strip().lower()
    rank = SEVERITY_RANK.get(label)
    if rank is None:
        return declared_severity  # unknown label — leave as-is

    strength = proof_strength(verification_method)
    # Only critical(4) and high(3) are subject to the one-notch downgrade.
    if rank >= SEVERITY_RANK["high"] and strength in ("unproven", "weak"):
        return _RANK_TO_LABEL[rank - 1]
    return label


# ── Report gating ─────────────────────────────────────────────────────────────
def should_report(
    severity: str,
    verification_method: Union[str, VerificationMethod, None],
) -> bool:
    """Gate a finding before it reaches the client-facing report.

    Reject UNVERIFIED medium-or-higher: a medium+ severity requires at least
    WEAK verification to surface. Below medium (low/info) is always allowed —
    those are context findings that don't need proof to be listed. Any
    verification at all (weak/context/strong) clears a medium+ finding.
    """
    label = (severity or "").strip().lower()
    rank = SEVERITY_RANK.get(label, 0)
    if rank < SEVERITY_RANK["medium"]:
        return True  # low / info / none — always allowed
    # medium+ needs at least weak verification.
    return proof_strength(verification_method) != "unproven"


if __name__ == "__main__":  # pragma: no cover — tiny smoke/demo CLI
    import json

    demo = {
        "methods": [m.value for m in VerificationMethod],
        "proven_exploited": is_proven("exploited"),
        "proven_reflected": is_proven("reflected"),
        "classify_sqli_dump": classify_evidence("dumped the users table", "sqli"),
        "adjust_unverified_critical": adjust_severity("critical", "unverified"),
        "should_report_unverified_medium": should_report("medium", "unverified"),
    }
    print(json.dumps(demo, indent=2))
