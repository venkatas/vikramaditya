#!/usr/bin/env python3
from __future__ import annotations
"""
Finding Validator — 7-Question Gate + Never-Submit List.

Filters scan findings before report generation. Kills weak findings,
downgrades uncertain ones, and flags chain opportunities.

Severity inflation / high-critical acceptance aligns with
policies/severity_rubric.md (codex-security inspired).

Includes PentestCode-inspired severity-inflation critic (clean-room):
scanner hits / banners / admin panels without proven impact are killed
or hard-downgraded. See assess_severity_inflation().

Usage:
    python3 finding_validator.py <findings_dir>
    python3 finding_validator.py <findings_dir> --strict
"""

import argparse
import json
import os
import re
import sys

# ── Never-Submit List ─────────────────────────────────────────────────────────
NEVER_SUBMIT = [
    "missing csp header", "missing hsts header", "missing x-frame-options",
    "missing x-content-type-options", "missing referrer-policy",
    "missing permissions-policy", "missing spf record", "missing dkim record",
    "missing dmarc record", "graphql introspection enabled",
    "banner disclosure", "version disclosure", "server header disclosure",
    "x-powered-by header", "clickjacking without sensitive action",
    "cors wildcard without credentialed exfil", "open redirect alone",
    "ssrf dns-only", "rate limit on non-critical",
    "session not invalidated on logout", "missing cookie flags",
    "cookie without httponly", "cookie without secure flag",
    "autocomplete not disabled", "directory listing on empty dir",
    "options method enabled", "trace method enabled",
    "host header injection without impact",
    # PentestCode-inspired critic expansions (no proven impact → never submit alone)
    "directory listing with no sensitive files",
    "self-signed certificate",
    "self-signed cert",
    "open port listed as vulnerability",
    "outdated software without cve",
    "version match only",
    "nmap version detection only",
    "nuclei version match only",
]

# Patterns that force INFO/KILL or hard downgrade when impact is not proven.
# Each entry: (id, compiled regex on normalized text, action, to_severity|None, reason)
# assess_severity_inflation() also applies proof-gate heuristics on top.
_SEVERITY_INFLATION_SPECS = [
    (
        "admin_login_page",
        re.compile(
            r"\b(wp-admin|phpmyadmin|pma/|tomcat.?manager|/manager/html|"
            r"admin.?login|administrator.?login|jenkins.?login)\b",
            re.I,
        ),
        "downgrade",
        "info",
        "Exposed admin/login page alone is not a vuln without default-creds, CVE, or open-registration proof",
    ),
    (
        "directory_listing",
        re.compile(r"\b(directory listing|index of /|autoindex)\b", re.I),
        "downgrade",
        "info",
        "Directory listing without sensitive files is informational",
    ),
    (
        "banner_version",
        re.compile(
            r"\b(banner disclosure|version disclosure|server header|x-powered-by|"
            r"detected version|software version|server:\s*[\w./-]+)\b",
            re.I,
        ),
        "kill",
        None,
        "Version/banner disclosure without a matching CVE exploit is not a finding",
    ),
    (
        "missing_headers_api",
        re.compile(
            r"\b(missing (?:csp|hsts|x-frame-options|x-content-type-options|"
            r"referrer-policy|permissions-policy).*(?:api|json|application/json)|"
            r"(?:api|json|application/json).*missing (?:csp|hsts|x-frame-options|"
            r"x-content-type-options|referrer-policy|permissions-policy))\b",
            re.I,
        ),
        "kill",
        None,
        "Missing security headers on non-browser/JSON APIs are not actionable findings",
    ),
    (
        "self_signed_cert",
        re.compile(r"\b(self[- ]signed (?:cert|certificate)|untrusted certificate)\b", re.I),
        "downgrade",
        "info",
        "Self-signed cert on an internal service is expected / informational without MitM impact proof",
    ),
    (
        "open_port_as_vuln",
        re.compile(
            r"\b(open port|port \d{1,5} (?:is )?open|listening on port)\b.*\b(vuln|vulnerable|critical|high)\b|"
            r"\b(vuln|vulnerable|critical|high)\b.*\b(open port|port \d{1,5} (?:is )?open)\b",
            re.I,
        ),
        "kill",
        None,
        "An open port listed as a vulnerability without an actual vuln/exploit is not a finding",
    ),
    (
        "outdated_no_cve",
        re.compile(r"\b(outdated|end[- ]of[- ]life|eol|unsupported version)\b", re.I),
        "kill",
        None,
        "'Outdated software' without an exact CVE for that version is not a confirmed finding",
    ),
    (
        "scanner_version_match",
        re.compile(
            r"\b(nuclei|nmap)\b.*\b(vulnerable|version[- ]match|cpe:)\b|"
            r"\b(version[- ]match|cpe:).*\b(vulnerable)\b|"
            r"\b\[vulnerable\]\b.*\b(version|detected)\b",
            re.I,
        ),
        "downgrade",
        "info",
        "Scanner 'VULNERABLE' based only on version match (no active exploit test) is a lead, not proof",
    ),
]

SEVERITY_INFLATION = [spec[0] for spec in _SEVERITY_INFLATION_SPECS]

# Signals that the finding HAS proven impact / active exploit — defeats inflation kill.
_PROOF_RE = re.compile(
    r"\b("
    r"default[- ]?(?:creds?|password|passwd|login)|"
    r"cve-\d{4}-\d{4,}|"
    r"open registration|self[- ]registration|"
    r"uid=\d|gid=\d|groups=\d|"
    r"root:x:0:0:|"
    r"canary|oob callback|interactsh|burpcollaborator|"
    r"dumped|exfiltrat|"
    r"cross[- ]user|other user(?:'s)? data|victim (?:pii|data|session)|"
    r"injectable|sqlmap.*vulnerable|successfully dumped|"
    r"webshell|reverse shell|command execution|"
    r"active (?:exploit|poc|test)|reproduced|confirmed impact|"
    r"sensitive (?:file|files|backup|\.env|id_rsa|credentials?)"
    r")\b",
    re.I,
)

# ── Conditional Chain Table ───────────────────────────────────────────────────
CHAIN_CANDIDATES = {
    "open redirect": ["oauth code theft", "phishing"],
    "ssrf dns-only": ["internal data access", "cloud metadata"],
    "cors wildcard": ["credentialed data exfil"],
    "graphql introspection": ["auth bypass on mutations"],
    "s3 bucket listing": ["secrets in js bundles"],
    "subdomain takeover": ["oauth redirect_uri hijack"],
    "prompt injection": ["idor via chatbot"],
    "path traversal": ["/proc/self/environ rce"],
    "jwt weak secret": ["forge admin token"],
    "file upload bypass": ["xss via svg", "rce via webshell"],
}

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Default severity per vulnerability type. Used when the finding line carries
# no explicit severity token. High-impact, generally-confirmed-on-detection
# classes default to critical/high so they are NOT killed by --strict (which
# is documented as "Kill below HIGH").
VTYPE_DEFAULT_SEVERITY = {
    "sqli": "critical",
    "rce": "critical",
    "ssti": "critical",
    "lfi": "high",
    "idor": "high",
    "auth_bypass": "high",
    "business_logic": "high",
    "ssrf": "high",
    "takeover": "high",
    "upload": "high",
    "upload_type_bypass": "high",
    "oauth": "high",
    "cves": "high",
    "xss": "medium",
    "cors": "medium",
    "redirect": "low",
    "misconfig": "low",
    "exposure": "medium",
    "race": "medium",
}

# Explicit severity tokens that may appear in a finding line, e.g.
# "[CRITICAL]", "[HIGH - SQLi]", "(low)", "severity: high".
#
# IMPORTANT: only ANCHORED forms count. A bare severity word elsewhere on the
# line (e.g. "info" inside "http://h/info.php", or "low" inside "low
# false-positive rate") is NOT a severity declaration — honoring it would
# silently DOWNGRADE a confirmed finding (a real SQLi line routinely contains
# such words in its URL/description) and, under --strict, KILL it. So we match
# only bracketed / parenthesized / "severity:"-labelled tokens; everything
# else falls through to the per-vtype default.
_SEVERITY_TOKEN_RE = re.compile(
    r"\[\s*(critical|high|medium|low|info)\b"                    # [CRITICAL]  /  [HIGH - SQLi]
    r"|\(\s*(critical|high|medium|low|info)\s*\)"                # (low)
    r"|\bseverity\s*[:=]\s*(critical|high|medium|low|info)\b"    # severity: high  /  severity=high
    r"|^\s*(critical|high|medium|low|info)\s*:",                 # leading label: "low: verbose ..."
    re.IGNORECASE)


def parse_severity(line: str, vtype: str = "") -> str:
    """Derive a finding's severity.

    Precedence:
      1. An EXPLICIT, anchored severity token in the line (see _SEVERITY_TOKEN_RE).
      2. The per-vtype default from VTYPE_DEFAULT_SEVERITY.
      3. "medium" as a last-resort fallback.
    """
    m = _SEVERITY_TOKEN_RE.search(line or "")
    if m:
        return next(g for g in m.groups() if g).lower()
    return VTYPE_DEFAULT_SEVERITY.get(vtype, "medium")


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower().strip())


def _finding_blob(finding: dict) -> str:
    parts = [
        finding.get("raw", ""),
        finding.get("title", ""),
        finding.get("description", ""),
        finding.get("evidence", ""),
        finding.get("proof", ""),
        finding.get("url", ""),
        finding.get("host", ""),
    ]
    return " ".join(str(p) for p in parts if p)


def has_proven_impact(finding: dict) -> bool:
    """True when the finding text includes a concrete impact/proof artifact."""
    return bool(_PROOF_RE.search(_finding_blob(finding)))


def assess_severity_inflation(finding: dict) -> dict:
    """Critic: kill/downgrade findings that inflate severity without proven impact.

    Returns ``{action: pass|kill|downgrade, to_severity?, reason}``.
    Inspired by PentestCode critic patterns (MIT) — clean-room Python.
    """
    blob = _finding_blob(finding)
    if not blob.strip():
        return {"action": "pass", "reason": "empty finding"}

    proven = has_proven_impact(finding)
    # Special-case: directory listing WITH sensitive-file proof → pass
    # Special-case: outdated WITH exact CVE → pass (has_proven_impact covers CVE-)

    for _id, rx, action, to_sev, reason in _SEVERITY_INFLATION_SPECS:
        if not rx.search(blob):
            continue
        if proven:
            # Admin panel + default creds / CVE → not inflated
            # Directory listing + sensitive files → not inflated
            # Version disclosure + CVE exploit → not inflated
            return {
                "action": "pass",
                "reason": f"Matched inflation pattern '{_id}' but proof present — keep",
            }
        out = {"action": action, "reason": reason}
        if action == "downgrade" and to_sev:
            out["to_severity"] = to_sev
        return out

    return {"action": "pass", "reason": "no severity-inflation pattern matched"}


def is_never_submit(finding_text: str) -> str | None:
    normalized = _normalize(finding_text)
    for pattern in NEVER_SUBMIT:
        # Word/phrase-boundary aware: a never-submit phrase only matches as a
        # standalone token sequence, not as incidental context inside a larger
        # high-impact finding line.
        if re.search(r"\b" + re.escape(pattern) + r"\b", normalized):
            return pattern
    return None


def is_chain_candidate(finding_text: str) -> list[str] | None:
    normalized = _normalize(finding_text)
    for trigger, chains in CHAIN_CANDIDATES.items():
        if trigger in normalized:
            return chains
    return None


def validate_finding(finding: dict) -> dict:
    """Run the 7-Question Gate on a finding.

    Returns dict with:
        decision: "pass" | "kill" | "downgrade" | "chain_required"
        reason: str
        kill_question: int | None
        chains: list[str] | None
        to_severity: str | None  (when downgraded by critic)
    """
    raw = finding.get("raw", "")
    severity = finding.get("severity", "medium")

    # Q7: Never-submit list
    ns_match = is_never_submit(raw)
    if ns_match:
        chains = is_chain_candidate(raw)
        if chains:
            return {"decision": "chain_required", "reason": f"Never-submit '{ns_match}' but chainable",
                    "kill_question": 7, "chains": chains, "to_severity": None}
        # A never-submit substring should not silently discard a finding that
        # parsed as critical/high impact — route it to manual review instead of
        # an outright kill, so a single context phrase cannot drop a real
        # high-impact finding with no degradation marker.
        if SEVERITY_RANK.get(severity, 2) <= 1:
            return {"decision": "chain_required",
                    "reason": f"Never-submit '{ns_match}' but parsed {severity} — manual review",
                    "kill_question": 7, "chains": None, "to_severity": None}
        return {"decision": "kill", "reason": f"Never-submit: {ns_match}",
                "kill_question": 7, "chains": None, "to_severity": None}

    # Critic / severity-inflation (before pass path)
    inflation = assess_severity_inflation(finding)
    if inflation["action"] == "kill":
        return {"decision": "kill", "reason": inflation["reason"],
                "kill_question": 6, "chains": None, "to_severity": None}
    if inflation["action"] == "downgrade":
        to_sev = inflation.get("to_severity", "info")
        return {"decision": "downgrade",
                "reason": inflation["reason"],
                "kill_question": 6, "chains": None, "to_severity": to_sev}

    # Q6: Impact provable?
    if severity in ("low", "info"):
        return {"decision": "downgrade", "reason": f"Low-impact ({severity}) — needs concrete PoC",
                "kill_question": 6, "chains": None, "to_severity": severity}

    return {"decision": "pass", "reason": "Passed 7-question gate",
            "kill_question": None, "chains": None, "to_severity": None}


def validate_findings_dir(findings_dir: str, strict: bool = False) -> dict:
    results = {"pass": [], "kill": [], "downgrade": [], "chain_required": []}
    subdir_vtype = {
        "sqli": "sqli", "xss": "xss", "ssti": "ssti", "rce": "rce",
        "lfi": "lfi", "idor": "idor", "ssrf": "ssrf", "cors": "cors",
        "takeover": "takeover", "exposure": "exposure", "cves": "cves",
        "misconfig": "misconfig", "redirects": "redirect",
        "upload": "upload", "upload_type_bypass": "upload_type_bypass",
        "race": "race", "race_condition": "race",
        "oauth": "oauth", "auth_bypass": "auth_bypass",
        "business_logic": "business_logic",
    }
    for subdir, vtype in subdir_vtype.items():
        path = os.path.join(findings_dir, subdir)
        if not os.path.isdir(path):
            continue
        for fn in sorted(os.listdir(path)):
            if not fn.endswith(".txt"):
                continue
            try:
                with open(os.path.join(path, fn), errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        finding = {"raw": line, "vtype": vtype,
                                   "severity": parse_severity(line, vtype), "url": ""}
                        url_m = re.search(r"https?://\S+", line)
                        if url_m:
                            finding["url"] = url_m.group(0)
                        result = validate_finding(finding)
                        result["finding"] = finding
                        result["source"] = f"{subdir}/{fn}"
                        results[result["decision"]].append(result)
            except OSError:
                continue

    if strict:
        # "Kill below HIGH": keep critical(0)/high(1), drop medium(2)/low(3)/info(4).
        for item in list(results["pass"]):
            if SEVERITY_RANK.get(item["finding"].get("severity", "medium"), 2) > 1:
                item["decision"] = "kill"
                item["reason"] = f"Strict mode: {item['finding']['severity']} killed (below HIGH)"
                results["kill"].append(item)
                results["pass"].remove(item)
    return results


def main():
    parser = argparse.ArgumentParser(description="7-Question Gate finding validator")
    parser.add_argument("findings_dir", help="Findings directory")
    parser.add_argument("--strict", action="store_true", help="Kill below HIGH")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    if not os.path.isdir(args.findings_dir):
        print(f"[-] Not a directory: {args.findings_dir}", file=sys.stderr)
        return 1

    results = validate_findings_dir(args.findings_dir, strict=args.strict)
    if args.json:
        print(json.dumps({k: len(v) for k, v in results.items()}, indent=2))
    else:
        print(f"[+] PASS: {len(results['pass'])} | [-] KILL: {len(results['kill'])} | "
              f"[!] DOWNGRADE: {len(results['downgrade'])} | [~] CHAIN: {len(results['chain_required'])}")
        for item in results["kill"][:10]:
            print(f"  KILL: {item['source']}: {item['reason']}")
        for item in results["chain_required"]:
            print(f"  CHAIN: {item['source']}: {item['chains']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
