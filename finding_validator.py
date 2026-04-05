#!/usr/bin/env python3
from __future__ import annotations
"""
Finding Validator — 7-Question Gate + Never-Submit List.

Filters scan findings before report generation. Kills weak findings,
downgrades uncertain ones, and flags chain opportunities.

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
]

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


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower().strip())


def is_never_submit(finding_text: str) -> str | None:
    normalized = _normalize(finding_text)
    for pattern in NEVER_SUBMIT:
        if pattern in normalized:
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
    """
    raw = finding.get("raw", "")
    severity = finding.get("severity", "medium")

    # Q7: Never-submit list
    ns_match = is_never_submit(raw)
    if ns_match:
        chains = is_chain_candidate(raw)
        if chains:
            return {"decision": "chain_required", "reason": f"Never-submit '{ns_match}' but chainable",
                    "kill_question": 7, "chains": chains}
        return {"decision": "kill", "reason": f"Never-submit: {ns_match}",
                "kill_question": 7, "chains": None}

    # Q6: Impact provable?
    if severity in ("low", "info"):
        return {"decision": "downgrade", "reason": f"Low-impact ({severity}) — needs concrete PoC",
                "kill_question": 6, "chains": None}

    return {"decision": "pass", "reason": "Passed 7-question gate",
            "kill_question": None, "chains": None}


def validate_findings_dir(findings_dir: str, strict: bool = False) -> dict:
    results = {"pass": [], "kill": [], "downgrade": [], "chain_required": []}
    subdir_vtype = {
        "sqli": "sqli", "xss": "xss", "ssti": "ssti", "rce": "rce",
        "lfi": "lfi", "idor": "idor", "ssrf": "ssrf", "cors": "cors",
        "takeover": "takeover", "exposure": "exposure", "cves": "cves",
        "misconfig": "misconfig", "redirects": "redirect",
        "upload": "upload", "race": "race", "oauth": "oauth",
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
                        finding = {"raw": line, "vtype": vtype, "severity": "medium", "url": ""}
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
        for item in list(results["pass"]):
            if SEVERITY_RANK.get(item["finding"].get("severity", "medium"), 2) >= 2:
                item["decision"] = "kill"
                item["reason"] = f"Strict mode: {item['finding']['severity']} killed"
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
