#!/usr/bin/env python3
from __future__ import annotations
"""
Chain Builder — A→B exploit escalation discovery.

Given initial findings, looks up the chain table and suggests
escalation paths that turn medium findings into critical ones.

Usage:
    python3 chain_builder.py <findings_dir>
    python3 chain_builder.py <findings_dir> --output chains.json
"""

import argparse
import json
import os
import re
import sys

# ── A→B Chain Lookup Table ────────────────────────────────────────────────────
# Each entry: (trigger_pattern, B_tests, combined_impact, description)
CHAIN_TABLE = [
    {
        "trigger": "idor",
        "trigger_method": "GET",
        "b_tests": ["IDOR on PUT/DELETE same path", "IDOR on sibling endpoints"],
        "combined_impact": "high",
        "description": "GET IDOR → try PUT/DELETE on same resource for write access",
    },
    {
        "trigger": "auth_bypass",
        "trigger_method": None,
        "b_tests": ["Every sibling endpoint in same controller"],
        "combined_impact": "high",
        "description": "Auth bypass → check all siblings for unauthenticated access",
    },
    {
        "trigger": "xss",
        "trigger_method": None,
        "b_tests": ["Admin views stored XSS → privilege escalation"],
        "combined_impact": "critical",
        "description": "Stored XSS → if admin views it, auto-submit priv esc payload",
    },
    {
        "trigger": "ssrf",
        "trigger_method": None,
        "b_tests": ["169.254.169.254 cloud metadata", "Internal service access"],
        "combined_impact": "critical",
        "description": "SSRF DNS callback → escalate to cloud metadata / internal APIs",
    },
    {
        "trigger": "open_redirect",
        "trigger_method": None,
        "b_tests": ["OAuth redirect_uri → authorization code theft"],
        "combined_impact": "critical",
        "description": "Open redirect → steal OAuth code via redirect_uri manipulation",
    },
    {
        "trigger": "s3_listing",
        "trigger_method": None,
        "b_tests": ["JS bundles → grep for OAuth client_secret / API keys"],
        "combined_impact": "high",
        "description": "S3 bucket listing → find secrets in JavaScript bundles",
    },
    {
        "trigger": "graphql_introspection",
        "trigger_method": None,
        "b_tests": ["Auth bypass on mutations", "IDOR via node() queries"],
        "combined_impact": "high",
        "description": "GraphQL introspection → find unprotected mutations / node() IDOR",
    },
    {
        "trigger": "subdomain_takeover",
        "trigger_method": None,
        "b_tests": ["OAuth redirect_uri at taken-over subdomain"],
        "combined_impact": "critical",
        "description": "Subdomain takeover → hijack OAuth flows via redirect_uri",
    },
    {
        "trigger": "jwt_weak",
        "trigger_method": None,
        "b_tests": ["Forge admin token with cracked secret"],
        "combined_impact": "critical",
        "description": "JWT weak secret → forge admin JWT → full account takeover",
    },
    {
        "trigger": "file_upload",
        "trigger_method": None,
        "b_tests": ["SVG upload → stored XSS", "PHP/JSP upload → RCE"],
        "combined_impact": "critical",
        "description": "File upload bypass → escalate to XSS via SVG or RCE via webshell",
    },
    {
        "trigger": "path_traversal",
        "trigger_method": None,
        "b_tests": ["/proc/self/environ → environment variables → RCE"],
        "combined_impact": "critical",
        "description": "Path traversal → read /proc/self/environ for secrets → RCE",
    },
    {
        "trigger": "lfi",
        "trigger_method": None,
        "b_tests": ["Log poisoning → RCE", "/etc/passwd → user enumeration"],
        "combined_impact": "critical",
        "description": "LFI → log poisoning for RCE or sensitive file disclosure",
    },
]


def find_chains(findings_dir: str) -> list[dict]:
    """Scan findings directory and return chain opportunities."""
    chains = []

    subdir_vtype = {
        "sqli": "sqli", "xss": "xss", "ssti": "ssti", "rce": "rce",
        "lfi": "lfi", "idor": "idor", "ssrf": "ssrf", "cors": "cors",
        "takeover": "takeover", "exposure": "exposure",
        "redirects": "open_redirect", "upload": "file_upload",
        "graphql": "graphql_introspection", "jwt": "jwt_weak",
    }

    found_types = set()
    found_findings = {}

    for subdir, vtype in subdir_vtype.items():
        path = os.path.join(findings_dir, subdir)
        if not os.path.isdir(path):
            continue
        for fn in sorted(os.listdir(path)):
            if not fn.endswith(".txt"):
                continue
            filepath = os.path.join(path, fn)
            try:
                with open(filepath, errors="replace") as f:
                    lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
                if lines:
                    found_types.add(vtype)
                    found_findings[vtype] = {"source": f"{subdir}/{fn}", "count": len(lines),
                                             "sample": lines[0][:200]}
            except OSError:
                continue

    # Match findings against chain table
    for chain in CHAIN_TABLE:
        trigger = chain["trigger"]
        if trigger in found_types:
            chains.append({
                "trigger_finding": trigger,
                "trigger_source": found_findings[trigger]["source"],
                "trigger_sample": found_findings[trigger]["sample"],
                "b_tests": chain["b_tests"],
                "combined_impact": chain["combined_impact"],
                "description": chain["description"],
            })

    return chains


def main():
    parser = argparse.ArgumentParser(description="Chain Builder — A→B exploit escalation")
    parser.add_argument("findings_dir", help="Findings directory")
    parser.add_argument("--output", help="Output JSON file")
    args = parser.parse_args()

    if not os.path.isdir(args.findings_dir):
        print(f"[-] Not a directory: {args.findings_dir}", file=sys.stderr)
        return 1

    chains = find_chains(args.findings_dir)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(chains, f, indent=2)
        print(f"[+] {len(chains)} chain opportunities → {args.output}")
    else:
        if not chains:
            print("[*] No chain opportunities found")
        else:
            print(f"[+] {len(chains)} chain opportunities:\n")
            for c in chains:
                print(f"  {c['trigger_finding'].upper()} → {c['combined_impact'].upper()}")
                print(f"    Source: {c['trigger_source']}")
                print(f"    Description: {c['description']}")
                for b in c["b_tests"]:
                    print(f"    → Test: {b}")
                print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
