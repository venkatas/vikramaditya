#!/usr/bin/env python3
"""
dorks.py — Passive recon via Google dork generation (v9.3.0)

Generates a clickable HTML/JSON/text catalogue of search-engine queries that
surface common engagement-relevant exposures (creds in .env, exposed admin
panels, PII in spreadsheets, M365 tenant SAML metadata, etc.) for a given
client target. No requests are issued from this host — every query is
rendered as a `https://www.google.com/search?q=...` URL so the operator can
review and click through manually. This keeps the passive phase strictly
within "passive intel" rules (no traffic to client, no automation against
Google's TOS) while still standardising the dork list across engagements.

Adapted from `shuvonsec/claude-bug-bounty/scripts/dork_runner.py` (MIT) for
VAPT framing — replaced bug-bounty branding, added engagement categories
(microsoft365, compliance), wired the output path into our session layout
(`recon/<target>/sessions/<id>/passive/dorks.{html,json,txt}`).

Usage:
    python3 dorks.py -d target.com                 # all categories → recon dir
    python3 dorks.py -d target.com -c credentials  # one category
    python3 dorks.py -d target.com --output-dir custom/  # custom out dir
    python3 dorks.py -d target.com --list          # list categories only
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
from datetime import datetime


# ── Colors ────────────────────────────────────────────────────────────────────
class C:
    RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    BLUE = "\033[94m"; CYAN = "\033[96m"; RESET = "\033[0m"; BOLD = "\033[1m"


# ── Dork Templates ────────────────────────────────────────────────────────────
DORK_CATEGORIES: dict[str, list[str]] = {
    "credentials": [
        'site:{target} ext:env',
        'site:{target} ext:env "DB_PASSWORD"',
        'site:{target} ext:env "API_KEY"',
        'site:{target} "api_key" OR "apikey"',
        'site:{target} "secret_key" OR "SECRET_KEY"',
        'site:{target} "password" filetype:log',
        'site:{target} "password" filetype:txt',
        'site:{target} ext:yaml "password:"',
        'site:{target} ext:json "private_key"',
        'site:{target} inurl:".git/config"',
        'site:{target} ext:pem "BEGIN RSA PRIVATE KEY"',
        'site:{target} "aws_secret_access_key"',
        'site:{target} "AKIA" intext:AKIA',
        'site:{target} ext:json "type: service_account"',
    ],
    "pii": [
        'site:{target} ext:csv intext:"email" intext:"phone"',
        'site:{target} ext:xls intext:"ssn"',
        'site:{target} ext:xlsx intext:"date of birth"',
        'site:{target} ext:csv "first name" "last name" "email"',
        'site:{target} filetype:csv "password" "username"',
        'site:{target} intitle:"index of" "users.csv"',
        'site:{target} intitle:"index of" "customers.csv"',
        'site:{target} ext:log intext:"email"',
        'site:{target} filetype:xls "employee" "salary"',
        # v9.3.0 — Aadhaar / PAN / Indian-specific PII (we hunt mostly Indian targets)
        'site:{target} ext:csv intext:"aadhaar" OR intext:"PAN"',
        'site:{target} ext:pdf intext:"aadhaar"',
    ],
    "admin": [
        'site:{target} inurl:admin',
        'site:{target} inurl:/admin/login',
        'site:{target} inurl:/phpmyadmin',
        'site:{target} inurl:/jenkins',
        'site:{target} inurl:/grafana',
        'site:{target} inurl:/kibana',
        'site:{target} inurl:/actuator',
        'site:{target} inurl:/swagger-ui',
        'site:{target} inurl:/api-docs',
        'site:{target} intitle:"admin panel"',
        'site:{target} intitle:"control panel"',
        'site:{target} inurl:"/wp-login.php"',
        'site:{target} inurl:/manager/html',  # Tomcat manager
        'site:{target} inurl:/jmx-console',   # JBoss
    ],
    "errors": [
        'site:{target} "SQL syntax" OR "mysql_fetch"',
        'site:{target} "Warning: mysql_"',
        'site:{target} "Fatal error:" filetype:php',
        'site:{target} "Stack trace:" filetype:html',
        'site:{target} "Traceback (most recent call last)"',
        'site:{target} "NullPointerException"',
        'site:{target} "DEBUG = True" filetype:py',
        'site:{target} "APP_DEBUG=true" ext:env',
        'site:{target} inurl:phpinfo.php',
        'site:{target} ext:log "error"',
        'site:{target} intitle:"index of" "error.log"',
    ],
    "cloud": [
        '"{target}" site:s3.amazonaws.com',
        '"{target}" site:blob.core.windows.net',
        '"{target}" site:storage.googleapis.com',
        '"{target}" site:firebaseio.com',
        '{target}.s3.amazonaws.com',
        'intitle:"index of" site:{target}',
    ],
    "subdomains": [
        'site:*.{target}',
        'site:*.*.{target}',
        'site:*.{target} inurl:login',
        'site:*.{target} inurl:admin',
        'site:*.{target} inurl:api',
        'site:*.{target} inurl:staging',
        'site:*.{target} inurl:dev',
        'site:*.{target} inurl:test',
        'site:*.{target} inurl:uat',
    ],
    "params": [
        'site:{target} inurl:url=http',
        'site:{target} inurl:redirect=http',
        'site:{target} inurl:next=http',
        'site:{target} inurl:?id=',
        'site:{target} inurl:?user_id=',
        'site:{target} inurl:search=',
        'site:{target} inurl:q=',
        'site:{target} inurl:file=',
        'site:{target} inurl:path=',
        'site:{target} inurl:include=',
        'site:{target} inurl:page=',
        'site:{target} inurl:debug=',
    ],
    "leaks": [
        'site:pastebin.com "{target}"',
        'site:pastebin.com "{target}" "password"',
        'site:github.com "{target}" "password"',
        'site:github.com "{target}" "api_key"',
        'site:github.com "{target}" ".env"',
        'site:gist.github.com "{target}"',
        'site:notion.so "{target}"',
        'site:docs.google.com "{target}"',
        'site:trello.com "{target}"',
        # v9.3.0 — additional leak-surface platforms
        'site:replit.com "{target}"',
        'site:codepen.io "{target}"',
        'site:postman.com "{target}"',
    ],
    "github": [
        'site:github.com "{target}" "password"',
        'site:github.com "{target}" "api_key"',
        'site:github.com "{target}" "secret"',
        'site:github.com "{target}" "token"',
        'site:github.com "{target}" extension:env',
        'site:github.com "{target}" filename:config.yml',
        'site:github.com "{target}" filename:.env',
        'site:github.com "{target}" "BEGIN RSA PRIVATE KEY"',
    ],
    "juicy": [
        'site:{target} intitle:"index of" "backup"',
        'site:{target} intitle:"index of" "sql"',
        'site:{target} intitle:"index of" "dump"',
        'site:{target} ext:sql',
        'site:{target} ext:bak',
        'site:{target} ext:old',
        'site:{target} inurl:backup',
        'site:{target} filetype:pdf "confidential"',
        'site:{target} filetype:pdf "internal use only"',
    ],
    # v9.3.0 — VAPT-specific categories
    "microsoft365": [
        # Tenant enumeration via federation/SAML metadata
        'site:login.microsoftonline.com "{target}"',
        'site:outlook.office365.com "{target}"',
        'site:{target} inurl:/.well-known/openid-configuration',
        'site:{target} inurl:/_layouts',           # SharePoint
        'site:{target} inurl:/sites/             ',  # SharePoint sites
        # Public Teams / OneDrive shares
        '"{target}" site:onedrive.live.com',
        '"{target}" site:1drv.ms',
        # Power BI public reports — common Indian enterprise leak
        '"{target}" site:app.powerbi.com',
    ],
    "compliance": [
        # ISO/PCI/SOC2 audit-doc leaks (commonly indexed once published to extranets)
        'site:{target} filetype:pdf "iso 27001"',
        'site:{target} filetype:pdf "soc 2"',
        'site:{target} filetype:pdf "PCI DSS"',
        'site:{target} filetype:pdf "vulnerability assessment"',
        'site:{target} filetype:pdf "penetration test"',
        # Internal policy / DPA / vendor-questionnaire docs
        'site:{target} filetype:pdf "data protection agreement"',
        'site:{target} filetype:pdf "DPA" "personal data"',
        'site:{target} filetype:pdf "non-disclosure"',
        # Engineering runbooks / on-call docs (often leaked to intranet)
        'site:{target} filetype:pdf "runbook"',
        'site:{target} filetype:pdf "incident response"',
    ],
    "all": [],  # filled below
}

# Fill "all" with every other category
for _cat, _dorks in list(DORK_CATEGORIES.items()):
    if _cat != "all":
        DORK_CATEGORIES["all"].extend(_dorks)


def google_url(dork: str) -> str:
    return f"https://www.google.com/search?q={urllib.parse.quote(dork)}&num=50"


def render_html(target: str, results: list[dict], out_path: str) -> None:
    parts = [
        "<!DOCTYPE html>",
        "<html lang='en'><head><meta charset='UTF-8'>",
        f"<title>Passive Dork Catalogue — {target}</title>",
        "<style>",
        "  body{font-family:monospace;background:#1a1a1a;color:#e0e0e0;padding:20px}",
        "  h1{color:#ff4444}",
        "  h2{color:#44aaff;border-bottom:1px solid #333;padding-bottom:5px}",
        "  a{color:#44ff44;text-decoration:none} a:hover{text-decoration:underline}",
        "  .dork{background:#2a2a2a;padding:8px 12px;margin:4px 0;border-radius:4px;border-left:3px solid #44aaff}",
        "  .meta{color:#888;font-size:12px}",
        "  .footer{color:#666;font-size:11px;margin-top:30px;padding-top:10px;border-top:1px solid #333}",
        "</style></head><body>",
        f"<h1>Passive Dork Catalogue — {target}</h1>",
        f"<p class='meta'>Generated {datetime.now().isoformat(timespec='seconds')} | {len(results)} dorks</p>",
        "<p class='meta'>Click each link to run the query in Google. No traffic is sent to the target by this report — that is the operator's responsibility, manually, after reviewing scope.</p>",
    ]
    current_cat = ""
    for item in results:
        if item["category"] != current_cat:
            current_cat = item["category"]
            parts.append(f"<h2>{current_cat.upper()}</h2>")
        parts.append(
            f"<div class='dork'><a href='{item['url']}' target='_blank' rel='noopener'>{item['dork']}</a></div>"
        )
    parts.append(
        "<div class='footer'>Vikramaditya v9.3.0 passive recon · "
        "scope-respecting (no requests issued; clickable URLs only).</div>"
    )
    parts.append("</body></html>")
    with open(out_path, "w") as fh:
        fh.write("\n".join(parts))


def render_text(target: str, results: list[dict], out_path: str) -> None:
    with open(out_path, "w") as fh:
        fh.write(f"# Passive Dork Catalogue — {target}\n")
        fh.write(f"# Generated: {datetime.now().isoformat(timespec='seconds')}\n")
        fh.write(f"# Total dorks: {len(results)}\n\n")
        current_cat = ""
        for item in results:
            if item["category"] != current_cat:
                current_cat = item["category"]
                fh.write(f"\n## [{current_cat}]\n")
            fh.write(f"DORK: {item['dork']}\n")
            fh.write(f"URL:  {item['url']}\n\n")


def render_json(target: str, category: str, results: list[dict], out_path: str) -> None:
    payload = {
        "tool": "vikramaditya.dorks",
        "version": "9.3.0",
        "target": target,
        "category": category,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "total": len(results),
        "dorks": results,
    }
    with open(out_path, "w") as fh:
        json.dump(payload, fh, indent=2)


def generate(target: str, category: str = "all") -> list[dict]:
    """Return the rendered list of {category, dork, url} dicts for `target`.

    Importable from hunt.py / vikramaditya.py — does no I/O.
    """
    if category not in DORK_CATEGORIES:
        raise ValueError(f"Unknown category {category!r}. Available: {sorted(DORK_CATEGORIES)}")
    results: list[dict] = []
    if category == "all":
        # Walk per-category so the output is grouped, not flattened.
        for cat, templates in DORK_CATEGORIES.items():
            if cat == "all":
                continue
            for tmpl in templates:
                d = tmpl.replace("{target}", target)
                results.append({"category": cat, "dork": d, "url": google_url(d)})
    else:
        for tmpl in DORK_CATEGORIES[category]:
            d = tmpl.replace("{target}", target)
            results.append({"category": category, "dork": d, "url": google_url(d)})
    return results


def write_outputs(target: str, category: str, results: list[dict], out_dir: str) -> dict[str, str]:
    """Write html + json + txt artifacts. Returns {fmt: path}."""
    os.makedirs(out_dir, exist_ok=True)
    safe = target.replace("/", "_").replace(":", "_")
    paths = {
        "html": os.path.join(out_dir, f"dorks_{safe}.html"),
        "json": os.path.join(out_dir, f"dorks_{safe}.json"),
        "txt":  os.path.join(out_dir, f"dorks_{safe}.txt"),
    }
    render_html(target, results, paths["html"])
    render_json(target, category, results, paths["json"])
    render_text(target, results, paths["txt"])
    return paths


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dorks",
        description="Vikramaditya passive recon — Google dork catalogue generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\nCategories:\n  " + ", ".join(sorted(DORK_CATEGORIES)),
    )
    parser.add_argument("-d", "--domain", help="Target domain (required unless --list)")
    parser.add_argument("-c", "--category", default="all",
                        choices=sorted(DORK_CATEGORIES.keys()),
                        help="Dork category (default: all)")
    parser.add_argument("--output-dir",
                        help="Output directory. Default: recon/<target>/sessions/<latest>/passive/ "
                             "(falls back to ./dorks_out/ if no session exists)")
    parser.add_argument("--list", action="store_true",
                        help="List categories and dork counts; do not generate")
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    if args.list:
        for cat in sorted(DORK_CATEGORIES):
            n = len(DORK_CATEGORIES[cat])
            print(f"  {cat:<14} {n} dorks")
        return 0

    if not args.domain:
        parser.error("-d/--domain is required (or use --list)")

    target = args.domain.strip().lower().rstrip("/")
    results = generate(target, args.category)

    # Resolve output dir: prefer the latest existing session under recon/<target>/
    if args.output_dir:
        out_dir = args.output_dir
    else:
        repo_root = os.path.dirname(os.path.abspath(__file__))
        sessions_root = os.path.join(repo_root, "recon", target, "sessions")
        latest_session = None
        if os.path.isdir(sessions_root):
            sessions = sorted(
                (d for d in os.listdir(sessions_root)
                 if os.path.isdir(os.path.join(sessions_root, d))),
                reverse=True,
            )
            if sessions:
                latest_session = os.path.join(sessions_root, sessions[0])
        if latest_session:
            out_dir = os.path.join(latest_session, "passive")
        else:
            out_dir = os.path.join(repo_root, "dorks_out", target)

    paths = write_outputs(target, args.category, results, out_dir)

    print(f"{C.CYAN}[*]{C.RESET} target={target}  category={args.category}  count={len(results)}")
    for fmt, p in paths.items():
        print(f"{C.GREEN}[+]{C.RESET} {fmt:<4} → {p}")
    print(
        f"\n{C.YELLOW}[*]{C.RESET} No requests issued. Open the HTML report and click "
        f"queries individually after confirming scope.\n"
        f"    Pro tip: feed the JSON into a passive scraper "
        f"(pagodo/serpapi) under your own rate limit, NEVER against client infra."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
