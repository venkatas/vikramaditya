#!/usr/bin/env python3
"""
intel.py — CVE intelligence feed for a tech stack (v9.4.0 wired).

Queries GitHub Security Advisory Database + NVD CVE API and writes a
prioritized markdown report to `recon/<target>/intel.md`. Used by
`hunt.py` after recon detects the live tech stack so the brain has fresh
CVE context before generating the scan plan.

No traffic is sent to the client target — both data sources are
public CVE databases.

Usage:
    python3 intel.py --tech "iis,aspnet,jwt"
    python3 intel.py --tech "nextjs,graphql" --target clienta.com
    python3 intel.py --tech "wordpress" --target site.com --output custom/path.md
"""

import argparse
import json
import os
import re
import ssl
import sys
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime

# v9.17.0 — endoflife.date lifecycle integration (credits: https://endoflife.date)
try:
    import eol_check  # type: ignore
    _EOL_AVAILABLE = True
except ImportError:
    _EOL_AVAILABLE = False

# macOS: Python may not have system SSL certs. Use unverified context for API queries.
_SSL_CTX = ssl.create_default_context()
try:
    import certifi
    _SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL_CTX.check_hostname = False
    _SSL_CTX.verify_mode = ssl.CERT_NONE

# ─── Color codes ──────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ─── Tech → npm/pypi/cargo package name mapping ───────────────────────────────
TECH_TO_PACKAGE = {
    "nextjs":    ("npm", "next"),
    "next.js":   ("npm", "next"),
    "graphql":   ("npm", "graphql"),
    "react":     ("npm", "react"),
    "express":   ("npm", "express"),
    "hasura":    ("npm", "hasura"),
    "jwt":       ("npm", "jsonwebtoken"),
    "jsonwebtoken": ("npm", "jsonwebtoken"),
    "axios":     ("npm", "axios"),
    "webpack":   ("npm", "webpack"),
    "lodash":    ("npm", "lodash"),
    "node":      ("npm", "node"),
    "django":    ("pip", "django"),
    "flask":     ("pip", "flask"),
    "rails":     ("gem", "rails"),
    "spring":    ("maven", "spring"),
    # v9.23 — map the JS bundler so it resolves to the real npm package instead of
    # a bare "vite" keyword (which NVD matched to ViteMoneyCoin / VITEC / Vitess).
    "vite":      ("npm", "vite"),
}

# v9.23 — tokens that are protocols/headers/transport features, not products, plus
# generic framework names whose bare NVD keyword search collides with unrelated
# products. Mirrors cve.py. These get NO bare-keyword NVD search.
NON_PRODUCT_TECHS = {
    "hsts", "https", "http", "http/1.1", "http/2", "http/3", "h2", "h3",
    "ssl", "tls", "preload", "gzip", "deflate", "br", "chunked", "keep-alive",
    "cors", "csp", "set-cookie", "cookie", "etag", "cache-control",
    "strict-transport-security",
}
AMBIGUOUS_BARE_TECHS = {
    "bootstrap", "jquery", "parsley.js", "parsley", "modernizr",
    "underscore", "moment", "select2",
    # v9.23 — JS frameworks whose bare NVD keyword collides with unrelated products:
    # "vue" matched HP-UX VUE 3.0 (1994), Pearson VUE, Carestream Vue RIS.
    "vue", "vuejs", "vue.js", "react", "angular", "ember",
}

# v9.23 — drop ancient version-less keyword matches. A bare "wordpress"/"php"
# search returns WordPress 1.2 (2004) / php.cgi (1999) CVEs on a stack actually
# running WordPress 6.8 / PHP 7.4. CVEs published before this year are treated as
# keyword noise unless a version correlation is present.
NVD_MIN_YEAR = 2012


def _split_tech(token: str) -> tuple[str, str]:
    """'php=7.4.33' / 'php:7.4.33' -> ('php', '7.4.33'); bare 'php' -> ('php', '')."""
    m = re.match(r"^\s*(.+?)\s*[=:]\s*([0-9][\w.\-]*)\s*$", token or "")
    if m:
        return m.group(1).strip().lower(), m.group(2).strip()
    return (token or "").strip().lower(), ""


def _nvd_searchable(tech: str) -> bool:
    """True if a token is safe to send to NVD as a free-text keyword search."""
    tl = (tech or "").lower().strip()
    if not tl or len(tl) < 2:
        return False
    if tl in TECH_TO_PACKAGE:        # explicitly mapped -> trusted
        return True
    if tl in NON_PRODUCT_TECHS:
        return False
    if tl in AMBIGUOUS_BARE_TECHS:   # unmapped + ambiguous -> skip the keyword noise
        return False
    return True

# ─── Tech → grep patterns to search for in source code ────────────────────────
TECH_GREP_PATTERNS = {
    "nextjs": [
        "grep -rn 'getServerSideProps' --include='*.ts' --include='*.tsx' | grep 'fetch'",
        "grep -rn 'middleware' --include='*.ts' | grep -v test",
        "grep -rn 'rewrite\\|redirect' next.config",
    ],
    "graphql": [
        "grep -rn 'internalId\\|id:' --include='*.graphql' --include='*.ts'",
        "grep -rn 'introspection\\|__schema' --include='*.ts'",
        "grep -rn 'context\\.user\\|context\\.auth' --include='*.ts' | grep -v test",
    ],
    "jwt": [
        "grep -rn \"=== \" --include='*.ts' | grep -i 'token\\|secret\\|key'",
        "grep -rn 'alg.*none\\|algorithm.*none' --include='*.ts'",
        "grep -rn 'jwt\\.verify\\|jwt\\.decode' --include='*.ts'",
    ],
    "hasura": [
        "grep -rn 'x-hasura-role\\|x-hasura-admin-secret' --include='*.ts'",
        "grep -rn 'HASURA_GRAPHQL_JWT_SECRET\\|HASURA_SECRET' --include='*.env*'",
        "grep -rn 'hasuraClaims\\|hasura_claims' --include='*.ts'",
    ],
    "solidity": [
        "grep -rn 'tx\\.origin\\|delegatecall\\|selfdestruct' --include='*.sol'",
        "grep -rn 'transfer(\\|send(\\|call{' --include='*.sol'",
        "grep -rn 'block\\.timestamp\\|now' --include='*.sol'",
    ],
    "oauth": [
        "grep -rn 'redirect_uri\\|returnTo\\|next=' --include='*.ts'",
        "grep -rn 'state.*param\\|csrf.*oauth' --include='*.ts' -i",
        "grep -rn 'code_verifier\\|PKCE' --include='*.ts' -i",
    ],
}

# ─── HackerOne tech keyword mapping ───────────────────────────────────────────
TECH_H1_KEYWORDS = {
    "nextjs":   ["next.js", "nextjs", "vercel"],
    "graphql":  ["graphql", "introspection", "graphql idor"],
    "jwt":      ["jwt", "json web token", "token forgery"],
    "hasura":   ["hasura", "graphql engine"],
    "solidity": ["solidity", "smart contract", "reentrancy"],
    "oauth":    ["oauth", "oidc", "redirect_uri", "open redirect oauth"],
    "ssrf":     ["ssrf", "server-side request forgery"],
    "idor":     ["idor", "insecure direct object"],
    "xss":      ["xss", "cross-site scripting"],
    "csrf":     ["csrf", "cross-site request forgery"],
}


def fetch_url(url: str, headers: dict = None, data: bytes = None, timeout: int = 10) -> dict | None:
    """Simple HTTP fetch, returns parsed JSON or None on error."""
    req = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return json.loads(body)
    except urllib.error.HTTPError as e:
        print(f"  {YELLOW}HTTP {e.code} for {url}{RESET}")
        return None
    except Exception as e:
        print(f"  {YELLOW}Error fetching {url}: {e}{RESET}")
        return None


def fetch_github_advisories(tech: str) -> list[dict]:
    """Query GitHub Advisory Database for a package."""
    ecosystem, package = TECH_TO_PACKAGE.get(tech.lower(), (None, None))
    if not ecosystem or not package:
        return []

    url = f"https://api.github.com/advisories?ecosystem={ecosystem}&affects={urllib.parse.quote(package)}&per_page=10"
    data = fetch_url(url, headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    if not data or not isinstance(data, list):
        return []

    results = []
    for item in data:
        severity = item.get("severity", "unknown").upper()
        summary  = item.get("summary", "No summary")[:120]
        ghsa_id  = item.get("ghsa_id", "")
        published = item.get("published_at", "")[:10]
        cves     = [x.get("value", "") for x in item.get("identifiers", []) if x.get("type") == "CVE"]
        cve_str  = cves[0] if cves else ghsa_id
        results.append({
            "id":        cve_str,
            "source":    "GitHub Advisory",
            "tech":      tech,
            "severity":  severity,
            "summary":   summary,
            "published": published,
            "grep":      TECH_GREP_PATTERNS.get(tech.lower(), ["(see tech grep patterns above)"]),
        })
    return results


def fetch_nvd_cves(tech: str) -> list[dict]:
    """Query NVD CVE API by keyword."""
    # v9.23 — skip protocol/header tokens (e.g. "hsts") and unmapped ambiguous
    # framework names (e.g. bare "bootstrap"/"jquery") whose keyword search returns
    # unrelated products. Mapped tokens (TECH_TO_PACKAGE) still run.
    if not _nvd_searchable(tech):
        return []
    query = TECH_TO_PACKAGE.get(tech.lower(), (None, tech))[1]
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(query)}&resultsPerPage=5"
    data = fetch_url(url, timeout=15)
    if not data:
        return []

    results = []
    for item in (data.get("vulnerabilities") or []):
        cve = item.get("cve", {})
        cve_id   = cve.get("id", "")
        desc     = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")[:120]
        metrics  = cve.get("metrics", {})
        score    = None
        severity = "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                score    = m.get("cvssData", {}).get("baseScore")
                severity = m.get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                break
        published = cve.get("published", "")[:10]
        # v9.23 — drop ancient version-less keyword noise (WordPress 1.2 / php.cgi
        # 1999) that a bare-name search returns for a modern stack.
        try:
            if published and int(published[:4]) < NVD_MIN_YEAR:
                continue
        except ValueError:
            pass
        results.append({
            "id":        cve_id,
            "source":    "NVD",
            "tech":      tech,
            "severity":  severity,
            "summary":   desc,
            "published": published,
            "score":     score,
            "grep":      TECH_GREP_PATTERNS.get(tech.lower(), []),
        })
    return results


def fetch_hackerone_hacktivity(keyword: str, limit: int = 5) -> list[dict]:
    """Query HackerOne Hacktivity public GraphQL for a keyword."""
    # Pass the keyword as a GraphQL variable, never interpolated into the
    # document text. Interpolating it directly let a target-controlled token
    # (e.g. a quote-bearing Server header) terminate the GraphQL string and
    # silently drop HackerOne intel for that tech.
    query = {
        "query": f"""query($kw: String!) {{
          hacktivity_items(
            first: {limit},
            order_by: {{ field: popular, direction: DESC }},
            where: {{
              report: {{ title: {{ _icontains: $kw }} }},
              disclosed_at: {{ _is_null: false }}
            }}
          ) {{
            nodes {{
              ... on HacktivityDocument {{
                report {{
                  title
                  severity_rating
                  disclosed_at
                  url
                }}
              }}
            }}
          }}
        }}""",
        "variables": {"kw": keyword},
    }
    data = fetch_url(
        "https://hackerone.com/graphql",
        headers={"Content-Type": "application/json"},
        data=json.dumps(query).encode(),
    )
    if not data:
        return []

    results = []
    nodes = (data.get("data") or {}).get("hacktivity_items", {}).get("nodes", [])
    for node in nodes:
        report = node.get("report")
        if not report:
            continue
        results.append({
            "id":        report.get("url", ""),
            "source":    "HackerOne",
            "tech":      keyword,
            "severity":  (report.get("severity_rating") or "unknown").upper(),
            "summary":   report.get("title", ""),
            "published": (report.get("disclosed_at") or "")[:10],
            "grep":      [],
        })
    return results


def fetch_cvemap(tech: str, limit: int = 20) -> list[dict]:
    """v9.5.0 — query ProjectDiscovery cvemap CLI for CVEs by product.

    cvemap maintains a continuously-updated CVE database with KEV /
    public-PoC / EPSS metadata. Faster than NVD's HTTPS API and richer
    metadata than GHSA. Falls back silently if the binary isn't on PATH.
    Outputs are normalized to the same dict shape as the NVD/GHSA
    fetchers so downstream rendering doesn't care about the source.

    Requires a free PDCP API key (set via `cvemap -auth` or
    PDCP_API_KEY env var). If the key is missing, cvemap exits 2 with
    "api key cannot be empty" — we swallow that and return [], so the
    GHSA + NVD fallback paths still produce intel.
    """
    import shutil as _shutil
    import subprocess as _sub
    binary = _shutil.which("cvemap")
    if not binary:
        return []
    try:
        proc = _sub.run(
            [binary, "-product", tech, "-json", "-silent",
             "-limit", str(limit), "-disable-update-check"],
            capture_output=True, text=True, timeout=60,
        )
    except Exception:
        return []
    if proc.returncode != 0 or not proc.stdout.strip():
        return []
    out: list[dict] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            cve = json.loads(line)
        except json.JSONDecodeError:
            continue
        cvss = (cve.get("cvss_metrics") or {}).get("cvss31") or {}
        sev = (cvss.get("severity") or cve.get("severity") or "unknown").upper()
        cve_id = cve.get("cve_id") or cve.get("id") or ""
        out.append({
            "tech": tech,
            "source": "cvemap",
            "id": cve_id,
            "severity": sev,
            "summary": (cve.get("description") or "")[:300],
            "published": (cve.get("published_date") or "")[:10],
            "grep": [cve_id] if cve_id else [],
            "kev": bool(cve.get("is_kev") or cve.get("in_kev")),
            "epss": (cve.get("epss") or {}).get("score"),
        })
    return out


def fetch_intel(techs: list[str]) -> list[dict]:
    """Collect intel from all sources for all techs."""
    all_results = []
    for raw in techs:
        # v9.23 — CVE/advisory searches use the bare product NAME; any attached
        # version (e.g. "php=7.4.33") is consumed by the EOL block instead.
        tech, _ver = _split_tech(raw)
        # v9.5.0 — cvemap first (local PD cache, fast); fall back to GHSA + NVD
        cvm = fetch_cvemap(tech)
        if cvm:
            print(f"  {CYAN}[{tech}]{RESET} cvemap returned {len(cvm)} CVEs")
            all_results.extend(cvm)

        print(f"  {CYAN}[{tech}]{RESET} Querying GitHub Advisory Database...")
        all_results.extend(fetch_github_advisories(tech))

        print(f"  {CYAN}[{tech}]{RESET} Querying NVD CVE API...")
        all_results.extend(fetch_nvd_cves(tech))

        # HackerOne — use keyword variations
        keywords = TECH_H1_KEYWORDS.get(tech.lower(), [tech])
        for kw in keywords[:2]:  # limit to 2 keywords per tech to avoid slow queries
            print(f"  {CYAN}[{tech}]{RESET} Querying HackerOne Hacktivity for '{kw}'...")
            all_results.extend(fetch_hackerone_hacktivity(kw, limit=5))

    return all_results


def severity_order(s: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "MODERATE": 2, "LOW": 3, "UNKNOWN": 4}.get(s.upper(), 4)


def build_markdown(techs: list[str], results: list[dict]) -> str:
    """Build intel.md content."""
    lines = [
        f"# Bug Intelligence Report",
        f"",
        f"**Technologies:** {', '.join(techs)}",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"**Sources:** GitHub Advisory DB, NVD CVE API, HackerOne Hacktivity, endoflife.date (lifecycle)",
        f"",
        f"---",
        f"",
    ]

    # v9.17.0 — Lifecycle / EOL block (data: endoflife.date, MIT licensed)
    if _EOL_AVAILABLE:
        try:
            # v9.23 — pass the DETECTED VERSION so the EOL check matches the right
            # lifecycle cycle. Previously this hardcoded None, so e.g. "php=7.4.33"
            # was looked up as bare "php" and reported the generic latest cycle as
            # "Supported" — false-negativing that PHP 7.4 is end-of-life.
            eol_results = eol_check.lookup_many(
                [(name, ver or None) for name, ver in (_split_tech(t) for t in techs)])
            mapped = [r for r in eol_results if r.get("slug")]
            if mapped:
                lines += [
                    "## Lifecycle / End-of-Life Status",
                    "",
                    f"_Data source: [endoflife.date]({eol_check.ENDOFLIFE_HOMEPAGE}) — please credit when redistributing._",
                    "",
                    "| Tech | Slug | Latest cycle | EOL | Status |",
                    "|---|---|---|---|---|",
                ]
                for r in eol_results:
                    if not r.get("slug"):
                        continue
                    cyc = r.get("matched_cycle") or {}
                    eol_v = cyc.get("eol")
                    eol_s = ("supported" if eol_v is False else
                             "expired"  if eol_v is True  else (eol_v or "—"))
                    icon = {"expired": "🔴 EOL", "soon": "🟠 Ending soon",
                            "supported": "🟢 Supported", "unknown": "⚪ Unknown",
                            "no_data": "⚪ Not tracked"}.get(r["status"], r["status"])
                    lines.append(
                        f"| {r['tech']} | `{r['slug']}` | "
                        f"{cyc.get('cycle','—')} (rel {cyc.get('releaseDate','—')}) | "
                        f"{eol_s} | {icon} |"
                    )
                lines += ["", "---", ""]
        except Exception as exc:  # never block the rest of intel on this
            lines += [f"_Lifecycle lookup skipped — endoflife.date error: {exc}_", "", "---", ""]

    # Group by tech
    by_tech: dict[str, list[dict]] = {}
    for r in results:
        t = r["tech"]
        by_tech.setdefault(t, []).append(r)

    _seen_tech = set()
    for tech in techs:
        # v9.23 — normalize the raw token to the same canonical key the fetchers
        # store under (lowercased, version-stripped). Without this, version-tagged
        # or mixed-case tokens like "php=7.4.33"/"IIS" miss the by_tech lookup and
        # render "_No results found_" even when CVEs were fetched.
        name = _split_tech(tech)[0]
        # Two raw tokens can collapse to the same canonical name (e.g. both "php"
        # and "php=7.4.33") — render each tech section only once.
        if name in _seen_tech:
            continue
        _seen_tech.add(name)
        tech_results = by_tech.get(name, [])
        tech_results.sort(key=lambda x: severity_order(x.get("severity", "UNKNOWN")))

        lines.append(f"## {name.upper()}")
        lines.append("")

        if not tech_results:
            lines.append("_No results found. Check manually at https://security.snyk.io_")
            lines.append("")
            continue

        lines.append("| ID | Source | Severity | Summary | Published |")
        lines.append("|---|---|---|---|---|")
        for r in tech_results[:15]:
            id_str   = f"[{r['id']}]({r['id']})" if r['id'].startswith("http") else r['id']
            sev      = r.get("severity", "?")
            summary  = r.get("summary", "")[:100].replace("|", "\\|")
            pub      = r.get("published", "")
            source   = r.get("source", "")
            lines.append(f"| {id_str} | {source} | {sev} | {summary} | {pub} |")

        lines.append("")

        # Add grep patterns if available
        # _split_tech already lowercased + stripped any version suffix, so this
        # now matches for version-tagged tokens (e.g. "php=7.4.33") too.
        patterns = TECH_GREP_PATTERNS.get(name, [])
        if patterns:
            lines.append(f"### Grep Patterns for `{name}` (run in target repo)")
            lines.append("")
            lines.append("```bash")
            for p in patterns:
                lines.append(p)
            lines.append("```")
            lines.append("")

    lines += [
        "---",
        "",
        "## Manual Research Links",
        "",
        "```bash",
        "# Snyk vulnerability DB",
        "open https://security.snyk.io/vuln?type=npm&search=PACKAGE_NAME",
        "",
        "# GitHub Security Advisories",
        "open https://github.com/advisories?query=TECH",
        "",
        "# HackerOne Hacktivity search",
        "open https://hackerone.com/hacktivity?querystring=TECH",
        "",
        "# pentester.land writeup aggregator",
        "open https://pentester.land/writeups/?search=TECH",
        "```",
    ]

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Fetch bug intelligence for a tech stack")
    parser.add_argument("--tech",    required=True, help="Comma-separated technologies (e.g., nextjs,graphql)")
    parser.add_argument("--target",  default="",    help="Target name for output folder (optional)")
    parser.add_argument("--output",  default="",    help="Output file path")
    parser.add_argument("--hackerone-program", default="", help="HackerOne program handle for targeted search")
    args = parser.parse_args()

    techs = [t.strip() for t in args.tech.split(",") if t.strip()]

    # Determine output path
    if args.output:
        output_path = args.output
    elif args.target:
        base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "recon", args.target)
        os.makedirs(base_dir, exist_ok=True)
        output_path = os.path.join(base_dir, "intel.md")
    else:
        output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "intel.md")

    print(f"\n{BOLD}Bug Intelligence Fetcher{RESET}")
    print(f"Technologies: {CYAN}{', '.join(techs)}{RESET}")
    print(f"Output: {output_path}\n")

    results = fetch_intel(techs)

    # If program specified, add program-specific HackerOne results
    if args.hackerone_program:
        print(f"  {CYAN}Fetching HackerOne disclosures for program: {args.hackerone_program}{RESET}")
        # Pass the program handle as a GraphQL variable, never interpolated
        # into the document text (see fetch_hackerone_hacktivity above).
        query = {
            "query": """query($handle: String!) {
              hacktivity_items(
                first: 20,
                order_by: { field: popular, direction: DESC },
                where: {
                  team: { handle: { _eq: $handle } },
                  disclosed_at: { _is_null: false }
                }
              ) {
                nodes {
                  ... on HacktivityDocument {
                    report {
                      title
                      severity_rating
                      disclosed_at
                      url
                    }
                  }
                }
              }
            }""",
            "variables": {"handle": args.hackerone_program},
        }
        data = fetch_url(
            "https://hackerone.com/graphql",
            headers={"Content-Type": "application/json"},
            data=json.dumps(query).encode(),
        )
        if data:
            nodes = (data.get("data") or {}).get("hacktivity_items", {}).get("nodes", [])
            for node in nodes:
                report = node.get("report")
                if report:
                    results.append({
                        "id":        report.get("url", ""),
                        "source":    f"HackerOne/{args.hackerone_program}",
                        "tech":      "program-disclosures",
                        "severity":  (report.get("severity_rating") or "unknown").upper(),
                        "summary":   report.get("title", ""),
                        "published": (report.get("disclosed_at") or "")[:10],
                        "grep":      [],
                    })
            techs.append("program-disclosures")

    content = build_markdown(techs, results)
    with open(output_path, "w") as f:
        f.write(content)

    total = len(results)
    high  = sum(1 for r in results if severity_order(r.get("severity", "")) <= 1)
    print(f"\n{BOLD}{GREEN}Done!{RESET}  {total} findings ({RED}{high} HIGH/CRITICAL{RESET})")
    print(f"Report: {output_path}\n")

    # Print top findings to terminal
    results.sort(key=lambda x: severity_order(x.get("severity", "UNKNOWN")))
    print(f"{BOLD}Top findings:{RESET}")
    for r in results[:10]:
        sev = r.get("severity", "?")
        c   = RED if severity_order(sev) <= 1 else (YELLOW if severity_order(sev) == 2 else GREEN)
        print(f"  {c}[{sev}]{RESET} [{r['source']}] {r['summary'][:90]}")
    print()


if __name__ == "__main__":
    main()
