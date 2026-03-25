#!/usr/bin/env python3
from __future__ import annotations

"""
Tech CVE Priority Engine
Parses httpx tech-detect output, scores each host based on detected
technologies against a CVE risk map, and outputs a prioritized list.

Usage:
    python3 tech_priority.py <httpx_output_file> <output_file>
    cat httpx_full.txt | python3 tech_priority.py - prioritized.txt
"""

import sys
import re
import json
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

# ─── CVE Risk Map ────────────────────────────────────────────────────────────
# Format: 'tech_keyword_lowercase': (cvss_score, 'CVE-IDs / description')
TECH_CVE_MAP = {
    # RCE Critical (9-10)
    "log4j":            (10, "CVE-2021-44228 Log4Shell RCE (CVSS 10.0)"),
    "log4shell":        (10, "CVE-2021-44228 Log4Shell RCE (CVSS 10.0)"),
    "spring":           (9,  "CVE-2022-22965 Spring4Shell RCE (CVSS 9.8)"),
    "spring framework": (9,  "CVE-2022-22965 Spring4Shell RCE (CVSS 9.8)"),
    "confluence":       (9,  "CVE-2022-26134 OGNL injection RCE (CVSS 9.8)"),
    "weblogic":         (9,  "CVE-2020-14882 Auth bypass + RCE (CVSS 9.8)"),
    "apache struts":    (9,  "CVE-2017-5638 Struts RCE (CVSS 10.0)"),
    "jboss":            (9,  "CVE-2017-12149 Deserialization RCE (CVSS 9.8)"),
    "wildfly":          (9,  "CVE-2017-12149 Deserialization RCE (CVSS 9.8)"),
    "citrix":           (9,  "CVE-2019-19781 Path Traversal RCE (CVSS 9.8)"),
    "citrix netscaler": (9,  "CVE-2023-3519 Auth bypass RCE (CVSS 9.8)"),
    "pulse secure":     (9,  "CVE-2019-11510 Arbitrary file read (CVSS 10.0)"),
    "fortios":          (9,  "CVE-2018-13379 Path traversal (CVSS 9.8)"),
    "fortigate":        (9,  "CVE-2023-27997 Heap overflow RCE (CVSS 9.8)"),
    "f5 big-ip":        (9,  "CVE-2020-5902 RCE via TMUI (CVSS 9.8)"),
    "f5":               (9,  "CVE-2022-1388 Auth bypass (CVSS 9.8)"),
    "vmware":           (9,  "CVE-2021-21985 vCenter RCE (CVSS 9.8)"),
    "exchange":         (9,  "CVE-2021-26855 ProxyLogon RCE (CVSS 9.8)"),
    "microsoft exchange":(9, "CVE-2021-26855 ProxyLogon RCE (CVSS 9.8)"),
    "jenkins":          (9,  "CVE-2017-1000353 Java deserialization RCE (CVSS 9.8)"),
    "gitlab":           (9,  "CVE-2021-22205 RCE via image parser (CVSS 9.9)"),
    "drupal":           (9,  "CVE-2018-7600 Drupalgeddon2 RCE (CVSS 9.8)"),
    "ghostscript":      (9,  "CVE-2023-36664 RCE (CVSS 9.8)"),
    "coldfusion":       (9,  "CVE-2023-29298 Auth bypass (CVSS 9.8)"),
    "adobe coldfusion": (9,  "CVE-2023-26360 Auth bypass RCE (CVSS 9.8)"),
    "moveit":           (10, "CVE-2023-34362 SQLi to RCE (CVSS 9.8)"),
    "ivanti":           (10, "CVE-2024-21887 RCE (CVSS 9.1)"),
    "openfire":         (9,  "CVE-2023-32315 Path traversal Auth bypass (CVSS 9.8)"),
    "langflow":         (10, "CVE-2025-34291 token hijack to RCE + multiple auth/API flaws"),
    "dify":             (9,  "CVE-2025-3466 RCE / CVE-2024-11822 SSRF / multi-tenant auth issues"),

    # High (7-8.9)
    "wordpress":        (7,  "CVE-2022-21661 SQLi + multiple plugin CVEs"),
    "laravel":          (8,  "CVE-2021-3129 Debug mode RCE (CVSS 9.8)"),
    "jira":             (8,  "CVE-2019-11581 SSTI RCE (CVSS 9.8)"),
    "grafana":          (7,  "CVE-2021-43798 Path Traversal (CVSS 7.5)"),
    "kibana":           (7,  "CVE-2019-7609 Prototype pollution RCE (CVSS 9.1)"),
    "websphere":        (8,  "CVE-2020-4450 Deserialization RCE (CVSS 9.8)"),
    "tomcat":           (7,  "CVE-2020-1938 AJP Ghostcat file read (CVSS 9.8)"),
    "apache tomcat":    (7,  "CVE-2020-1938 AJP Ghostcat file read (CVSS 9.8)"),
    "glassfish":        (7,  "CVE-2017-1000028 Directory traversal (CVSS 7.5)"),
    "phpmyadmin":       (7,  "CVE-2020-26934 XSS + multiple auth bypass CVEs"),
    "adminer":          (8,  "CVE-2021-21311 SSRF (CVSS 7.3)"),
    "rails":            (7,  "CVE-2019-5420 Dev mode RCE (CVSS 9.8)"),
    "ruby on rails":    (7,  "CVE-2019-5420 Dev mode RCE (CVSS 9.8)"),
    "elasticsearch":    (7,  "Unauthenticated access / CVE-2015-1427 Groovy RCE"),
    "redis":            (8,  "Unauthenticated access via SSRF chain to RCE"),
    "mongodb":          (7,  "Unauthenticated access / NoSQLi"),
    "glpi":             (8,  "CVE-2023-35924 Auth bypass (CVSS 8.5)"),
    "zabbix":           (8,  "CVE-2022-23131 SAML auth bypass (CVSS 9.8)"),
    "cacti":            (9,  "CVE-2022-46169 Auth bypass + RCE (CVSS 9.8)"),
    "nagios":           (7,  "CVE-2021-37352 Auth bypass (CVSS 7.5)"),
    "sonarqube":        (7,  "CVE-2021-32827 RCE via webhooks (CVSS 8.8)"),
    "mattermost":       (7,  "CVE-2021-37865 IDOR (CVSS 6.5)"),
    "nextcloud":        (7,  "CVE-2023-28644 Path traversal (CVSS 7.5)"),
    "owncloud":         (9,  "CVE-2023-49105 Auth bypass (CVSS 9.8)"),
    "openssl":          (7,  "CVE-2022-0778 DoS / CVE-2014-0160 Heartbleed"),
    "flowise":          (8,  "CVE-2026-30823 ownership bypass / auth workflow flaws"),
    "anythingllm":      (8,  "CVE-2024-10513 path traversal / CVE-2026-32628 SQLi"),
    "ollama":           (8,  "CVE-2024-7773 ZipSlip RCE / CVE-2024-28224 DNS rebinding"),
    "langchain":        (7,  "CVE-2025-2828 SSRF via tool / loader integrations"),
    "mcp sse":          (7,  "CVE-2025-6515 predictable session IDs in MCP SSE servers"),
    "mcp":              (7,  "MCP server auth, session, and tool-permission exposure"),
    "iis":              (5,  "CVE-2017-7269 ScStoragePathFromUrl buffer overflow"),
    "microsoft iis":    (5,  "CVE-2017-7269 ScStoragePathFromUrl buffer overflow"),

    # Medium (4-6.9)
    "nginx":            (5,  "CVE-2021-23017 DNS resolver overflow (CVSS 7.7)"),
    "apache httpd":     (5,  "CVE-2021-41773 Path traversal / CVE-2021-42013 RCE"),
    "apache":           (5,  "CVE-2021-41773 Path traversal (CVSS 7.5)"),
    "php":              (5,  "Multiple CVEs by version — check version"),
    "node.js":          (5,  "Multiple prototype pollution CVEs"),
    "jquery":           (4,  "CVE-2020-11022 XSS / CVE-2019-11358 Prototype pollution"),
    "angularjs":        (4,  "CVE-2019-14863 XSS via sanitization bypass"),
    "bootstrap":        (3,  "CVE-2019-8331 XSS (older versions)"),
    "react":            (3,  "Low risk — check for dangerous innerHTML usage"),
    "vue.js":           (3,  "Low risk — check for v-html misuse"),
    "wordpress plugin": (6,  "Check plugin versions for known CVEs"),
    "woocommerce":      (6,  "CVE-2021-32790 SQLi (CVSS 6.5)"),
    "magento":          (7,  "CVE-2022-24086 Pre-auth RCE (CVSS 9.8)"),
    "prestashop":       (8,  "CVE-2023-30839 SQLi (CVSS 8.8)"),
    "opencart":         (6,  "CVE-2022-21693 RCE via file manager"),
    "typo3":            (6,  "CVE-2023-24814 XSS (CVSS 6.1)"),
    "joomla":           (6,  "CVE-2023-23752 Auth bypass (CVSS 5.3)"),
    "gogs":             (7,  "CVE-2018-18925 Auth bypass RCE"),
    "gitea":            (6,  "CVE-2022-1058 Open redirect + multiple CVEs"),
    "hashicorp vault":  (7,  "CVE-2021-3024 Privilege escalation"),
    "consul":           (7,  "CVE-2021-37219 RCE via Raft RPC"),
    "kubernetes":       (7,  "CVE-2018-1002105 API server priv esc (CVSS 9.8)"),
    "docker":           (7,  "CVE-2019-5736 runc container escape (CVSS 8.6)"),
    "ansible":          (6,  "CVE-2021-3583 Template injection"),
    "terraform":        (5,  "CVE-2021-28093 Code injection"),
}

# Severity thresholds
CRITICAL_SCORE = 9
HIGH_SCORE = 7
MEDIUM_SCORE = 4

# Structured, tech-aware follow-ups inspired by curated recon/playbook repos.
TECH_ATTACK_MAP = {
    "graphql": [
        "GraphQL introspection / hidden schema review",
        "Batch / alias abuse for rate-limit bypass",
        "GraphQL mutation IDOR on object identifiers",
    ],
    "nextjs": [
        "Next.js middleware / rewrite auth-bypass review",
        "Server actions and SSRF-capable server-side fetch checks",
    ],
    "drupal": [
        "Drupalgeddon / Drupal-specific nuclei and PoC verification",
        "CHANGELOG.txt, user registration, and config exposure review",
    ],
    "wordpress": [
        "WP plugin/theme CVE sweep and wp-json exposure review",
        "XML-RPC, wp-login, and admin surface checks",
    ],
    "joomla": [
        "Joomla auth-bypass and extension CVE checks",
    ],
    "laravel": [
        "Debug / ignition exposure and APP_KEY review",
        "Signed URL and deserialization gadget surface review",
    ],
    "spring": [
        "Actuator exposure and Spring4Shell-era route review",
        "Header smuggling / path traversal checks on Java edge stacks",
    ],
    "tomcat": [
        "Tomcat PUT / Ghostcat / manager exposure checks",
    ],
    "apache": [
        "Path normalization and traversal checks on Apache endpoints",
        "403 bypass / header rewrite checks on protected paths",
    ],
    "nginx": [
        "Alias traversal and path normalization review",
        "Reverse-proxy auth bypass / host-header poisoning review",
    ],
    "redis": [
        "Unauthenticated exposure and SSRF-to-Redis chaining review",
    ],
    "elasticsearch": [
        "Unauthenticated index access and API enumeration review",
    ],
    "kubernetes": [
        "Kubernetes dashboard / API exposure and token handling review",
    ],
    "aws": [
        "IMDS SSRF probes and bucket / object exposure review",
    ],
    "oauth": [
        "redirect_uri abuse, state handling, and token leakage review",
    ],
    "jwt": [
        "alg:none, weak secret, and claim forgery review",
    ],
    "dify": [
        "Dify custom-tool and document-import SSRF review",
        "Workspace / chatbot ownership and role-boundary checks",
        "Prompt / orchestrate mutation and API-key exposure review",
    ],
    "langflow": [
        "Langflow unauth API / monitor endpoint review",
        "CORS, API-key, and ownership verification checks",
        "PythonCodeTool / component execution exposure review",
    ],
    "flowise": [
        "Flowise prediction endpoint and chatflow auth review",
        "Ownership / SSO configuration and CORS boundary checks",
        "Credential node, webhook, and file-handling review",
    ],
    "anythingllm": [
        "AnythingLLM document-manager path traversal review",
        "Plugin / community-hub install and SQL-agent abuse checks",
        "CORS and workspace role-boundary review",
    ],
    "librechat": [
        "LibreChat plugin / provider token leakage review",
        "Conversation-share, OAuth callback, and role-boundary checks",
    ],
    "n8n": [
        "n8n webhook auth bypass and credential-store exposure review",
        "Workflow SSRF / internal-request checks on HTTP-capable nodes",
    ],
    "ollama": [
        "Ollama local-bind / DNS-rebinding exposure review",
        "Model upload / archive handling and file-write checks",
    ],
    "vllm": [
        "Open inference API exposure and model-loading review",
        "Authless generation endpoints and prompt/log leakage review",
    ],
    "langchain": [
        "LangChain tool / loader SSRF and callback exposure review",
        "Unsafe agent tool execution and secret handling checks",
    ],
    "mcp sse": [
        "MCP SSE auth, origin restriction, and session-ID review",
        "Tool permission boundaries and localhost-only exposure checks",
    ],
    "mcp": [
        "MCP auth, origin restriction, and tool-permission review",
        "Local-only exposure and session management checks",
    ],
}

STATUS_ATTACK_MAP = {
    "401": [
        "Auth bypass and alternate-method probing on protected endpoints",
        "Default-credential and unauthenticated API exposure review",
    ],
    "403": [
        "403 bypass via rewrite headers and path mutation",
        "Host-header / reverse-proxy enforcement review",
    ],
}

AI_TECH_FOCUS = {
    "anythingllm", "dify", "flowise", "langchain", "langflow",
    "librechat", "mcp", "mcp sse", "n8n", "ollama", "vllm",
}

LEGACY_PHP_CHECKS = [
    "Legacy PHP review for upload, deserialization, and old library RCE chains",
    "PHPinfo, debug, and composer artifact exposure review",
]


def dedupe_keep_order(items):
    seen = set()
    ordered = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def version_tuple(version: str) -> tuple[int, ...]:
    parts = []
    for chunk in version.split("."):
        if not chunk.isdigit():
            break
        parts.append(int(chunk))
    return tuple(parts)


def is_vulnerable_drupal_version(version: str) -> bool:
    parts = version_tuple(version)
    if not parts:
        return False
    if parts[0] == 7:
        return parts < (7, 58)
    if parts[0] == 8:
        return (
            parts < (8, 3, 9)
            or ((8, 4, 0) <= parts < (8, 4, 6))
            or ((8, 5, 0) <= parts < (8, 5, 1))
        )
    return False


def normalize_host(raw_host: str) -> str:
    host = (raw_host or "").strip().lower()
    if "@" in host:
        host = host.split("@", 1)[1]
    if ":" in host:
        host = host.split(":", 1)[0]
    return host


def host_from_url(url: str) -> str:
    try:
        return normalize_host(urlparse(url.strip()).netloc)
    except Exception:
        return ""


def infer_hints_from_text(text: str) -> list[str]:
    line = (text or "").strip()
    if not line:
        return []
    line_lower = line.lower()
    hints = []

    if any(marker in line_lower for marker in (
        "drupal.js", "/misc/ajax.js", "/misc/progress.js",
        "/sites/all/", "/modules/system/", "/user/login",
    )):
        hints.append("drupal")
    if any(marker in line_lower for marker in ("changelog.txt", "/user/register", "/user/password", "/user/login")):
        hints.append("evidence:drupal-surface")
    if "changelog.txt" in line_lower:
        hints.append("evidence:drupal-changelog")

    drupal_version = None
    for pattern in (
        r"(?:misc/)?(?:ajax|progress)\.js\?v=(\d+\.\d+(?:\.\d+)?)",
        r"x-generator:\s*drupal\s+(\d+\.\d+(?:\.\d+)?)",
        r"drupal[^0-9]{0,12}(\d+\.\d+(?:\.\d+)?)",
    ):
        match = re.search(pattern, line_lower)
        if match:
            drupal_version = match.group(1)
            break
    if drupal_version:
        hints.extend(["drupal", f"drupal {drupal_version}"])

    php_match = re.search(r"php[/ ](\d+\.\d+(?:\.\d+)?)", line_lower)
    if php_match:
        hints.extend(["php", f"php {php_match.group(1)}"])

    if any(marker in line_lower for marker in ("wordpress", "/wp-json", "/wp-admin", "xmlrpc.php", "wp-content/")):
        hints.append("wordpress")
    if any(marker in line_lower for marker in ("/wp-json", "/wp-admin", "xmlrpc.php", "admin-ajax.php")):
        hints.append("evidence:wordpress-surface")

    if any(marker in line_lower for marker in ("laravel", "laravel_session")):
        hints.append("laravel")
    if any(marker in line_lower for marker in ("_ignition", "laravel_session", "whoops", "ignition.execute-solution")):
        hints.append("evidence:laravel-debug")

    if any(marker in line_lower for marker in ("bigip", "big-ip", "tmui", "mgmt/tm")):
        hints.append("f5")
    if any(marker in line_lower for marker in ("/tmui", "/mgmt/tm/", "mgmt/tm/util/bash")):
        hints.append("evidence:f5-mgmt")

    if any(marker in line_lower for marker in ("jmx-console", "admin-console", "invoker/jmxinvokerservlet", "invoker/ejbinvokerservlet")):
        hints.extend(["jboss", "wildfly", "evidence:jboss-surface"])

    if any(marker in line_lower for marker in ("tomcat", "/manager/html", "/host-manager/html")):
        hints.append("tomcat")
    if any(marker in line_lower for marker in ("/manager/html", "/host-manager/html")):
        hints.append("evidence:tomcat-manager")

    if any(marker in line_lower for marker in ("exchange", "/owa", "/ecp")):
        hints.append("exchange")
    if any(marker in line_lower for marker in ("/owa", "/ecp")):
        hints.append("evidence:exchange-surface")

    return dedupe_keep_order(hints)


def load_port_hints(recon_dir: Path) -> dict[str, list[str]]:
    host_hints: dict[str, list[str]] = {}
    candidates = [
        recon_dir / "ports" / "nmap_results.txt",
        recon_dir / "ports" / "nmap_critical_http.txt",
        recon_dir / "ports" / "nmap_critical_https.txt",
    ]

    for candidate in candidates:
        if not candidate.is_file():
            continue
        current_host = ""
        try:
            for raw_line in candidate.read_text(errors="ignore").splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                match = re.search(r"Nmap scan report for ([^(]+)", line)
                if match:
                    current_host = normalize_host(match.group(1).strip())
                    continue
                lower = line.lower()
                hints = []
                if "8009/tcp" in lower or "ajp13" in lower:
                    hints.extend(["tomcat", "evidence:tomcat-ajp"])
                if "9990/tcp" in lower or "9993/tcp" in lower:
                    hints.extend(["jboss", "wildfly", "evidence:jboss-surface"])
                if hints and current_host:
                    current = host_hints.get(current_host, [])
                    host_hints[current_host] = dedupe_keep_order(current + hints)
        except OSError:
            continue

    return host_hints


def load_recon_hints(input_path: str) -> tuple[dict[str, list[str]], list[str]]:
    path = Path(input_path)
    if not path.is_file() or path.name != "httpx_full.txt" or path.parent.name != "live":
        return {}, []

    recon_dir = path.parent.parent
    host_hints: dict[str, list[str]] = {}
    global_hints: list[str] = []

    def remember(host: str, hints: list[str]) -> None:
        if not hints:
            return
        if host:
            current = host_hints.get(host, [])
            host_hints[host] = dedupe_keep_order(current + hints)
        global_hints.extend(hints)

    candidates = [
        recon_dir / "priority" / "version_fingerprints.txt",
        recon_dir / "urls" / "with_params.txt",
        recon_dir / "urls" / "js_files.txt",
    ]

    priority_dir = recon_dir / "priority"
    if priority_dir.is_dir():
        candidates.extend(sorted(priority_dir.glob("whatweb_*.txt")))

    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            for raw_line in candidate.read_text(errors="ignore").splitlines():
                hints = infer_hints_from_text(raw_line)
                if not hints:
                    continue
                remember(host_from_url(raw_line), hints)
        except OSError:
            continue

    for host, hints in load_port_hints(recon_dir).items():
        remember(host, hints)

    return host_hints, dedupe_keep_order(global_hints)


def _replace_cve_message(cves: list[str], prefixes: tuple[str, ...], replacement: str) -> list[str]:
    filtered = []
    lowered_prefixes = tuple(prefix.lower() for prefix in prefixes)
    for cve in cves:
        if cve.lower().startswith(lowered_prefixes):
            continue
        filtered.append(cve)
    filtered.append(replacement)
    return dedupe_keep_order(filtered)


def score_host(host_line: str, extra_hints: list[str] | None = None) -> dict:
    """
    Parse a single httpx output line and score the host.
    Expected format: URL [STATUS] [TITLE] [TECH:version,TECH2,...]
    """
    host_line = host_line.strip()
    if not host_line:
        return None

    # Strip ANSI escape codes — httpx -tech-detect writes colour codes like
    # \033[32mTomcat\033[0m which break substring keyword matching
    host_line = re.sub(r'\x1b\[[0-9;]*[mK]', '', host_line)

    # Extract URL (first token)
    tokens = host_line.split()
    if not tokens:
        return None

    url = tokens[0]
    extra_hints = extra_hints or []
    enriched_line = host_line if not extra_hints else f"{host_line} {' '.join(extra_hints)}"
    line_lower = enriched_line.lower()
    status_match = re.search(r"\[(\d{3})\]", host_line)

    max_score = 0
    matched_cves = []
    matched_techs = []
    recommended_checks = []
    version_hints = []
    evidence_hints = [hint for hint in extra_hints if hint.startswith("evidence:")]

    # Scan the entire line for tech keywords
    for tech_key, (score, cve_info) in TECH_CVE_MAP.items():
        if tech_key in line_lower:
            if score > max_score:
                max_score = score
            matched_cves.append(f"{tech_key.title()}: {cve_info}")

    for tech_key, checks in TECH_ATTACK_MAP.items():
        if tech_key in line_lower:
            matched_techs.append(tech_key)
            recommended_checks.extend(checks)

    if "graphql" in url.lower():
        matched_techs.append("graphql")
        recommended_checks.extend(TECH_ATTACK_MAP.get("graphql", []))

    if status_match:
        recommended_checks.extend(STATUS_ATTACK_MAP.get(status_match.group(1), []))

    drupal_versions = []
    for pattern in (
        r"drupal[^0-9]{0,12}(\d+\.\d+(?:\.\d+)?)",
        r"(?:misc/)?(?:ajax|progress)\.js\?v=(\d+\.\d+(?:\.\d+)?)",
    ):
        drupal_versions.extend(re.findall(pattern, line_lower))
    drupal_versions = dedupe_keep_order(drupal_versions)
    if drupal_versions:
        drupal_version = max(drupal_versions, key=version_tuple)
        version_hints.append(f"drupal {drupal_version}")
        matched_techs.append("drupal")
        recommended_checks.extend(TECH_ATTACK_MAP.get("drupal", []))
        drupal_parts = version_tuple(drupal_version)
        if drupal_parts and drupal_parts[0] == 7 and drupal_parts < (7, 58):
            max_score = max(max_score, 10)
            matched_cves.append(
                f"Drupal {drupal_version}: legacy Drupal 7 build (pre-7.58) — prioritize Drupalgeddon-era RCE validation"
            )
        elif drupal_parts and drupal_parts[0] == 7:
            max_score = max(max_score, 8)
            matched_cves.append(
                f"Drupal {drupal_version}: legacy Drupal 7 branch — review Drupal-specific CVEs and exposed admin paths"
            )

    php_match = re.search(r"php[^0-9]{0,8}(\d+\.\d+(?:\.\d+)?)", line_lower)
    if php_match:
        php_version = php_match.group(1)
        version_hints.append(f"php {php_version}")
        matched_techs.append("php")
        php_parts = version_tuple(php_version)
        if php_parts and php_parts < (7, 0):
            max_score = max(max_score, 7)
            matched_cves.append(
                f"PHP {php_version}: end-of-life PHP branch — prioritize legacy PHP exploit-surface review"
            )
            recommended_checks.extend(LEGACY_PHP_CHECKS)

    if "drupal" in line_lower:
        drupal_versions = [
            hint.split(" ", 1)[1]
            for hint in version_hints
            if hint.lower().startswith("drupal ")
        ]
        if any(is_vulnerable_drupal_version(version) for version in drupal_versions):
            max_score = max(max_score, 10)
        else:
            max_score = min(max_score, 7)
            matched_cves = _replace_cve_message(
                matched_cves,
                ("Drupal",),
                "Drupal detected — exploitability not yet validated; confirm vulnerable version or exposed Drupal entrypoints before RCE checks",
            )

    if any(marker in line_lower for marker in ("f5", "bigip", "big-ip")):
        if "evidence:f5-mgmt" in evidence_hints:
            max_score = max(max_score, 9)
        else:
            max_score = min(max_score, 6)
            matched_cves = _replace_cve_message(
                matched_cves,
                ("F5",),
                "F5 / BIG-IP detected — CVE-2022-1388 needs exposed management endpoints like /tmui or /mgmt/tm",
            )

    if "laravel" in line_lower:
        if "evidence:laravel-debug" in evidence_hints:
            max_score = max(max_score, 9)
        else:
            max_score = min(max_score, 6)
            matched_cves = _replace_cve_message(
                matched_cves,
                ("Laravel",),
                "Laravel detected — CVE-2021-3129 requires debug / Ignition exposure, not just framework presence",
            )

    if "wordpress" in line_lower:
        if "evidence:wordpress-surface" in evidence_hints:
            max_score = max(max_score, 6)
        else:
            max_score = min(max_score, 5)
            matched_cves = _replace_cve_message(
                matched_cves,
                ("Wordpress",),
                "WordPress detected — SQLi/CVE validation needs version or vulnerable plugin evidence, not only a banner match",
            )

    if "tomcat" in line_lower:
        if any(marker in evidence_hints for marker in ("evidence:tomcat-ajp", "evidence:tomcat-manager")):
            max_score = max(max_score, 8)
        else:
            max_score = min(max_score, 6)
            matched_cves = _replace_cve_message(
                matched_cves,
                ("Tomcat", "Apache Tomcat"),
                "Tomcat detected — Ghostcat / PUT-style exploitation needs AJP or manager-style preconditions, not only product presence",
            )

    if any(marker in line_lower for marker in ("jboss", "wildfly")):
        if "evidence:jboss-surface" in evidence_hints:
            max_score = max(max_score, 8)
        else:
            max_score = min(max_score, 6)
            matched_cves = _replace_cve_message(
                matched_cves,
                ("Jboss", "Wildfly"),
                "JBoss / WildFly detected — deserialization RCE needs exposed admin or invoker surfaces, not only tech fingerprinting",
            )

    if "exchange" in line_lower:
        if "evidence:exchange-surface" in evidence_hints:
            max_score = max(max_score, 8)
        else:
            max_score = min(max_score, 6)
            matched_cves = _replace_cve_message(
                matched_cves,
                ("Exchange",),
                "Exchange detected — ProxyLogon-style checks should wait for OWA / ECP exposure evidence",
            )

    if "spring" in line_lower:
        max_score = min(max_score, 6)
        matched_cves = _replace_cve_message(
            matched_cves,
            ("Spring", "Spring Framework"),
            "Spring detected — Spring4Shell requires exact version and deployment validation, not only framework presence",
        )

    if any(marker in line_lower for marker in ("fortigate", "fortios")):
        max_score = min(max_score, 6)
        matched_cves = _replace_cve_message(
            matched_cves,
            ("Fortigate", "Fortios"),
            "FortiGate detected — version-specific validation is required before treating CVE-2023-27997 as exploitable",
        )

    if "openssl" in line_lower:
        max_score = min(max_score, 5)
        matched_cves = _replace_cve_message(
            matched_cves,
            ("Openssl",),
            "OpenSSL detected — Heartbleed / CVE-2022-0778 require exact version evidence before spending validation time",
        )

    matched_techs = dedupe_keep_order(matched_techs)[:6]
    recommended_checks = dedupe_keep_order(recommended_checks)[:6]
    matched_cves = dedupe_keep_order(matched_cves)[:3]
    version_hints = dedupe_keep_order(version_hints)[:4]
    evidence_hints = dedupe_keep_order(evidence_hints)[:6]

    confidence = "banner"
    if version_hints:
        confidence = "versioned"
    if evidence_hints:
        confidence = "evidence-backed"

    # Determine priority label
    if max_score >= CRITICAL_SCORE:
        priority = "CRITICAL"
    elif max_score >= HIGH_SCORE:
        priority = "HIGH"
    elif max_score >= MEDIUM_SCORE:
        priority = "MEDIUM"
    elif max_score > 0:
        priority = "LOW"
    else:
        priority = "INFO"

    return {
        "url": url,
        "score": max_score,
        "priority": priority,
        "cves": matched_cves,
        "tech_matches": matched_techs,
        "recommended_checks": recommended_checks,
        "version_hints": version_hints,
        "evidence_hints": evidence_hints,
        "confidence": confidence,
        "raw": host_line,
    }


def build_attack_surface(scored: list[dict]) -> dict:
    tech_counter = Counter()
    check_counter = Counter()
    version_counter = Counter()
    ai_focus_hosts = []

    for host in scored:
        for tech in host.get("tech_matches", []):
            tech_counter[tech] += 1
        for check in host.get("recommended_checks", []):
            check_counter[check] += 1
        for version_hint in host.get("version_hints", []):
            version_counter[version_hint] += 1
        if any(tech in AI_TECH_FOCUS for tech in host.get("tech_matches", [])):
            ai_focus_hosts.append({
                "url": host["url"],
                "priority": host["priority"],
                "tech_matches": host.get("tech_matches", []),
                "recommended_checks": host.get("recommended_checks", []),
            })

    top_hosts = [
        {
            "url": host["url"],
            "priority": host["priority"],
            "score": host["score"],
            "tech_matches": host.get("tech_matches", []),
            "version_hints": host.get("version_hints", []),
            "evidence_hints": host.get("evidence_hints", []),
            "confidence": host.get("confidence", "banner"),
            "recommended_checks": host.get("recommended_checks", []),
            "cves": host.get("cves", []),
        }
        for host in scored
        if host["priority"] in {"CRITICAL", "HIGH", "MEDIUM"}
    ][:12]

    validation_targets = [
        {
            "url": host["url"],
            "priority": host["priority"],
            "score": host["score"],
            "confidence": host.get("confidence", "banner"),
            "version_hints": host.get("version_hints", []),
            "evidence_hints": host.get("evidence_hints", []),
            "cves": host.get("cves", []),
        }
        for host in scored
        if host.get("confidence") in {"versioned", "evidence-backed"}
        and host["priority"] in {"CRITICAL", "HIGH", "MEDIUM"}
    ][:15]

    return {
        "total_hosts": len(scored),
        "tech_clusters": [
            {"tech": tech, "count": count}
            for tech, count in tech_counter.most_common(15)
        ],
        "priority_recommendations": [
            {"check": check, "count": count}
            for check, count in check_counter.most_common(12)
        ],
        "detected_versions": [
            {"version": version, "count": count}
            for version, count in version_counter.most_common(12)
        ],
        "top_hosts": top_hosts,
        "validation_targets": validation_targets,
        "ai_agent_hosts": ai_focus_hosts[:10],
    }


def render_attack_surface_markdown(attack_surface: dict) -> str:
    top_tech_clusters = ", ".join(
        f"{item['tech']} ({item['count']})"
        for item in attack_surface.get("tech_clusters", [])[:8]
    ) or "none"
    top_versions = ", ".join(
        f"{item['version']} ({item['count']})"
        for item in attack_surface.get("detected_versions", [])[:6]
    ) or "none"

    lines = [
        "# Attack Surface Report",
        "",
        "## Summary",
        f"- Total scored hosts: {attack_surface.get('total_hosts', 0)}",
        f"- Top tech clusters: {top_tech_clusters}",
        f"- Version signals: {top_versions}",
        "",
        "## Priority Follow-Ups",
    ]

    if attack_surface.get("priority_recommendations"):
        for item in attack_surface["priority_recommendations"]:
            lines.append(f"- {item['check']} [{item['count']} host(s)]")
    else:
        lines.append("- No tech-specific follow-ups generated")

    lines.extend([
        "",
        "## Top Hosts",
    ])

    if attack_surface.get("validation_targets"):
        lines.extend([
            "",
            "## Best Validation Targets",
        ])
        for host in attack_surface["validation_targets"]:
            lines.append(f"- {host['url']} [{host['priority']}, {host.get('confidence', 'banner')}]")
            if host.get("version_hints"):
                lines.append(f"  - Version hints: {', '.join(host['version_hints'])}")
            if host.get("evidence_hints"):
                lines.append(f"  - Evidence: {', '.join(host['evidence_hints'])}")

    if attack_surface.get("ai_agent_hosts"):
        lines.extend([
            "",
            "## AI / Agent Surface",
        ])
        for host in attack_surface["ai_agent_hosts"]:
            lines.append(f"- {host['url']} [{host['priority']}] :: {', '.join(host.get('tech_matches', []))}")

    for host in attack_surface.get("top_hosts", []):
        lines.append(f"### {host['priority']} — {host['url']}")
        lines.append(f"- Score: {host['score']}")
        if host.get("tech_matches"):
            lines.append(f"- Tech matches: {', '.join(host['tech_matches'])}")
        if host.get("version_hints"):
            lines.append(f"- Version hints: {', '.join(host['version_hints'])}")
        if host.get("cves"):
            lines.append(f"- CVE signals: {'; '.join(host['cves'])}")
        if host.get("recommended_checks"):
            lines.append("- Recommended checks:")
            for check in host["recommended_checks"]:
                lines.append(f"  - {check}")
        lines.append("")

    return "\n".join(lines).strip() + "\n"


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <httpx_output_file|-stdin> <output_file>", file=sys.stderr)
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    # Read input
    if input_path == "-":
        lines = sys.stdin.read().splitlines()
        host_hints = {}
        global_hints = []
    else:
        try:
            lines = Path(input_path).read_text().splitlines()
        except FileNotFoundError:
            print(f"[-] File not found: {input_path}", file=sys.stderr)
            sys.exit(1)
        host_hints, global_hints = load_recon_hints(input_path)

    # Score all hosts
    scored = []
    unique_hosts = {
        host_from_url(line.split()[0])
        for line in lines
        if line.split() and host_from_url(line.split()[0])
    }
    use_global_hints = len(unique_hosts) <= 10

    for line in lines:
        host = host_from_url(line.split()[0]) if line.split() else ""
        hints = list(host_hints.get(host, []))
        if use_global_hints:
            hints.extend(global_hints)
        hints = dedupe_keep_order(hints)
        result = score_host(line, extra_hints=hints)
        if result:
            scored.append(result)

    # Sort by score descending
    scored.sort(key=lambda x: x["score"], reverse=True)

    # Write prioritized output
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    critical, high, medium, low, info = [], [], [], [], []
    for h in scored:
        bucket = {"CRITICAL": critical, "HIGH": high,
                  "MEDIUM": medium, "LOW": low, "INFO": info}
        bucket[h["priority"]].append(h)

    # Summary to stdout
    print(f"\n[*] Tech CVE Prioritization Results")
    print(f"    Total hosts scored: {len(scored)}")
    print(f"    CRITICAL (CVSSv3 ≥9): {len(critical)}")
    print(f"    HIGH     (CVSSv3 7-8): {len(high)}")
    print(f"    MEDIUM   (CVSSv3 4-6): {len(medium)}")
    print(f"    LOW      (CVSSv3 1-3): {len(low)}")
    print(f"    INFO     (no match):   {len(info)}\n")

    if critical:
        print(f"[!] CRITICAL TARGETS — Hunt These First:")
        for h in critical:
            print(f"    {h['url']}")
            for cve in h["cves"]:
                print(f"      -> {cve}")

    if high:
        print(f"\n[!] HIGH PRIORITY TARGETS:")
        for h in high:
            print(f"    {h['url']}")
            for cve in h["cves"]:
                print(f"      -> {cve}")

    validation_targets = attack_surface = build_attack_surface(scored)
    if validation_targets.get("validation_targets"):
        print(f"\n[*] BEST VALIDATION TARGETS — Spend Time Here:")
        for h in validation_targets["validation_targets"][:12]:
            print(f"    {h['url']} [{h.get('confidence', 'banner')}]")
            if h.get("version_hints"):
                print(f"      -> version: {', '.join(h['version_hints'][:2])}")
            if h.get("evidence_hints"):
                printable = ", ".join(h["evidence_hints"][:3]).replace("evidence:", "")
                print(f"      -> evidence: {printable}")

    # Write full prioritized list with URLs only (for tool piping)
    with output.open("w") as f:
        for bucket_name, bucket in [("CRITICAL", critical), ("HIGH", high),
                                     ("MEDIUM", medium), ("LOW", low), ("INFO", info)]:
            for h in bucket:
                f.write(h["url"] + "\n")

    # Write detailed JSON report
    json_output = output.with_suffix(".json")
    with json_output.open("w") as f:
        json.dump({
            "total": len(scored),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
        }, f, indent=2)

    # Write per-severity URL lists for downstream shell tooling.
    severity_lists = {
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
    }
    for severity, bucket in severity_lists.items():
        list_path = output.with_name(f"{severity}_hosts.txt")
        urls = [h["url"] for h in bucket]
        list_path.write_text("".join(f"{url}\n" for url in urls))

    # Write attack-surface guidance for downstream scanner / Brain consumers.
    attack_surface = validation_targets
    attack_json = output.with_name("attack_surface.json")
    attack_md = output.with_name("attack_surface.md")
    attack_json.write_text(json.dumps(attack_surface, indent=2))
    attack_md.write_text(render_attack_surface_markdown(attack_surface))

    if attack_surface.get("priority_recommendations"):
        print("\n[*] Priority follow-ups:")
        for item in attack_surface["priority_recommendations"][:6]:
            print(f"    - {item['check']} [{item['count']}]")

    print(f"\n[+] Prioritized URLs: {output}")
    print(f"[+] Detailed JSON:    {json_output}")
    print(f"[+] Attack surface:   {attack_md}")


if __name__ == "__main__":
    main()
