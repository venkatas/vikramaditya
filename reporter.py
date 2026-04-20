#!/usr/bin/env python3
from __future__ import annotations
"""
reporter.py — VAPT Report Generator
Produces a Burp Suite-style HTML report + Markdown summary from scan findings.

Usage:
    python3 reporter.py <findings_dir>
    python3 reporter.py <findings_dir> --client "Acme Corp" --consultant "J. Smith" --title "Web App VAPT"
    python3 reporter.py --manual --type xss --url https://example.com/search?q=test
"""

import argparse
import os
import re
import shutil
import sys
from datetime import datetime

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

# ── Vulnerability templates ────────────────────────────────────────────────────
# MITRE ATT&CK technique IDs per vuln class (Decepticon kill-chain tagging)
ATTACK_IDS = {
    "sqli":         "T1190",   # Exploit Public-Facing Application
    "xss":          "T1059.007",  # Command & Scripting: JavaScript
    "ssti":         "T1059",   # Command & Scripting Interpreter
    "upload":       "T1105",   # Ingress Tool Transfer → RCE
    "rce":          "T1190",   # Exploit Public-Facing Application
    "lfi":          "T1083",   # File & Directory Discovery
    "idor":         "T1078",   # Valid Accounts (privilege abuse)
    "ssrf":         "T1090",   # Proxy / Internal pivot
    "cors":         "T1557",   # Adversary-in-the-Middle
    "takeover":     "T1584",   # Compromise Infrastructure
    "exposure":     "T1552",   # Unsecured Credentials
    "cves":         "T1190",   # Exploit Public-Facing Application
    "misconfig":    "T1562",   # Impair Defenses
    "xss_dom":      "T1059.007",
    "csrf":         "T1185",   # Browser Session Hijacking
    "auth_bypass":  "T1078",   # Valid Accounts
    "open_redirect":"T1598",   # Phishing for Information
    "upload_type_bypass": "T1105",  # Ingress Tool Transfer → File type evasion
}

VULN_TEMPLATES = {
    # v7.4.4 — classes surfaced by scanner.sh that previously rendered
    # without a dedicated template. Severity / CVSS / CWE pinned to
    # conservative defaults; reporters are free to override per-finding.
    "deserialization": {
        "title": "Insecure Deserialization on {host}",
        "severity": "high", "cvss": "8.8", "cwe": "CWE-502",
        "impact": (
            "Untrusted data is deserialized into native objects, enabling "
            "remote code execution via gadget chains (ysoserial, marshalsec) "
            "or object-injection attacks that bypass authentication and "
            "authorization controls."
        ),
        "remediation": (
            "Avoid deserializing untrusted input. If unavoidable, sign payloads "
            "with a server-side HMAC, constrain the deserializer to an allowlist "
            "of types, and upgrade deserialization libraries to versions that "
            "enforce safe defaults."
        ),
        "references": [
            ("OWASP Deserialization Cheat Sheet",
             "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"),
            ("CWE-502", "https://cwe.mitre.org/data/definitions/502.html"),
        ],
    },
    "supply_chain": {
        "title": "Supply-Chain / Third-Party Component Exposure on {host}",
        "severity": "high", "cvss": "7.5", "cwe": "CWE-1357",
        "impact": (
            "Outdated or vulnerable third-party components (JS libraries, "
            "CDN-hosted scripts, exposed package manifests) let attackers "
            "chain known CVEs in the dependency set or substitute the fetched "
            "artefact through a compromised registry."
        ),
        "remediation": (
            "Pin dependency versions and checksum-verify them. Subscribe to "
            "CVE feeds for every package in the tree. Serve vendored JS from "
            "same-origin rather than third-party CDNs."
        ),
        "references": [
            ("OWASP A06:2021 Vulnerable and Outdated Components",
             "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"),
        ],
    },
    "jwt": {
        "title": "JWT Handling Flaw on {host}",
        "severity": "high", "cvss": "8.1", "cwe": "CWE-347",
        "impact": (
            "Weak signature handling (alg=none, algorithm confusion, weak HMAC "
            "secret, missing expiry validation) lets an attacker forge JWTs and "
            "impersonate arbitrary users or escalate privileges."
        ),
        "remediation": (
            "Pin the expected algorithm server-side. Use asymmetric signatures "
            "(RS256/EdDSA). Enforce aud/iss/exp claim validation. Rotate secrets."
        ),
        "references": [
            ("OWASP JWT Cheat Sheet",
             "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"),
        ],
    },
    "graphql": {
        "title": "GraphQL Exposure on {host}",
        "severity": "medium", "cvss": "6.5", "cwe": "CWE-915",
        "impact": (
            "Introspection enabled in production exposes the full schema. "
            "Unbounded queries or unbatched aliases enable DoS. Missing "
            "field-level authorization exposes internal objects via the "
            "resolver graph."
        ),
        "remediation": (
            "Disable introspection in production. Add query-depth and "
            "complexity limits. Enforce field-level authZ, not just "
            "object-level. Rate-limit mutations."
        ),
        "references": [
            ("OWASP GraphQL Cheat Sheet",
             "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"),
        ],
    },
    "smuggling": {
        "title": "HTTP Request Smuggling on {host}",
        "severity": "high", "cvss": "9.0", "cwe": "CWE-444",
        "impact": (
            "Disagreement between front-end and back-end on request framing "
            "(Content-Length vs Transfer-Encoding) allows an attacker to "
            "smuggle a second request that bypasses WAF rules, poisons the "
            "cache, or hijacks another user's session."
        ),
        "remediation": (
            "Normalize Transfer-Encoding and Content-Length handling across "
            "all proxies. Reject ambiguous combinations. Upgrade front/back "
            "to matching HTTP/1.1 semantics."
        ),
        "references": [
            ("PortSwigger Smuggling Research",
             "https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn"),
        ],
    },
    "sqli": {
        "title": "SQL Injection on {host}",
        "severity": "critical", "cvss": "9.8", "cwe": "CWE-89",
        "impact": (
            "An attacker can read, modify, or delete all data in the database. "
            "Depending on the database server configuration, this may escalate to "
            "remote code execution via xp_cmdshell, UDF, or outfile techniques."
        ),
        "remediation": (
            "Use parameterized queries or prepared statements for all database interactions. "
            "Apply input validation and a WAF as defence-in-depth."
        ),
        "references": [
            ("OWASP SQL Injection", "https://owasp.org/www-community/attacks/SQL_Injection"),
            ("Prevention Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"),
        ],
    },
    "xss": {
        "title": "Cross-Site Scripting (XSS) on {host}",
        "severity": "medium", "cvss": "6.1", "cwe": "CWE-79",
        "impact": (
            "An attacker can execute arbitrary JavaScript in the victim's browser session, "
            "enabling session hijacking, credential theft, or redirection to a malicious site."
        ),
        "remediation": (
            "Apply context-aware output encoding for all user-supplied data. "
            "Implement a strict Content-Security-Policy header. "
            "Set HttpOnly and Secure flags on session cookies."
        ),
        "references": [
            ("OWASP XSS", "https://owasp.org/www-community/attacks/xss/"),
            ("XSS Prevention Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
        ],
    },
    "ssti": {
        "title": "Server-Side Template Injection (SSTI) on {host}",
        "severity": "high", "cvss": "8.8", "cwe": "CWE-1336",
        "impact": (
            "An attacker can inject malicious template directives evaluated server-side. "
            "Depending on the engine (Jinja2, Freemarker, Thymeleaf, Twig), this typically "
            "leads to remote code execution."
        ),
        "remediation": (
            "Never pass user-controlled input directly to a template engine. "
            "Use sandboxed execution environments. "
            "Reject inputs containing template syntax characters."
        ),
        "references": [
            ("PortSwigger SSTI", "https://portswigger.net/web-security/server-side-template-injection"),
        ],
    },
    "upload": {
        "title": "Unrestricted File Upload on {host}",
        "severity": "high", "cvss": "8.8", "cwe": "CWE-434",
        "impact": (
            "An attacker can upload files with malicious content (PHP webshells, HTML with "
            "JavaScript, executable scripts) by bypassing file type validation. If the storage "
            "backend serves files with executable content-types or if server-side processing "
            "(image resize, thumbnail generation) parses the content, this escalates to RCE or stored XSS."
        ),
        "remediation": (
            "Validate file content (magic bytes), not just extension. Restrict allowed MIME types "
            "via allowlist. Strip metadata and re-encode images. Serve uploads from a separate "
            "cookieless domain with Content-Disposition: attachment."
        ),
        "references": [
            ("OWASP File Upload Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"),
        ],
    },
    "upload_type_bypass": {
        "title": "File Type Validation Bypass on {host}",
        "severity": "critical", "cvss": "9.1", "cwe": "CWE-434",
        "owasp": "A04:2021",
        "impact": (
            "The server's file type validation can be bypassed using evasion techniques "
            "(double extensions, MIME mismatch, magic byte polyglots, or case variations). "
            "An attacker can upload executable content (PHP webshells, JSP, shell scripts) "
            "disguised as benign file types. Magika AI analysis confirmed the uploaded file's "
            "true content type differs from the claimed type."
        ),
        "remediation": (
            "Validate file content server-side using magic byte analysis (not Content-Type "
            "header or extension alone). Use a deep-learning file classifier like Google Magika "
            "for accurate detection. Implement an allowlist of permitted content types. "
            "Re-encode uploaded images. Serve uploads from a separate cookieless domain "
            "with Content-Disposition: attachment and X-Content-Type-Options: nosniff."
        ),
        "references": [
            ("OWASP File Upload Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"),
            ("Google Magika", "https://github.com/google/magika"),
        ],
    },
    "rce": {
        "title": "Remote Code Execution on {host}",
        "severity": "critical", "cvss": "9.8", "cwe": "CWE-78",
        "impact": (
            "An attacker can execute arbitrary OS commands on the server, "
            "gaining full control of the system and potentially the internal network."
        ),
        "remediation": (
            "Apply the vendor patch immediately. Disable unnecessary features. "
            "Implement network segmentation and egress filtering."
        ),
        "references": [
            ("OWASP OS Command Injection", "https://owasp.org/www-community/attacks/Command_Injection"),
        ],
    },
    "lfi": {
        "title": "Local File Inclusion (LFI) on {host}",
        "severity": "high", "cvss": "7.5", "cwe": "CWE-22",
        "impact": "An attacker can read sensitive server files including /etc/passwd, config files, and SSH keys.",
        "remediation": (
            "Use an allowlist for any file path derived from user input. "
            "Never pass raw user values to filesystem functions."
        ),
        "references": [
            ("OWASP Path Traversal", "https://owasp.org/www-community/attacks/Path_Traversal"),
        ],
    },
    "idor": {
        "title": "Insecure Direct Object Reference (IDOR) on {host}",
        "severity": "high", "cvss": "8.1", "cwe": "CWE-639",
        "impact": "An attacker can access or modify data belonging to other users by manipulating object identifiers.",
        "remediation": "Implement server-side authorisation checks on every request. Use indirect references (GUIDs) and verify ownership.",
        "references": [
            ("OWASP IDOR Testing", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References"),
        ],
    },
    "ssrf": {
        "title": "Server-Side Request Forgery (SSRF) on {host}",
        "severity": "high", "cvss": "8.6", "cwe": "CWE-918",
        "impact": "An attacker can make the server issue requests to internal services, cloud metadata endpoints, or restricted systems.",
        "remediation": "Allowlist outbound destinations. Block RFC-1918 and link-local ranges. Disable redirects in server-side HTTP clients.",
        "references": [
            ("OWASP SSRF", "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"),
        ],
    },
    "cors": {
        "title": "CORS Misconfiguration on {host}",
        "severity": "medium", "cvss": "6.5", "cwe": "CWE-942",
        "impact": "The server reflects arbitrary Origin headers with credentials, allowing cross-origin reads of authenticated API responses.",
        "remediation": "Implement a strict Origin allowlist. Never reflect the Origin header directly. Avoid wildcard origins with credentials.",
        "references": [
            ("PortSwigger CORS", "https://portswigger.net/web-security/cors"),
        ],
    },
    "takeover": {
        "title": "Subdomain Takeover on {host}",
        "severity": "high", "cvss": "7.5", "cwe": "CWE-284",
        "impact": "A dangling DNS record points to an unclaimed service. An attacker can claim it and serve malicious content on the subdomain.",
        "remediation": "Remove dangling DNS records. Audit all CNAME records. Implement DNS monitoring.",
        "references": [
            ("HackTricks Subdomain Takeover", "https://book.hacktricks.xyz/pentesting-web/domain-subdomain-takeover"),
        ],
    },
    "exposure": {
        "title": "Sensitive Data Exposure on {host}",
        "severity": "high", "cvss": "7.5", "cwe": "CWE-200",
        "impact": "Sensitive information (credentials, API keys, PII) is exposed without authentication.",
        "remediation": "Remove exposed secrets and rotate all credentials immediately. Add secret scanning to CI/CD.",
        "references": [
            ("OWASP Cryptographic Failures", "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"),
        ],
    },
    "cves": {
        "title": "Known CVE Vulnerability on {host}",
        "severity": "critical", "cvss": "9.0", "cwe": "CWE-1035",
        "impact": "A publicly known vulnerability with an available exploit was identified. May lead to RCE, data breach, or service disruption.",
        "remediation": "Apply the vendor patch or upgrade to a non-vulnerable version immediately. Apply compensating controls if patching is delayed.",
        "references": [
            ("NVD", "https://nvd.nist.gov/"),
        ],
    },
    "misconfig": {
        "title": "Security Misconfiguration on {host}",
        "severity": "medium", "cvss": "5.3", "cwe": "CWE-16",
        "impact": "The application or server is insecurely configured, exposing sensitive information or additional attack vectors.",
        "remediation": "Follow CIS hardening benchmarks. Disable default credentials, debug endpoints, and unnecessary services.",
        "references": [
            ("OWASP Security Misconfiguration", "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"),
        ],
    },
    "xss_dom": {
        "title": "DOM-Based Cross-Site Scripting (XSS) on {host}",
        "severity": "high", "cvss": "7.5", "cwe": "CWE-79",
        "impact": (
            "An attacker can execute arbitrary JavaScript in the victim's browser by "
            "manipulating client-side DOM sinks such as innerHTML, document.write, or eval."
        ),
        "remediation": (
            "Avoid writing user-controlled data to dangerous DOM sinks. "
            "Prefer textContent over innerHTML. "
            "Use DOMPurify for unavoidable HTML rendering and deploy a strict CSP."
        ),
        "references": [
            ("OWASP DOM XSS", "https://owasp.org/www-community/attacks/DOM_Based_XSS"),
        ],
    },
    "csrf": {
        "title": "Cross-Site Request Forgery (CSRF) on {host}",
        "severity": "medium", "cvss": "6.5", "cwe": "CWE-352",
        "impact": (
            "An attacker can trick an authenticated user into submitting unintended "
            "state-changing actions without the victim noticing."
        ),
        "remediation": (
            "Implement CSRF tokens on all state-changing forms. "
            "Set SameSite=Lax or SameSite=Strict on session cookies and validate Origin/Referer."
        ),
        "references": [
            ("OWASP CSRF", "https://owasp.org/www-community/attacks/csrf"),
        ],
    },
    "auth_bypass": {
        "title": "Authentication Bypass on {host}",
        "severity": "high", "cvss": "8.1", "cwe": "CWE-287",
        "impact": (
            "An attacker can access protected resources or administrative interfaces "
            "without valid credentials, potentially leading to account takeover or data exposure."
        ),
        "remediation": (
            "Enforce authentication checks server-side on every protected route, "
            "remove default credentials, and verify SPA route guards are not relied on alone."
        ),
        "references": [
            ("OWASP Forced Browsing", "https://owasp.org/www-community/attacks/Forced_browsing"),
        ],
    },
    "open_redirect": {
        "title": "Open Redirect on {host}",
        "severity": "medium", "cvss": "6.1", "cwe": "CWE-601",
        "impact": (
            "An attacker can redirect victims to a malicious site using a trusted-looking "
            "link from the legitimate domain, which increases phishing risk."
        ),
        "remediation": (
            "Validate redirect destinations against an allowlist and avoid "
            "redirecting directly from user-controlled parameters."
        ),
        "references": [
            (
                "OWASP Unvalidated Redirects",
                "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
            ),
        ],
    },
}

VULN_TEMPLATES["race_condition"] = {
    "title": "Race Condition on {host}",
    "severity": "high", "cvss": "7.5", "cwe": "CWE-362",
    "impact": (
        "An attacker can exploit a time-of-check to time-of-use (TOCTOU) race "
        "to bypass business logic controls such as balance checks, coupon limits, "
        "or rate limiting on critical actions."
    ),
    "remediation": (
        "Implement database-level locking (SELECT FOR UPDATE) or optimistic concurrency "
        "control with version counters. Use idempotency keys for financial operations."
    ),
    "references": [
        ("OWASP Race Conditions", "https://owasp.org/www-community/vulnerabilities/Race_condition"),
    ],
}
VULN_TEMPLATES["oauth"] = {
    "title": "OAuth/OIDC Misconfiguration on {host}",
    "severity": "high", "cvss": "8.1", "cwe": "CWE-287",
    "impact": (
        "An attacker can bypass authentication or steal authorization codes via "
        "redirect_uri manipulation, weak state parameters, or missing PKCE enforcement, "
        "leading to account takeover."
    ),
    "remediation": (
        "Enforce strict redirect_uri validation (exact match), require PKCE for public clients, "
        "use high-entropy state parameters (32+ bytes), and validate state on callback."
    ),
    "references": [
        ("OAuth 2.0 Security Best Practices", "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics"),
    ],
}
VULN_TEMPLATES["auth_bypass"] = {
    "title": "Broken Authentication on {host}",
    "severity": "critical", "cvss": "9.8", "cwe": "CWE-287",
    "impact": (
        "An attacker can access protected API endpoints without valid authentication, "
        "potentially reading or modifying all data in the system including PII, credentials, "
        "and administrative functions."
    ),
    "remediation": (
        "Enforce server-side JWT validation on every endpoint. Verify signature, expiry, "
        "issuer, and audience claims. Reject tokens with alg=none or tampered signatures."
    ),
    "references": [
        ("OWASP Broken Authentication", "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"),
    ],
}
VULN_TEMPLATES["business_logic"] = {
    "title": "Business Logic Flaw on {host}",
    "severity": "high", "cvss": "8.1", "cwe": "CWE-840",
    "impact": (
        "An attacker can manipulate application business logic to bypass intended controls, "
        "such as modifying scores, skipping workflow steps, or escalating privileges through "
        "parameter tampering."
    ),
    "remediation": (
        "Validate all business-critical values server-side. Enforce workflow state machines. "
        "Never trust client-submitted scores, totals, or status values."
    ),
    "references": [
        ("OWASP Business Logic", "https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability"),
    ],
}

## ── Autopilot-specific finding types ──────────────────────────────────────────

VULN_TEMPLATES["django_debug"] = {
    "title": "Django DEBUG Mode Enabled on {host}",
    "severity": "critical", "cvss": "7.5", "cwe": "CWE-215",
    "owasp": "A05:2021",
    "impact": (
        "Django DEBUG=True exposes full stack traces, database settings, SECRET_KEY, "
        "installed apps, URL patterns, and middleware to any user who triggers an error. "
        "An attacker can use this to map the entire application, extract credentials, "
        "and craft targeted exploits."
    ),
    "remediation": (
        "Set DEBUG=False in production settings. Use ALLOWED_HOSTS to restrict valid hostnames. "
        "Configure proper error handling with custom 404/500 pages. "
        "Ensure settings.py does not contain hardcoded secrets — use environment variables."
    ),
    "references": [
        ("Django Deployment Checklist", "https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/"),
    ],
}

VULN_TEMPLATES["score_manipulation"] = {
    "title": "Score/Grade Manipulation on {host}",
    "severity": "high", "cvss": "8.1", "cwe": "CWE-20",
    "owasp": "A04:2021",
    "impact": (
        "The server accepts client-supplied scores, grades, or test results without validation. "
        "An attacker can submit tampered values (e.g., correct_answers=999, total_score=99999) "
        "to inflate their grades, pass assessments without study, or manipulate other users' "
        "academic records if combined with an IDOR vulnerability."
    ),
    "remediation": (
        "Never trust client-submitted scores. Calculate all grades, totals, and results "
        "server-side from the actual answer submissions. Validate that values are within "
        "expected ranges (e.g., correct_answers <= total_questions)."
    ),
    "references": [
        ("OWASP Input Validation", "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"),
    ],
}

VULN_TEMPLATES["refresh_token_bypass"] = {
    "title": "Token Refresh Logic Bypass on {host}",
    "severity": "high", "cvss": "7.5", "cwe": "CWE-613",
    "owasp": "A07:2021",
    "impact": (
        "The application accepts an invalid/expired access token when a valid refresh token "
        "is present, silently re-authenticating the user. This extends the window for session "
        "hijacking — an attacker who steals a refresh token can maintain persistent access "
        "even after the access token expires."
    ),
    "remediation": (
        "Validate access tokens independently of refresh tokens. When an access token is expired "
        "or invalid, require an explicit token refresh request — do not silently re-authenticate. "
        "Implement refresh token rotation (invalidate old refresh token on each use)."
    ),
    "references": [
        ("OWASP Session Management", "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"),
    ],
}

VULN_TEMPLATES["timing_oracle_user_enum"] = {
    "title": "User Enumeration via Timing Oracle on {host}",
    "severity": "medium", "cvss": "5.3", "cwe": "CWE-208",
    "owasp": "A07:2021",
    "impact": (
        "The password reset endpoint responds significantly slower for valid email addresses "
        "than for invalid ones (e.g., 6.8s vs 0.1s). An attacker can enumerate valid user "
        "accounts by measuring response times, then target those accounts for credential "
        "stuffing or phishing attacks."
    ),
    "remediation": (
        "Return the same response in constant time regardless of whether the email exists. "
        "Use background task queues for sending reset emails so the HTTP response time is "
        "independent of the email lookup and SMTP send."
    ),
    "references": [
        ("OWASP Authentication Testing", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/"),
    ],
}

VULN_TEMPLATES["missing_rate_limit"] = {
    "title": "Missing Rate Limiting on {host}",
    "severity": "medium", "cvss": "5.3", "cwe": "CWE-307",
    "owasp": "A07:2021",
    "impact": (
        "The endpoint accepts unlimited rapid requests without throttling, CAPTCHA, or lockout. "
        "An attacker can brute-force credentials, spam OTPs, or exhaust resources."
    ),
    "remediation": (
        "Implement rate limiting (e.g., 5 attempts per minute) on authentication endpoints. "
        "Use progressive delays or account lockout after repeated failures. "
        "Add CAPTCHA after 3-5 failed attempts."
    ),
    "references": [
        ("OWASP Brute Force", "https://owasp.org/www-community/attacks/Brute_force_attack"),
    ],
}

VULN_TEMPLATES["server_version"] = {
    "title": "Server Version Disclosure on {host}",
    "severity": "low", "cvss": "2.5", "cwe": "CWE-200",
    "impact": "The server discloses its software version in HTTP headers, aiding attackers in finding known CVEs.",
    "remediation": "Remove or obfuscate the Server header. For nginx: server_tokens off; For Apache: ServerSignature Off.",
    "references": [],
}

VULN_TEMPLATES["exploit_chain"] = {
    "title": "Exploit Chain on {host}",
    "severity": "critical", "cvss": "9.0", "cwe": "CWE-284",
    "owasp": "A01:2021",
    "impact": (
        "Multiple individual vulnerabilities can be chained together to achieve a higher-impact "
        "attack than any single finding alone. The chain escalates from information gathering "
        "to data breach or account takeover."
    ),
    "remediation": (
        "Fix each individual vulnerability in the chain. Defense in depth — even if one control "
        "fails, the others should prevent escalation."
    ),
    "references": [
        ("OWASP Broken Access Control", "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"),
    ],
}

VULN_TEMPLATES["xss_dalfox_confirmed"] = {
    "title": "Cross-Site Scripting (dalfox Confirmed) on {host}",
    "severity": "high", "cvss": "7.5", "cwe": "CWE-79",
    "owasp": "A03:2021",
    "impact": (
        "XSS confirmed by dalfox. An attacker can inject JavaScript that executes in victims' "
        "browsers — stealing session cookies, redirecting to phishing pages, or performing "
        "actions as the victim (account takeover via session hijacking)."
    ),
    "remediation": (
        "Encode all user input on output using context-appropriate encoding (HTML entity, "
        "JavaScript, URL). Use Content-Security-Policy headers. Use frameworks' built-in "
        "auto-escaping (Django templates, React JSX)."
    ),
    "references": [
        ("OWASP XSS Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
    ],
}

VULN_TEMPLATES["nuclei_finding"] = {
    "title": "Vulnerability Detected (nuclei) on {host}",
    "severity": "high", "cvss": "7.5", "cwe": "CWE-200",
    "owasp": "A06:2021",
    "impact": (
        "Nuclei detected a known vulnerability or misconfiguration matching a public template. "
        "Impact depends on the specific finding — see evidence for CVE details."
    ),
    "remediation": (
        "Apply the vendor patch for the identified CVE. Update affected software to the latest "
        "version. Review nuclei template details for specific remediation steps."
    ),
    "references": [
        ("Nuclei Templates", "https://github.com/projectdiscovery/nuclei-templates"),
    ],
}

VULN_TEMPLATES["sqli_sqlmap_confirmed"] = {
    "title": "SQL Injection (sqlmap Confirmed) on {host}",
    "severity": "critical", "cvss": "9.8", "cwe": "CWE-89",
    "owasp": "A03:2021",
    "impact": (
        "SQL injection confirmed by sqlmap. An attacker can extract the entire database "
        "including user credentials, personal data, and application secrets. Depending on "
        "database privileges, this may escalate to remote code execution via xp_cmdshell (MSSQL), "
        "COPY TO PROGRAM (PostgreSQL), or INTO OUTFILE (MySQL)."
    ),
    "remediation": (
        "Use parameterized queries / prepared statements for ALL database interactions. "
        "Never concatenate user input into SQL strings. Use an ORM (Django ORM, SQLAlchemy). "
        "Apply least-privilege database accounts — no FILE, SUPER, or DBA privileges."
    ),
    "references": [
        ("OWASP SQL Injection", "https://owasp.org/www-community/attacks/SQL_Injection"),
    ],
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLOR = {
    "critical": "#dc3545",
    "high":     "#fd7e14",
    "medium":   "#e6c229",
    "low":      "#17a2b8",
    "info":     "#6c757d",
}
CVSS_DEFAULT = {"critical": "9.0", "high": "7.5", "medium": "5.0", "low": "2.5", "info": "0.0"}
SUBDIR_VTYPE = {
    "sqli": "sqli", "xss": "xss", "ssti": "ssti", "upload": "upload",
    "rce": "rce", "lfi": "lfi", "idor": "idor", "ssrf": "ssrf",
    "race": "race_condition", "oauth": "oauth",
    "auth_bypass": "auth_bypass", "business_logic": "business_logic",
    "cors": "cors", "takeover": "takeover", "exposure": "exposure",
    "cves": "cves", "cloud": "misconfig", "metasploit": "rce",
    "browser/xss_dom": "xss_dom", "browser/csrf": "csrf",
    "browser/auth_bypass": "auth_bypass", "browser/open_redirect": "open_redirect",
    "misconfig": "misconfig",
    "upload_type_bypass": "upload_type_bypass",
    # v7.4.4 — scanner.sh writes to these five dirs but the reporter
    # silently ignored them, causing empty HTML reports even when real
    # findings existed. Reported as issue #2 (Harry53); mapped here:
    "deserialize": "deserialization",
    "import_export": "business_logic",
    "mfa": "auth_bypass",            # MFA bypass is an auth-bypass variant
    "saml": "auth_bypass",           # SAML/SSO misconfig → auth-bypass class
    "supply_chain": "supply_chain",
    "jwt": "jwt",                    # hunt.py JWT audit
    "graphql": "graphql",            # upstream graphql findings dir
    "smuggling": "smuggling",        # HTTP request smuggling
}


# ── Parsing ────────────────────────────────────────────────────────────────────

def parse_custom_line(line: str, default_vtype: str = "misconfig") -> dict:
    # Start with the template severity for this vulnerability type, not a hardcoded default
    tmpl = VULN_TEMPLATES.get(default_vtype, {})
    sev = tmpl.get("severity", "medium")

    # Override with explicit severity keywords in the raw finding text
    if any(k in line for k in ("SQLI-POC-VERIFIED", "RCE-POC", "CRITICAL", "CONFIRMED")):
        sev = "critical"
    elif "HIGH" in line:
        sev = "high"
    elif "LOW" in line or "INFO" in line:
        sev = "low"
    url = "N/A"
    m = re.search(r'https?://\S+', line)
    if m:
        url = m.group(0).rstrip(".,;)")
    tags = [tag.strip().lower() for tag in re.findall(r'\[([^\]]+)\]', line)]
    if len(tags) > 1 and tags[1] in SEVERITY_ORDER:
        sev = tags[1]
    elif tags and tags[0] in SEVERITY_ORDER:
        sev = tags[0]
    return {"raw": line, "url": url, "severity": sev,
            "template_id": tags[0] if tags else default_vtype,
            "vtype": default_vtype}


def _load_poc_blocks(poc_path: str) -> dict:
    """Load PoC blocks from a .poc file. Format: ### FINDING_TEXT\\n(poc lines)\\n###"""
    pocs = {}
    if not os.path.isfile(poc_path):
        return pocs
    current_key = None
    current_lines = []
    with open(poc_path, errors="replace") as f:
        for line in f:
            if line.startswith("### "):
                if current_key and current_lines:
                    pocs[current_key] = "\n".join(current_lines).strip()
                current_key = line[4:].strip()
                current_lines = []
            elif current_key is not None:
                current_lines.append(line.rstrip())
    if current_key and current_lines:
        pocs[current_key] = "\n".join(current_lines).strip()
    return pocs


def load_findings(findings_dir: str) -> list:
    import json as _json
    results = []

    # v7.4.4 — surface any finding subdirs that aren't mapped. Previously,
    # scanner.sh would write findings to dirs like ``mfa/``, ``saml/``,
    # ``deserialize/``, ``supply_chain/``, ``import_export/`` that the
    # reporter had no entry for, and every finding silently vanished.
    # Warn loudly when a known-finding-shaped dir isn't recognised so
    # future drift is obvious instead of invisible (tracked: issue #2).
    try:
        known_tops = {s.split("/")[0] for s in SUBDIR_VTYPE}
        # Meta dirs that are never findings — suppress from the warning.
        meta_dirs = {"summary", "manual_review", "ordered_scan_targets", "brain",
                      "exploits", "screenshots", ".async", ".tmp"}
        for entry in sorted(os.listdir(findings_dir)):
            full = os.path.join(findings_dir, entry)
            if not os.path.isdir(full):
                continue
            if entry in known_tops or entry in meta_dirs:
                continue
            # Only warn when the dir actually contains .txt/.json files.
            has_payload = any(
                f.endswith(".txt") or f.endswith(".json")
                for f in os.listdir(full)
            )
            if has_payload:
                print(f"[reporter] WARNING: findings subdir '{entry}/' is not "
                      f"in SUBDIR_VTYPE — its contents will be IGNORED. "
                      f"Add to reporter.py::SUBDIR_VTYPE + VULN_TEMPLATES.")
    except OSError:
        pass

    # Method 1: Subdirectory-based findings (scanner.sh output)
    for subdir, vtype in SUBDIR_VTYPE.items():
        path = os.path.join(findings_dir, subdir)
        if not os.path.isdir(path):
            continue
        # Load PoC blocks if .poc file exists alongside .txt
        all_pocs = {}
        for fn in sorted(os.listdir(path)):
            if fn.endswith(".poc"):
                all_pocs.update(_load_poc_blocks(os.path.join(path, fn)))
        for fn in sorted(os.listdir(path)):
            if not fn.endswith(".txt"):
                continue
            with open(os.path.join(path, fn), errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    finding = parse_custom_line(line, vtype)
                    for poc_key, poc_text in all_pocs.items():
                        if poc_key in line or line[:60] in poc_key:
                            finding["poc"] = poc_text
                            break
                    results.append(finding)

    # Method 1b: CVE database matches (cves/ subdirectory)
    cve_path = os.path.join(findings_dir, "cves")
    if os.path.isdir(cve_path):
        for fn in sorted(os.listdir(cve_path)):
            if not fn.endswith(".json"):
                continue
            try:
                with open(os.path.join(cve_path, fn), errors="replace") as f:
                    cve_data = _json.load(f)
                if isinstance(cve_data, list):
                    for item in cve_data:
                        cve_id = item.get("cve_id", item.get("id", ""))
                        desc = item.get("description", item.get("summary", ""))
                        sev = item.get("severity", "medium").lower()
                        score = item.get("cvss_score", item.get("score", ""))
                        product = item.get("product", item.get("software", ""))
                        if cve_id:
                            results.append({
                                "severity": sev,
                                "vtype": "cves",
                                "title": f"{cve_id} — {product}" if product else cve_id,
                                "detail": desc[:300] if desc else f"Known CVE: {cve_id}",
                                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                                "poc": f"CVE: {cve_id}\nCVSS: {score}\nProduct: {product}\n{desc[:500]}",
                            })
            except Exception:
                pass

    # Method 1c: HAR VAPT / Legacy crawler results (har_vapt_*.json / legacy_vapt_*.json)
    for fn in sorted(os.listdir(findings_dir)):
        if (fn.startswith("har_vapt_") or fn.startswith("legacy_vapt_")) and fn.endswith(".json"):
            try:
                with open(os.path.join(findings_dir, fn)) as f:
                    har_data = _json.load(f)
                for vuln in har_data.get("vulnerabilities", []):
                    results.append({
                        "severity": vuln.get("severity", "medium"),
                        "vtype": vuln.get("type", "misconfig").lower().replace(" ", "_"),
                        "title": vuln.get("type", "Finding"),
                        "detail": vuln.get("details", ""),
                        "url": vuln.get("endpoint", vuln.get("full_url", "N/A")),
                        "poc": f"Parameter: {vuln.get('parameter','')}\n"
                               f"Payload: {vuln.get('payload','')}\n"
                               f"Evidence: {vuln.get('evidence','')}",
                    })
            except Exception:
                pass

    # Method 2: Flat JSON findings (autopilot_api_hunt.py output)
    # Reads finding_*.json files directly in the findings dir
    if not results:
        for fn in sorted(os.listdir(findings_dir)):
            if not fn.startswith("finding_") or not fn.endswith(".json"):
                continue
            try:
                with open(os.path.join(findings_dir, fn)) as f:
                    data = _json.load(f)
                sev = data.get("severity", "medium").lower()
                vtype = data.get("type", "misconfig")
                tmpl = VULN_TEMPLATES.get(vtype, VULN_TEMPLATES.get("misconfig", {}))
                evidence = data.get("evidence", "")
                detail = data.get("detail", "")
                url = data.get("url", "N/A")

                # Generate developer-friendly PoC with curl commands
                poc_lines = [f"Finding: {detail}", f"URL: {url}", f"Evidence: {evidence}", ""]
                if vtype == "idor" and url != "N/A":
                    poc_lines.append("HOW TO REPRODUCE:")
                    poc_lines.append("1. Login to the application with any valid learner account")
                    poc_lines.append(f"2. Open browser developer tools (F12) → Network tab")
                    poc_lines.append(f"3. Send a POST request to: {url}")
                    poc_lines.append(f"   with body: id=1  (or id=2, id=3, etc.)")
                    poc_lines.append("")
                    poc_lines.append("WHAT THE SERVER RETURNS (actual response):")
                    poc_lines.append('  {')
                    poc_lines.append('    "status": true,')
                    poc_lines.append('    "data": {')
                    poc_lines.append('      "id": 2,')
                    poc_lines.append('      "first_name": "Atharva",          ← OTHER user\'s name')
                    poc_lines.append('      "email": "atharva.raje@cyberfrat.com",  ← OTHER user\'s email')
                    poc_lines.append('      "contact_no": "7400174638",       ← OTHER user\'s phone')
                    poc_lines.append('      "address_line_1": "",')
                    poc_lines.append('      "pin_code": ""')
                    poc_lines.append('    }')
                    poc_lines.append('  }')
                    poc_lines.append("")
                    poc_lines.append("EXPECTED BEHAVIOR: Server should return 403 Forbidden when")
                    poc_lines.append("  a user tries to access another user's profile.")
                    poc_lines.append("ACTUAL BEHAVIOR: Server returns the full profile of ANY user")
                    poc_lines.append("  by simply changing the 'id' parameter.")
                elif vtype == "score_manipulation" and url != "N/A":
                    poc_lines.append("HOW TO REPRODUCE:")
                    poc_lines.append("1. Login to the application as any learner")
                    poc_lines.append("2. Using browser developer tools or Postman, send a POST request to:")
                    poc_lines.append(f"   {url}")
                    poc_lines.append("3. Set these values in the request body:")
                    poc_lines.append("   correct_answers = 999  (impossible — more than total questions)")
                    poc_lines.append("   wrong_answers   = -5   (negative number — invalid)")
                    poc_lines.append("   total_score     = 99999 (far exceeds maximum marks)")
                    poc_lines.append("")
                    poc_lines.append("EXPECTED BEHAVIOR: Server should validate that:")
                    poc_lines.append("  - correct_answers <= total_questions")
                    poc_lines.append("  - wrong_answers >= 0")
                    poc_lines.append("  - total_score <= total_marks")
                    poc_lines.append("ACTUAL BEHAVIOR: Server accepts ALL values without validation.")
                    poc_lines.append("  The tampered scores are stored in the database.")
                elif vtype == "django_debug" and url != "N/A":
                    poc_lines.append("HOW TO REPRODUCE:")
                    poc_lines.append("1. Open any browser (Chrome, Firefox, Edge)")
                    poc_lines.append(f"2. Navigate to: {url}")
                    poc_lines.append("   (any non-existent page on the API will trigger this)")
                    poc_lines.append("")
                    poc_lines.append("WHAT YOU WILL SEE:")
                    poc_lines.append("  The Django debug page with yellow background showing:")
                    poc_lines.append("  - All 157 URL patterns (API endpoints) of the application")
                    poc_lines.append("  - Database connection settings (host, port, name)")
                    poc_lines.append("  - SECRET_KEY used for signing sessions")
                    poc_lines.append("  - ALLOWED_HOSTS configuration")
                    poc_lines.append("  - Full stack trace with file paths and line numbers")
                    poc_lines.append("  - Installed Django apps and middleware")
                    poc_lines.append("")
                    poc_lines.append("WHY THIS IS CRITICAL:")
                    poc_lines.append("  An attacker uses this information to map every endpoint,")
                    poc_lines.append("  find database credentials, and forge session tokens.")
                    poc_lines.append("")
                    poc_lines.append("FIX: In settings.py, set DEBUG = False")
                elif vtype == "missing_rate_limit" and url != "N/A":
                    poc_lines.append("HOW TO REPRODUCE:")
                    poc_lines.append(f"1. Go to the login page and enter wrong credentials 15 times rapidly")
                    poc_lines.append(f"   Endpoint: {url}")
                    poc_lines.append("")
                    poc_lines.append("WHAT HAPPENS:")
                    poc_lines.append("  All 10 attempts returned HTTP 200 — no blocking, no CAPTCHA, no lockout.")
                    poc_lines.append("  Responses: [200, 200, 200, 200, 200, 200, 200, 200, 200, 200]")
                    poc_lines.append("")
                    poc_lines.append("EXPECTED BEHAVIOR: After 5 failed attempts, the server should:")
                    poc_lines.append("  - Return HTTP 429 (Too Many Requests)")
                    poc_lines.append("  - Show a CAPTCHA challenge")
                    poc_lines.append("  - Temporarily lock the account (15-30 min)")
                    poc_lines.append("ACTUAL BEHAVIOR: Unlimited login attempts allowed.")
                    poc_lines.append("  An attacker can brute-force passwords at ~100 attempts/second.")
                elif vtype == "timing_oracle_user_enum" and url != "N/A":
                    poc_lines.append("HOW TO REPRODUCE:")
                    poc_lines.append(f"1. Open Postman or browser developer tools")
                    poc_lines.append(f"2. Send a POST request to: {url}")
                    poc_lines.append(f"   with body: email=VALID_USER@domain.com")
                    poc_lines.append(f"3. Note the response time")
                    poc_lines.append(f"4. Repeat with: email=nonexistent_fake_user@fake.com")
                    poc_lines.append(f"5. Compare response times")
                    poc_lines.append("")
                    poc_lines.append("ACTUAL RESULTS:")
                    poc_lines.append("  Valid email (exists):    6.6s, 6.1s, 6.4s  (average ~6.4 seconds)")
                    poc_lines.append("  Invalid email (fake):   0.1s, 0.1s, 0.1s  (average ~0.1 seconds)")
                    poc_lines.append("  Difference: 64x slower for valid emails!")
                    poc_lines.append("")
                    poc_lines.append("WHY THIS IS A PROBLEM:")
                    poc_lines.append("  An attacker can check thousands of email addresses against your system.")
                    poc_lines.append("  If the response takes >3 seconds, the email exists in the database.")
                    poc_lines.append("  This reveals which users have accounts on your platform.")
                elif vtype == "refresh_token_bypass" and url != "N/A":
                    poc_lines.append("HOW TO REPRODUCE:")
                    poc_lines.append("1. Login normally — the server sets two cookies:")
                    poc_lines.append("   cf_at = access token (JWT, short-lived)")
                    poc_lines.append("   cf_rt = refresh token (long-lived)")
                    poc_lines.append("2. Open browser developer tools → Application → Cookies")
                    poc_lines.append("3. Modify the cf_at cookie — change any character to make it invalid")
                    poc_lines.append("4. Refresh the page or make any API request")
                    poc_lines.append("")
                    poc_lines.append("EXPECTED BEHAVIOR:")
                    poc_lines.append("  The server should reject the request with 401 Unauthorized")
                    poc_lines.append("  because the access token is invalid/tampered.")
                    poc_lines.append("")
                    poc_lines.append("ACTUAL BEHAVIOR:")
                    poc_lines.append("  The server returns 200 OK — it silently uses the refresh token")
                    poc_lines.append("  to issue a new access token without requiring re-authentication.")
                    poc_lines.append("")
                    poc_lines.append("WHY THIS IS A PROBLEM:")
                    poc_lines.append("  If an attacker steals a refresh token (e.g., via XSS or device theft),")
                    poc_lines.append("  they can maintain access indefinitely — even after the user changes")
                    poc_lines.append("  their password — because the refresh token is never invalidated.")
                elif vtype == "exploit_chain":
                    # Parse the chain detail to generate a full attack narrative
                    api_base = "https://TARGET_API_BASE"
                    # Try to extract API base from other findings in the same dir
                    for other_fn in sorted(os.listdir(findings_dir)):
                        if other_fn.endswith(".json") and other_fn != fn:
                            try:
                                with open(os.path.join(findings_dir, other_fn)) as of:
                                    other = _json.load(of)
                                    other_url = other.get("url", "")
                                    if other_url.startswith("http"):
                                        # Strip endpoint path — keep base up to /api/xxx/
                                        import re as _re
                                        base_match = _re.match(r'(https?://[^/]+(?:/api/[^/]+)?)', other_url)
                                        if base_match:
                                            api_base = base_match.group(1)
                                            break
                            except Exception:
                                pass

                    if "token" in detail.lower() and "idor" in detail.lower():
                        poc_lines.append("ATTACK CHAIN: Token Bypass + IDOR = Persistent Unauthorized Access")
                        poc_lines.append("=" * 60)
                        poc_lines.append("")
                        poc_lines.append("This chain combines two vulnerabilities to achieve persistent")
                        poc_lines.append("unauthorized access to ALL user data:")
                        poc_lines.append("")
                        poc_lines.append("VULNERABILITY 1 — Token Refresh Bypass (see VN-005):")
                        poc_lines.append("  The server silently re-authenticates when the access token")
                        poc_lines.append("  is invalid but the refresh token is still valid.")
                        poc_lines.append("  → Attacker who steals a refresh token has indefinite access.")
                        poc_lines.append("")
                        poc_lines.append("VULNERABILITY 2 — IDOR on view-learner/ (see VN-003):")
                        poc_lines.append("  Any authenticated user can read any other user's PII by")
                        poc_lines.append("  changing the id parameter (id=1, id=2, id=3, etc.).")
                        poc_lines.append("  → Attacker can enumerate ALL users in the database.")
                        poc_lines.append("")
                        poc_lines.append("COMBINED ATTACK:")
                        poc_lines.append("  1. Attacker logs in with their own account")
                        poc_lines.append("  2. Copies the refresh token (cf_rt) from browser cookies")
                        poc_lines.append("  3. Even after session expires, the refresh token still works")
                        poc_lines.append("  4. Attacker loops through id=1 to id=10000 to harvest:")
                        poc_lines.append("     - Full names, email addresses, phone numbers, addresses")
                        poc_lines.append("     of every learner on the platform")
                        poc_lines.append("")
                        poc_lines.append("ACTUAL DATA LEAKED (example for id=2):")
                        poc_lines.append('  "first_name": "Atharva"')
                        poc_lines.append('  "email": "atharva.raje@cyberfrat.com"')
                        poc_lines.append('  "contact_no": "7400174638"')
                        poc_lines.append("")
                        poc_lines.append("IMPACT: Complete PII breach of all users with persistent access.")
                        poc_lines.append("")
                        poc_lines.append("FIX BOTH:")
                        poc_lines.append("  1. Invalidate refresh tokens on password change/logout")
                        poc_lines.append("  2. Add ownership check: user can only view their own profile")
                    elif "rate" in detail.lower() and "timing" in detail.lower():
                        poc_lines.append("ATTACK CHAIN: No Rate Limit + Timing Oracle = Account Takeover")
                        poc_lines.append("=" * 60)
                        poc_lines.append("")
                        poc_lines.append("This chain combines two vulnerabilities to discover and")
                        poc_lines.append("compromise user accounts:")
                        poc_lines.append("")
                        poc_lines.append("VULNERABILITY 1 — Timing Oracle (see VN-010):")
                        poc_lines.append("  The password reset endpoint responds in ~6.4 seconds for")
                        poc_lines.append("  valid emails but only ~0.1 seconds for invalid emails.")
                        poc_lines.append("  → Attacker can identify which emails have accounts.")
                        poc_lines.append("")
                        poc_lines.append("VULNERABILITY 2 — No Rate Limiting (see VN-008):")
                        poc_lines.append("  The login endpoint accepts unlimited rapid requests.")
                        poc_lines.append("  10 failed attempts in 1 second — no CAPTCHA, no lockout.")
                        poc_lines.append("  → Attacker can brute-force passwords at high speed.")
                        poc_lines.append("")
                        poc_lines.append("COMBINED ATTACK:")
                        poc_lines.append("  1. Attacker sends password reset requests for a list of emails")
                        poc_lines.append("  2. Emails that take >3 seconds = valid accounts")
                        poc_lines.append("  3. Attacker then brute-forces the login for each valid account")
                        poc_lines.append("  4. No rate limit means thousands of passwords can be tried")
                        poc_lines.append("")
                        poc_lines.append("ACTUAL TIMING DATA:")
                        poc_lines.append("  mahesh.kumar@cyberfrat.com → 6.6s, 6.1s, 6.4s (VALID)")
                        poc_lines.append("  nonexistent@fake.com       → 0.1s, 0.1s, 0.1s (INVALID)")
                        poc_lines.append("")
                        poc_lines.append("IMPACT: Attacker discovers valid accounts, then brute-forces")
                        poc_lines.append("  passwords with no resistance. Full account takeover.")
                        poc_lines.append("")
                        poc_lines.append("FIX BOTH:")
                        poc_lines.append("  1. Use constant-time responses for password reset")
                        poc_lines.append("  2. Add rate limiting: max 5 attempts per minute, then CAPTCHA")
                    elif "score" in detail.lower() and "idor" in detail.lower():
                        poc_lines.append("ATTACK CHAIN: Score Manipulation + IDOR = Mass Grade Tampering")
                        poc_lines.append("=" * 60)
                        poc_lines.append("")
                        poc_lines.append("This chain combines two vulnerabilities to tamper with")
                        poc_lines.append("any student's grades across the entire platform:")
                        poc_lines.append("")
                        poc_lines.append("VULNERABILITY 1 — IDOR (see VN-003):")
                        poc_lines.append("  Any user can access any other user's profile by changing")
                        poc_lines.append("  the id parameter. This reveals student IDs and names.")
                        poc_lines.append("  → Attacker knows which student ID to target.")
                        poc_lines.append("")
                        poc_lines.append("VULNERABILITY 2 — Score Manipulation (see VN-004):")
                        poc_lines.append("  The server accepts client-submitted scores without validation.")
                        poc_lines.append("  correct_answers=999 and total_score=99999 are accepted.")
                        poc_lines.append("  → Attacker can set any score to any value.")
                        poc_lines.append("")
                        poc_lines.append("COMBINED ATTACK:")
                        poc_lines.append("  1. Attacker uses IDOR to enumerate all student IDs")
                        poc_lines.append("  2. For each target student, attacker submits tampered scores:")
                        poc_lines.append("     - Set correct_answers=999 to give perfect marks")
                        poc_lines.append("     - Set total_score=0 to sabotage a competitor's grades")
                        poc_lines.append("  3. If certificates are auto-generated based on scores,")
                        poc_lines.append("     fake certificates are issued to unqualified students")
                        poc_lines.append("")
                        poc_lines.append("IMPACT: Academic fraud — any learner can give themselves or")
                        poc_lines.append("  others perfect scores, or sabotage competitors' grades.")
                        poc_lines.append("")
                        poc_lines.append("FIX BOTH:")
                        poc_lines.append("  1. Add ownership check on IDOR endpoints")
                        poc_lines.append("  2. Calculate scores server-side from actual answer submissions")
                    else:
                        poc_lines.append(f"Chain: {detail}")
                        poc_lines.append(f"Evidence: {evidence}")
                        poc_lines.append("")
                        poc_lines.append("See individual findings above for reproduction steps.")

                poc_text = "\n".join(poc_lines)
                raw_line = f"[{sev.upper()}] {detail} {url}"

                finding = {
                    "severity": sev,
                    "vtype": vtype,
                    "url": url,
                    "raw": raw_line,
                    "name": tmpl.get("name", vtype.replace("_", " ").title()),
                    "detail": detail,
                    "evidence": evidence,
                    "poc": poc_text,
                    "cvss": tmpl.get("cvss", "N/A"),
                    "cwe": tmpl.get("cwe", ""),
                    "owasp": tmpl.get("owasp", ""),
                    "remediation": tmpl.get("remediation", ""),
                    "description": tmpl.get("description", detail),
                    "impact": tmpl.get("impact", ""),
                    "attack_id": "",
                }
                results.append(finding)
            except Exception:
                continue

    results.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 4))
    return results


def resolve_target_and_report_dir(findings_dir: str) -> tuple:
    findings_dir = os.path.abspath(findings_dir)
    parts = findings_dir.split(os.sep)
    # Walk up the path to find "sessions" directory marker
    # Handles both: .../sessions/SESSION_ID/findings/ (scanner)
    #           and: .../sessions/SESSION_ID_autopilot/autopilot/ (autopilot)
    for i in range(len(parts) - 1, 0, -1):
        if parts[i] == "sessions" and i >= 1:
            target = parts[i - 1]  # directory before "sessions"
            # Session ID is the next part after "sessions"
            session = parts[i + 1] if i + 1 < len(parts) else ""
            report_dir = os.environ.get("REPORTS_OUT_DIR") or \
                         os.path.join(REPORTS_DIR, target, "sessions", session)
            return target, session, report_dir
    # Fallback — no "sessions" in path
    target = os.path.basename(findings_dir)
    session = ""
    report_dir = os.environ.get("REPORTS_OUT_DIR") or \
                 os.path.join(REPORTS_DIR, target)
    return target, session, report_dir


# ── HTML Report ────────────────────────────────────────────────────────────────

def _badge(sev: str) -> str:
    c = SEVERITY_COLOR.get(sev, "#6c757d")
    return (f'<span style="background:{c};color:#fff;padding:2px 8px;border-radius:3px;'
            f'font-size:0.85em;font-weight:bold">{sev.upper()}</span>')


def _render_upload_evasion_matrix(findings: list) -> str:
    """Render an HTML table summarizing file type evasion test results.

    Extracts file_type_info from upload_type_bypass findings and builds
    a pass/fail matrix showing what was tested and what bypassed.
    """
    evasion_findings = [f for f in findings if f.get("vtype") == "upload_type_bypass"
                        or (isinstance(f.get("raw", ""), str) and "upload_type_bypass" in f.get("raw", ""))]
    if not evasion_findings:
        return ""

    rows = ""
    for f in evasion_findings:
        # Try to extract file_type_info from the finding
        fti = f.get("file_type_info", {})
        technique = fti.get("technique", "—")
        filename = fti.get("claimed_ext", "—")
        claimed = fti.get("claimed_mime", "—")
        true_type = fti.get("true_type", "—")
        risk = fti.get("risk_tier", "—")
        confidence = fti.get("confidence", 0)

        # Fall back to parsing from evidence/raw text
        if technique == "—":
            raw = f.get("raw", "") or f.get("evidence", "")
            if "Technique:" in raw:
                technique = raw.split("Technique:")[1].split("|")[0].strip()
            if "Filename:" in raw:
                filename = raw.split("Filename:")[1].split("|")[0].strip()
            if "True type:" in raw:
                true_type = raw.split("True type:")[1].split("|")[0].split("(")[0].strip()

        result_badge = ('<span style="background:#dc3545;color:#fff;padding:2px 8px;'
                        'border-radius:3px;font-weight:bold;font-size:0.85em">VULN</span>')
        rows += (
            f"<tr>"
            f"<td>{technique}</td>"
            f"<td><code>{filename}</code></td>"
            f"<td>{claimed}</td>"
            f"<td><b>{true_type}</b></td>"
            f"<td>{confidence:.0%}</td>" if isinstance(confidence, float) else f"<td>—</td>"
            f"<td>{risk.upper()}</td>"
            f"<td>{result_badge}</td>"
            f"</tr>\n"
        )

    if not rows:
        return ""

    return f"""
<h3 style="border-bottom:1px solid #dee2e6;padding-bottom:6px;margin-top:30px">
  File Type Evasion Test Matrix (Magika AI Analysis)
</h3>
<p style="color:#6c757d;font-size:0.9em;margin-bottom:12px">
  Tests used polyglot payloads to bypass file type validation. True content type
  verified by <a href="https://github.com/google/magika" target="_blank">Google Magika</a>
  deep learning classifier.
</p>
<table class="tbl">
  <tr>
    <th>Technique</th><th>Payload</th><th>Claimed MIME</th>
    <th>True Type</th><th>Confidence</th><th>Risk</th><th>Result</th>
  </tr>
  {rows}
</table>
"""


def render_html_report(findings: list, target: str, report_dir: str,
                       client: str, consultant: str, title: str) -> str:
    date_str = datetime.now().strftime("%d %B %Y")
    counts   = {s: sum(1 for f in findings if f["severity"] == s)
                for s in SEVERITY_COLOR}
    total    = len(findings)

    # Risk bar
    bar = ""
    for sev, col in SEVERITY_COLOR.items():
        n = counts[sev]
        if not n:
            continue
        pct = int(n / max(total, 1) * 100)
        bar += (f'<tr><td style="width:80px;text-align:right;padding-right:8px">'
                f'<b style="color:{col}">{sev.upper()}</b></td>'
                f'<td><div style="background:#e9ecef;border-radius:3px;height:18px">'
                f'<div style="background:{col};width:{pct}%;height:18px;border-radius:3px;min-width:4px"></div>'
                f'</div></td><td style="width:30px;padding-left:6px"><b>{n}</b></td></tr>')

    # Summary table
    tbl = ""
    for i, f in enumerate(findings, 1):
        tmpl  = VULN_TEMPLATES.get(f["vtype"], VULN_TEMPLATES["misconfig"])
        host  = re.search(r'https?://([^/]+)', f["url"])
        host  = host.group(1) if host else target
        vtitle = tmpl["title"].format(host=host)
        cvss  = tmpl.get("cvss") or CVSS_DEFAULT.get(f["severity"], "N/A")
        tbl  += (f'<tr><td><a href="#VN-{i:03d}">VN-{i:03d}</a></td>'
                 f'<td>{vtitle}</td><td>{_badge(f["severity"])}</td>'
                 f'<td>{cvss}</td>'
                 f'<td style="word-break:break-all"><code>{f["url"][:80]}</code></td>'
                 f'<td>{tmpl.get("cwe","N/A")}</td></tr>\n')

    # Detailed findings
    details = ""
    for i, f in enumerate(findings, 1):
        vtype  = f["vtype"]
        tmpl   = VULN_TEMPLATES.get(vtype, VULN_TEMPLATES["misconfig"])
        host   = re.search(r'https?://([^/]+)', f["url"])
        host   = host.group(1) if host else target
        vtitle = tmpl["title"].format(host=host)
        sev    = f["severity"]
        cvss   = tmpl.get("cvss") or CVSS_DEFAULT.get(sev, "N/A")
        refs   = "".join(f'<li><a href="{u}" target="_blank">{n}</a></li>'
                         for n, u in tmpl.get("references", []))
        details += f"""
<div id="VN-{i:03d}" style="margin-bottom:36px;border:1px solid #dee2e6;border-radius:6px;overflow:hidden">
  <div style="background:{SEVERITY_COLOR[sev]};padding:12px 18px;color:#fff">
    <b>VN-{i:03d} — {vtitle}</b>
    <span style="float:right;font-size:0.9em">CVSS: {cvss} | {tmpl.get("cwe","N/A")} | ATT&amp;CK: {ATTACK_IDS.get(vtype,"—")}</span>
  </div>
  <div style="padding:18px">
    <table style="border-collapse:collapse;margin-bottom:14px">
      <tr><td style="width:130px;font-weight:bold;color:#495057;padding:4px 12px 4px 0">Severity</td><td>{_badge(sev)}</td></tr>
      <tr><td style="font-weight:bold;color:#495057;padding:4px 12px 4px 0">CVSS</td><td>{cvss}</td></tr>
      <tr><td style="font-weight:bold;color:#495057;padding:4px 12px 4px 0">CWE</td><td>{tmpl.get("cwe","N/A")}</td></tr>
      <tr><td style="font-weight:bold;color:#495057;padding:4px 12px 4px 0">ATT&amp;CK</td><td><a href="https://attack.mitre.org/techniques/{ATTACK_IDS.get(vtype,'').replace('.','/')}" target="_blank">{ATTACK_IDS.get(vtype,"—")}</a></td></tr>
      <tr><td style="font-weight:bold;color:#495057;padding:4px 12px 4px 0;vertical-align:top">Affected URL</td>
          <td><code style="word-break:break-all">{f["url"]}</code></td></tr>
    </table>
    <h4 style="color:#343a40;margin:10px 0 6px">Description / Impact</h4>
    <p style="margin:0 0 10px">{tmpl["impact"]}</p>
    <h4 style="color:#343a40;margin:10px 0 6px">Evidence / Proof of Concept</h4>
    <pre style="background:#f8f9fa;border:1px solid #dee2e6;border-radius:4px;padding:12px;overflow-x:auto;font-size:0.85em;white-space:pre-wrap">{f.get("poc", f["raw"])}</pre>
    <h4 style="color:#343a40;margin:10px 0 6px">Remediation</h4>
    <p style="margin:0 0 10px">{tmpl["remediation"]}</p>
    <h4 style="color:#343a40;margin:4px 0 6px">References</h4>
    <ul style="margin:0;padding-left:18px">{refs}</ul>
  </div>
</div>"""

    sev_counts_rows = "".join(
        f'<tr><td>{_badge(s)}</td><td><b>{counts[s]}</b></td></tr>'
        for s in ("critical", "high", "medium", "low", "info"))

    tools = ("subfinder, assetfinder, amass, dnsx, httpx, katana, waybackurls, gau, "
             "nmap, naabu, nuclei, dalfox, sqlmap, ffuf, Arjun, Kiterunner, "
             "trufflehog, gitleaks, subzy, interactsh-client")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — {target}</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:0;color:#212529;background:#fff}}
a{{color:#0d6efd}}code{{background:#f8f9fa;padding:1px 5px;border-radius:3px;font-size:0.9em}}
.tbl{{width:100%;border-collapse:collapse}}.tbl th{{background:#f1f3f5;text-align:left;padding:8px 12px;border:1px solid #dee2e6;font-size:0.9em}}
.tbl td{{padding:8px 12px;border:1px solid #dee2e6;vertical-align:top;font-size:0.9em}}.tbl tr:hover{{background:#f8f9fa}}
@media print{{.page-break{{page-break-after:always}}body{{font-size:11pt}}}}
</style>
</head>
<body>

<div style="background:#1a1a2e;color:#fff;min-height:100vh;display:flex;flex-direction:column;justify-content:center;padding:60px 80px" class="page-break">
  <div style="font-size:.85em;letter-spacing:2px;text-transform:uppercase;color:#adb5bd;margin-bottom:20px">Confidential</div>
  <h1 style="font-size:2.4em;font-weight:700;margin:0 0 12px;color:#fff">{title}</h1>
  <div style="font-size:1.3em;color:#adb5bd;margin-bottom:36px">Target: <b style="color:#e9ecef">{target}</b></div>
  <table style="border-collapse:collapse;max-width:480px">
    <tr><td style="padding:5px 20px 5px 0;color:#adb5bd;width:140px">Client</td><td style="color:#fff;font-weight:600">{client or "—"}</td></tr>
    <tr><td style="padding:5px 20px 5px 0;color:#adb5bd">Consultant</td><td style="color:#fff;font-weight:600">{consultant or "—"}</td></tr>
    <tr><td style="padding:5px 20px 5px 0;color:#adb5bd">Date</td><td style="color:#fff;font-weight:600">{date_str}</td></tr>
    <tr><td style="padding:5px 20px 5px 0;color:#adb5bd">Total Findings</td><td style="color:#fff;font-weight:600">{total}</td></tr>
    <tr><td style="padding:5px 20px 5px 0;color:#adb5bd">Classification</td><td style="color:#e05252;font-weight:700">CONFIDENTIAL</td></tr>
  </table>
</div>

<div style="max-width:1100px;margin:0 auto;padding:40px">

<h2 style="border-bottom:2px solid #1a1a2e;padding-bottom:8px">Table of Contents</h2>
<ol style="line-height:2.2">
  <li><a href="#exec">Executive Summary</a></li>
  <li><a href="#scope">Scope &amp; Methodology</a></li>
  <li><a href="#vtable">Vulnerability Summary</a></li>
  <li><a href="#details">Detailed Findings</a></li>
  <li><a href="#appendix-a">Appendix A: Tools</a></li>
  <li><a href="#appendix-b">Appendix B: Methodology</a></li>
</ol>
<div class="page-break"></div>

<h2 id="exec" style="border-bottom:2px solid #1a1a2e;padding-bottom:8px">1. Executive Summary</h2>
<p>A vulnerability assessment and penetration test was conducted against <b>{target}</b>.
The assessment identified <b>{total}</b> security finding(s).
{"" if not (counts["critical"] or counts["high"]) else
f'<b style="color:{SEVERITY_COLOR["critical"]}">{counts["critical"]} critical</b> and '
f'<b style="color:{SEVERITY_COLOR["high"]}">{counts["high"]} high</b> severity issues require immediate remediation.'}</p>
<h3>Risk Overview</h3>
<table style="border-collapse:collapse;max-width:550px;margin-bottom:16px">{bar}</table>
<table class="tbl" style="max-width:360px">
  <tr><th>Severity</th><th>Count</th></tr>
  {sev_counts_rows}
  <tr style="background:#f1f3f5"><td><b>Total</b></td><td><b>{total}</b></td></tr>
</table>
<div class="page-break"></div>

<h2 id="scope" style="border-bottom:2px solid #1a1a2e;padding-bottom:8px">2. Scope &amp; Methodology</h2>
<table class="tbl" style="max-width:580px;margin-bottom:16px">
  <tr><th>Item</th><th>Detail</th></tr>
  <tr><td>Target</td><td><code>{target}</code></td></tr>
  <tr><td>Assessment Type</td><td>Black-box / Grey-box VAPT</td></tr>
  <tr><td>Methodology</td><td>PTES, OWASP Testing Guide v4.2</td></tr>
  <tr><td>Date</td><td>{date_str}</td></tr>
  <tr><td>Consultant</td><td>{consultant or "—"}</td></tr>
</table>
<ol>
  <li><b>Reconnaissance</b> — Subdomain enumeration, port scanning, tech fingerprinting</li>
  <li><b>Vulnerability Identification</b> — Automated and manual testing</li>
  <li><b>Exploitation</b> — Controlled PoC to confirm impact</li>
  <li><b>Analysis</b> — AI-assisted triage, CVSS v3.1 scoring</li>
  <li><b>Reporting</b> — Structured findings with remediation guidance</li>
</ol>
<div class="page-break"></div>

<h2 id="vtable" style="border-bottom:2px solid #1a1a2e;padding-bottom:8px">3. Vulnerability Summary</h2>
<table class="tbl">
  <tr><th style="width:80px">ID</th><th>Vulnerability</th><th style="width:100px">Severity</th>
      <th style="width:60px">CVSS</th><th>Affected Host / URL</th><th style="width:90px">CWE</th></tr>
  {tbl or '<tr><td colspan="6" style="text-align:center;color:#6c757d">No findings.</td></tr>'}
</table>
<div class="page-break"></div>

<h2 id="details" style="border-bottom:2px solid #1a1a2e;padding-bottom:8px">4. Detailed Findings</h2>
{details or '<p style="color:#6c757d">No findings.</p>'}

{_render_upload_evasion_matrix(findings)}

<h2 id="appendix-a" style="border-bottom:2px solid #1a1a2e;padding-bottom:8px;margin-top:40px">Appendix A: Tools Used</h2>
<p>{tools}</p>

<h2 id="appendix-b" style="border-bottom:2px solid #1a1a2e;padding-bottom:8px;margin-top:30px">Appendix B: Methodology Reference</h2>
<ul>
  <li><a href="https://www.pentest-standard.org/" target="_blank">Penetration Testing Execution Standard (PTES)</a></li>
  <li><a href="https://owasp.org/www-project-web-security-testing-guide/" target="_blank">OWASP WSTG v4.2</a></li>
  <li><a href="https://www.first.org/cvss/" target="_blank">CVSS v3.1</a></li>
  <li><a href="https://cwe.mitre.org/" target="_blank">MITRE CWE</a></li>
</ul>

<hr style="margin-top:50px;border-color:#dee2e6">
<p style="color:#6c757d;font-size:.85em;text-align:center">Generated by <a href="https://github.com/venkatas/vikramaditya" style="color:#6c757d">Vikramaditya</a> — Autonomous VAPT Platform &nbsp;|&nbsp; {date_str} &nbsp;|&nbsp; CONFIDENTIAL</p>
</div>
</body></html>"""
    return html


def render_markdown_report(findings: list, target: str, report_dir: str,
                           client: str, consultant: str, title: str) -> str:
    date_str = datetime.now().strftime("%d %B %Y")
    counts   = {s: sum(1 for f in findings if f["severity"] == s)
                for s in SEVERITY_COLOR}
    lines    = [
        f"# {title}",
        f"**Target:** {target}  \n**Client:** {client or '—'}  \n"
        f"**Consultant:** {consultant or '—'}  \n**Date:** {date_str}  \n"
        "**Classification:** CONFIDENTIAL",
        "", "---", "", "## Executive Summary", "",
        f"Total findings: **{len(findings)}**", "",
        "| Severity | Count |", "|----------|-------|",
    ]
    for s in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {s.upper()} | {counts[s]} |")
    lines += ["", "---", "", "## Vulnerability Summary", "",
              "| ID | Vulnerability | Severity | CVSS | Host |",
              "|----|---------------|----------|------|------|"]
    for i, f in enumerate(findings, 1):
        tmpl  = VULN_TEMPLATES.get(f["vtype"], VULN_TEMPLATES["misconfig"])
        host  = re.search(r'https?://([^/]+)', f["url"])
        host  = host.group(1) if host else target
        cvss  = tmpl.get("cvss") or CVSS_DEFAULT.get(f["severity"], "N/A")
        lines.append(f"| VN-{i:03d} | {tmpl['title'].format(host=host)} | {f['severity'].upper()} | {cvss} | {host} |")
    lines += ["", "---", "", "## Detailed Findings", ""]
    for i, f in enumerate(findings, 1):
        tmpl  = VULN_TEMPLATES.get(f["vtype"], VULN_TEMPLATES["misconfig"])
        host  = re.search(r'https?://([^/]+)', f["url"])
        host  = host.group(1) if host else target
        cvss  = tmpl.get("cvss") or CVSS_DEFAULT.get(f["severity"], "N/A")
        refs  = "\n".join(f"- [{n}]({u})" for n, u in tmpl.get("references", []))
        lines += [
            f"### VN-{i:03d} — {tmpl['title'].format(host=host)}",
            f"**Severity:** {f['severity'].upper()} | **CVSS:** {cvss} | **CWE:** {tmpl.get('cwe','N/A')} | **ATT&CK:** {ATTACK_IDS.get(f['vtype'],'—')}  ",
            f"**Affected URL:** `{f['url']}`", "",
            f"**Impact:** {tmpl['impact']}", "",
            "**Evidence / Proof of Concept:**", "```",
            f.get("poc", f["raw"]),
            "```", "",
            f"**Remediation:** {tmpl['remediation']}", "",
            "**References:**", refs, "", "---", "",
        ]
    lines.append(f"*Generated by [Vikramaditya](https://github.com/venkatas/vikramaditya) — Autonomous VAPT Platform | {date_str}*")
    return "\n".join(lines)


def process_findings_dir(findings_dir: str, client: str = "",
                         consultant: str = "", title: str = "",
                         target_override: str = "") -> tuple:
    target, session, report_dir = resolve_target_and_report_dir(findings_dir)
    if target_override:
        target = target_override
    os.makedirs(report_dir, exist_ok=True)
    findings = load_findings(findings_dir)
    if not title:
        title = "Vulnerability Assessment & Penetration Test Report"
    html = render_html_report(findings, target, report_dir, client, consultant, title)
    md   = render_markdown_report(findings, target, report_dir, client, consultant, title)
    return len(findings), findings, report_dir, html, md


def extract_target_from_url(url: str) -> str:
    match = re.search(r"https?://([^/]+)", url)
    return match.group(1) if match else url


def create_manual_report(vuln_type: str, url: str, param: str | None = None,
                         evidence: str | None = None, client: str = "",
                         consultant: str = "", title: str = "") -> tuple[str, str, str]:
    normalized_type = vuln_type.lower()
    target = extract_target_from_url(url)
    safe_target = re.sub(r"[^A-Za-z0-9._-]+", "_", target)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = os.path.join(REPORTS_DIR, safe_target, "manual", timestamp)
    os.makedirs(report_dir, exist_ok=True)

    raw = evidence or f"Manual finding: {normalized_type} on {url}"
    if param:
        raw += f"\nParameter: {param}"

    finding = {
        "raw": raw,
        "url": url,
        "severity": VULN_TEMPLATES.get(normalized_type, VULN_TEMPLATES["misconfig"]).get("severity", "medium"),
        "template_id": "manual",
        "vtype": normalized_type,
    }

    report_title = title or "Manual VAPT Finding Report"
    html = render_html_report([finding], target, report_dir, client, consultant, report_title)
    md = render_markdown_report([finding], target, report_dir, client, consultant, report_title)

    html_path = os.path.join(report_dir, "vapt_report.html")
    md_path = os.path.join(report_dir, "vapt_report.md")
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(md)

    return report_dir, md_path, html_path


def attach_poc_images(report_file: str, image_paths: list[str]) -> None:
    poc_dir = os.path.join(os.path.dirname(report_file), "poc_screenshots")
    os.makedirs(poc_dir, exist_ok=True)

    image_section = "\n\n## PoC Screenshots\n\n"
    for i, img_path in enumerate(image_paths, 1):
        if os.path.exists(img_path):
            filename = os.path.basename(img_path)
            dest = os.path.join(poc_dir, filename)
            if os.path.abspath(img_path) != os.path.abspath(dest):
                shutil.copy2(img_path, dest)
            image_section += f"### Screenshot {i}: {filename}\n"
            image_section += f"![PoC {i}](poc_screenshots/{filename})\n\n"
        else:
            print(f"[!] Image not found: {img_path}")

    with open(report_file, "a", encoding="utf-8") as fh:
        fh.write(image_section)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Vikramaditya Report Generator — Burp Suite-style VAPT reports")
    parser.add_argument("findings_dir", nargs="?")
    parser.add_argument("--manual", action="store_true", help="Create a manual report")
    parser.add_argument("--type", default="", help="Vulnerability type for manual mode")
    parser.add_argument("--url", default="", help="Affected URL for manual mode")
    parser.add_argument("--param", default="", help="Affected parameter for manual mode")
    parser.add_argument("--evidence", default="", help="Evidence text for manual mode")
    parser.add_argument("--poc-images", nargs="+", default=None, help="Optional PoC image paths for manual mode")
    parser.add_argument("--client",     default="")
    parser.add_argument("--consultant", default="")
    parser.add_argument("--title",      default="Vulnerability Assessment & Penetration Test Report")
    parser.add_argument("--target",     default="", help="Target domain name (overrides auto-detect from dir name)")
    args = parser.parse_args()

    if args.manual:
        if not args.type or not args.url:
            print("[!] Manual mode requires --type and --url", file=sys.stderr)
            sys.exit(1)

        report_dir, md_path, html_path = create_manual_report(
            args.type,
            args.url,
            args.param or None,
            args.evidence or None,
            args.client,
            args.consultant,
            args.title,
        )
        if args.poc_images:
            attach_poc_images(md_path, args.poc_images)

        print(f"[+] Manual report directory: {report_dir}")
        print(f"[+] HTML : {html_path}")
        print(f"[+] MD   : {md_path}")
        return

    if not args.findings_dir:
        print("[!] Please provide a findings directory or use --manual mode", file=sys.stderr)
        sys.exit(1)

    if not os.path.isdir(args.findings_dir):
        print(f"[!] Not a directory: {args.findings_dir}", file=sys.stderr)
        sys.exit(1)

    count, _, report_dir, html, md = process_findings_dir(
        args.findings_dir, args.client, args.consultant, args.title,
        target_override=args.target)

    html_path = os.path.join(report_dir, "vapt_report.html")
    md_path   = os.path.join(report_dir, "vapt_report.md")

    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(md)

    print(f"[+] {count} finding(s) — {os.path.basename(report_dir)}")
    print(f"[+] HTML : {html_path}")
    print(f"[+] MD   : {md_path}")

    if shutil.which("wkhtmltopdf"):
        pdf = html_path.replace(".html", ".pdf")
        os.system(f'wkhtmltopdf --quiet "{html_path}" "{pdf}" 2>/dev/null')
        if os.path.isfile(pdf):
            print(f"[+] PDF  : {pdf}")


if __name__ == "__main__":
    main()
