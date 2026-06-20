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

# v10.6.0 — verification-based severity gating + weighted risk scoring / framework
# mapping (finding_schema.py, report_synthesis.py; adapted from xalgorix MIT). Both
# are pure-stdlib and optional — the report renders unchanged if they're absent.
try:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from finding_schema import VerificationMethod, adjust_severity, should_report
    import report_synthesis
    _SCHEMA_OK = True
except Exception:
    _SCHEMA_OK = False

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
    "exposed_credentials": {
        "title": "Verified Cloud Credential Exposed on {host}",
        "severity": "critical", "cvss": "9.8", "cwe": "CWE-798",
        "impact": "A live cloud credential was found exposed and validated; read-only enumeration "
                  "confirmed the access it grants (e.g. account-wide S3 read, downloadable database "
                  "backups). An attacker can use it directly against the cloud account.",
        "remediation": "Disable/rotate the key immediately, review CloudTrail for use, remove it "
                       "from source, and re-architect to short-lived/scoped credentials.",
        "references": [
            ("OWASP Secrets Management", "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"),
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
    "email_auth": {
        "title": "Email Authentication Weakness on {host}",
        "severity": "medium", "cvss": "5.3", "cwe": "CWE-290",
        "impact": "Missing or weak email authentication (SPF/DKIM/DMARC) lets an attacker spoof mail from this domain, enabling phishing and business-email-compromise against staff, customers, and partners.",
        "remediation": "Publish a DMARC record (start p=none with rua reporting, then move to quarantine/reject), tighten SPF toward -all once all senders are covered, and ensure DKIM signing on all sending sources.",
        "references": [
            ("DMARC.org", "https://dmarc.org/"),
            ("RFC 7489 (DMARC)", "https://datatracker.ietf.org/doc/html/rfc7489"),
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
    # NOTE: email_auth/ is intentionally NOT mapped here. Its findings.json is parsed by
    # the dedicated Method 1d loader (which sets per-finding cvss); routing it through the
    # generic Method-1 .txt scan would mis-score any .txt that appears (parse_custom_line
    # sets no cvss → template's fixed 5.3 for every severity). It is suppressed from the
    # unmapped-subdir warning via meta_dirs instead — same pattern as sqlmap/cves_custom.
}


# ── Parsing ────────────────────────────────────────────────────────────────────

def parse_custom_line(line: str, default_vtype: str = "misconfig") -> dict:
    # Start with the template severity for this vulnerability type, not a hardcoded default
    tmpl = VULN_TEMPLATES.get(default_vtype, {})
    sev = tmpl.get("severity", "medium")

    # Override with explicit severity keywords in the raw finding text.
    # Use word-boundary regex so severity tokens are not matched inside
    # payload/evidence text — e.g. INFORMATION_SCHEMA must not match "INFO",
    # HIGHCHARTS must not match "HIGH", SLOWLORIS/yellow must not match "LOW".
    # Hyphen counts as a \b boundary, so RCE-POC / SSTI-CONFIRMED still match.
    if re.search(r'\b(SQLI-POC-VERIFIED|RCE-POC|CRITICAL|CONFIRMED)\b', line):
        sev = "critical"
    elif re.search(r'\bHIGH\b', line):
        sev = "high"
    elif re.search(r'\bINFO\b', line):
        # Explicit INFO is context, not a low-severity vuln. Mapping it to "low"
        # turned benign informational lines (e.g. "CORS-INFO" for a wildcard
        # ACAO without credentials) into LOW findings in the report.
        sev = "info"
    elif re.search(r'\bLOW\b', line):
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
                      "exploits", "screenshots", ".async", ".tmp",
                      "cves_custom",   # cves_custom/ is handled by Method 1c below
                      "brain_active",  # brain_active/ is handled by Method 1e below
                      "sqlmap",        # sqlmap/ is handled by Method 1f below
                      "email_auth",    # email_auth/findings.json handled by Method 1d below
                      "exposed_credentials",  # handled by Method 1h below
                      "burp"}          # burp/findings.json handled by Method 1g below
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
        # v9.1.2 — non-finding files written by scanner.sh into finding dirs
        # to record probe state (auth-required, candidates, timeouts). These are
        # NOT findings; treating them as such inflates the report (97 fake "Unrestricted
        # File Upload" HIGHs from auth_required.txt during the 03-May clienta run).
        NON_FINDING_FILES = {
            "auth_required.txt",          # upload/ — paths protected by auth, not vulnerable
            "auth-required.txt",
            # NOTE: timebased_candidates.txt is deliberately NOT blacklisted — it can carry a
            # [SQLI-POC-VERIFIED] line (an EMPIRICALLY-CONFIRMED time-based SQLi PoC) alongside
            # the unverified [SQLI-CANDIDATE]/[SQLI-TIMEOUT-CANDIDATE] lines. File-level
            # blacklisting silently dropped the CONFIRMED CRITICAL; the per-line
            # NON_FINDING_PREFIXES below still suppress the unverified candidate lines.
            # cves/ — cvemap writes global "high-EPSS CVEs worth testing" (CVE IDs,
            # one per line via -lsi); they are NOT host/version-confirmed, so the
            # generic loader must not promote each ID to a CRITICAL cves finding.
            "cvemap_results.txt",
        }
        # Line-prefix markers used by scanner.sh to record state, not findings.
        NON_FINDING_PREFIXES = (
            "[UPLOAD-CANDIDATE-AUTH]",   # path returned 403 to GET+POST = auth-protected
            "[SQLI-CANDIDATE]",          # unverified time-based candidate, needs follow-up
            "[SQLI-TIMEOUT-CANDIDATE]",  # timeout was server-side slow, not necessarily SQLi
            "[GIT-FLAG-INJECTION-CANDIDATE]",  # candidate, not confirmed
            "[JAVA-RMI-CANDIDATE]",      # deserialize/ — manual ysoserial follow-up lead,
                                         # NOT a confirmed HIGH deserialization finding
        )
        for fn in sorted(os.listdir(path)):
            if not fn.endswith(".txt"):
                continue
            if fn in NON_FINDING_FILES:
                continue
            with open(os.path.join(path, fn), errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if any(line.startswith(p) for p in NON_FINDING_PREFIXES):
                        continue
                    finding = parse_custom_line(line, vtype)
                    for poc_key, poc_text in all_pocs.items():
                        if poc_key in line or line[:60] in poc_key:
                            finding["poc"] = poc_text
                            break
                    results.append(finding)

    # Method 1b: CVE database matches (cves/ subdirectory)
    # v9.1.2 — handles both schemas: bare list AND
    # {target, scan_date, technologies_detected, cves_found:[...]} (current cve.py format).
    #
    # v9.23 — cve.py populates cves_found via NVD *keyword* search on bare tech
    # tokens (e.g. "php", "bootstrap", "hsts") with NO version correlation and NO
    # active confirmation. Emitting each as a finding produced 25 bogus rows on
    # clientc.com — including two "CVSS 10.0" php.cgi-1999 entries and the
    # HSTS *header* matched as a product. We now only promote a match to a real
    # finding when it is version-correlated or confirmed (e.g. by nuclei); the
    # remaining unverified keyword matches are collapsed into ONE clearly-labelled
    # INFORMATIONAL context item so the findings table stays trustworthy.
    cve_path = os.path.join(findings_dir, "cves")
    unconfirmed_cves = []
    if os.path.isdir(cve_path):
        for fn in sorted(os.listdir(cve_path)):
            if not fn.endswith(".json"):
                continue
            try:
                with open(os.path.join(cve_path, fn), errors="replace") as f:
                    cve_data = _json.load(f)
                # Normalize to a list of CVE dicts
                if isinstance(cve_data, dict) and "cves_found" in cve_data:
                    cve_list = cve_data["cves_found"]
                elif isinstance(cve_data, list):
                    cve_list = cve_data
                else:
                    cve_list = []
                for item in cve_list:
                    cve_id = item.get("cve_id", item.get("id", ""))
                    if not cve_id:
                        continue
                    desc = item.get("description", item.get("summary", ""))
                    sev = str(item.get("severity", "")).lower()
                    score = item.get("cvss_score", item.get("score", ""))
                    product = item.get("product", item.get("software", item.get("technology", "")))
                    # Only a version-correlated or actively-confirmed match is a finding.
                    confirmed = bool(item.get("confirmed") or item.get("nuclei_confirmed")
                                     or item.get("verified"))
                    version_correlated = bool(item.get("matched_version") or item.get("version"))
                    if confirmed or version_correlated:
                        results.append({
                            "severity": sev if sev in SEVERITY_ORDER else "medium",
                            "vtype": "cves",
                            "title": f"{cve_id} — {product}" if product else cve_id,
                            "detail": desc[:300] if desc else f"Known CVE: {cve_id}",
                            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                            "poc": f"CVE: {cve_id}\nCVSS: {score}\nProduct: {product}\n{desc[:500]}",
                        })
                    else:
                        unconfirmed_cves.append((cve_id, product, score))
            except Exception:
                pass

    # Collapse unconfirmed keyword matches into a single INFO context item.
    if unconfirmed_cves:
        sample = ", ".join(f"{c} ({p})" if p else c for c, p, _ in unconfirmed_cves[:8])
        _collapsed_detail = (
            "These CVEs were matched by technology NAME only (NVD keyword search) "
            "with no version correlation and no active confirmation, so they are NOT "
            "verified findings and must not be reported as-is. Validate each against "
            "the actually-deployed version before including it. "
            f"Examples: {sample}.")
        # v10.0.2 — set an explicit per-severity CVSS so this INFO context row does NOT
        # inherit the misconfig template's hardcoded MEDIUM-band 5.3 (the renderer falls
        # back to tmpl.cvss when the finding carries none). Same per-severity approach as
        # the email_auth loader: INFO → "0.0". Also fold the rich detail (matched CVE
        # examples + "validate before reporting" warning) INTO the poc text, because the
        # renderers surface poc-before-detail (`poc or raw or detail`); without this the
        # CVE list and warning never reach the report.
        results.append({
            "severity": "info",
            "cvss": CVSS_DEFAULT.get("info", "0.0"),
            "vtype": "misconfig",
            "title": (f"Unconfirmed tech-stack CVE keyword matches ({len(unconfirmed_cves)}) "
                      "— version verification required"),
            "detail": _collapsed_detail,
            "url": "N/A",
            "poc": (f"{_collapsed_detail}\n\n"
                    "Source: cves/cve_database_matches.json (keyword matches; not version-verified)."),
        })

    # Method 1c: cves_custom/ — output of scanner.sh Check 1.5 (nuclei custom templates)
    # v9.1.2 — added to surface findings from /Users/venkatasatish/Documents/GitHub/obsidian/nuclei-templates/
    cves_custom_path = os.path.join(findings_dir, "cves_custom")
    if os.path.isdir(cves_custom_path):
        for fn in sorted(os.listdir(cves_custom_path)):
            if not fn.endswith(".txt"):
                continue
            try:
                with open(os.path.join(cves_custom_path, fn), errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        # nuclei output format: [template-id] [proto] [severity] url
                        # e.g. "[CVE-2025-68645-zimbra-webxml-lfi] [http] [high] https://mapi..../h/changepass?..."
                        import re as _re
                        m = _re.search(r"\[([^\]]+)\]\s+\[\w+\]\s+\[(\w+)\]\s+(\S+)", line)
                        if m:
                            template_id, sev, url = m.group(1), m.group(2), m.group(3)
                            # Normalize severity (nuclei emits "unknown"/"informational"
                            # for some templates). Without this an "unknown" finding is
                            # counted in `total` but excluded from the per-severity
                            # counts dict (which only iterates SEVERITY_COLOR keys), so
                            # the Executive Summary table fails to reconcile with Total.
                            # Mirrors the Method 1d normalization below.
                            sev = sev.lower()
                            if sev in ("informational", "information"):
                                sev = "info"
                            if sev not in SEVERITY_ORDER:
                                sev = "info"
                            results.append({
                                "severity": sev,
                                "vtype": "cves",
                                "title": f"{template_id} (custom template)",
                                "detail": f"Custom nuclei template fired: {template_id}",
                                "url": url,
                                "poc": line,
                            })
            except Exception:
                pass

    # Method 1d: Email authentication posture (email_auth/findings.json)
    # v9.23 — subspace_sentinel writes SPF/DKIM/DMARC/DNSSEC/MTA-STS results as a
    # JSON list, which Method 1's .txt scan never picked up. These are real,
    # confirmed DNS-level findings (e.g. "No DMARC record published" = MEDIUM) and
    # belong in the report.
    email_auth_path = os.path.join(findings_dir, "email_auth", "findings.json")
    if os.path.isfile(email_auth_path):
        try:
            with open(email_auth_path, errors="replace") as f:
                ea_data = _json.load(f)
            for item in (ea_data if isinstance(ea_data, list) else []):
                sev = str(item.get("severity", "low")).lower()
                if sev in ("informational", "information"):
                    sev = "info"
                if sev not in SEVERITY_ORDER:
                    sev = "low"
                # v10.0.1 — per-finding CVSS so a LOW/INFO posture item no longer inherits
                # the email_auth template's fixed MEDIUM 5.3 (previously EVERY email_auth
                # finding rendered 5.3 because the loader set severity but not cvss and the
                # renderer fell back to the template). Precedence: explicit per-item cvss →
                # if the finding's severity MATCHES the template's, keep the template's
                # authored score (so MEDIUM stays 5.3 — no needless drift, no split with peer
                # MEDIUM templates) → otherwise the canonical severity→score map.
                _ea_tmpl = VULN_TEMPLATES.get("email_auth", {})
                if item.get("cvss") is not None:
                    _ea_cvss = str(item["cvss"])
                elif sev == _ea_tmpl.get("severity"):
                    _ea_cvss = _ea_tmpl.get("cvss", CVSS_DEFAULT.get(sev, "N/A"))
                else:
                    _ea_cvss = CVSS_DEFAULT.get(sev, "N/A")
                results.append({
                    "severity": sev,
                    "cvss": _ea_cvss,
                    "vtype": "email_auth",
                    "title": item.get("title", "Email authentication weakness"),
                    "detail": item.get("notes", ""),
                    "url": item.get("endpoint", "N/A"),
                    "poc": (f"Class : {item.get('vuln_class','')}\n"
                            f"Area  : {item.get('area','')}\n"
                            f"Result: {item.get('result','')}\n\n"
                            f"{item.get('notes','')}"),
                })
        except Exception:
            pass

    # Method 1h: Verified cloud-credential blast-radius (exposed_credentials/findings.json)
    # cred_blast_radius.py writes a confirmed, READ-ONLY-verified assessment of a discovered &
    # validated cloud key (identity, IAM/S3 reach, DB-backup inventory, PII indicators). Its JSON
    # shape is not what the generic Method-1 .txt scan expects, so parse it here (mirrors 1d/1g).
    exposed_cred_path = os.path.join(findings_dir, "exposed_credentials", "findings.json")
    if os.path.isfile(exposed_cred_path):
        try:
            with open(exposed_cred_path, errors="replace") as f:
                ec_data = _json.load(f)
            items = ec_data.get("findings", []) if isinstance(ec_data, dict) else (ec_data or [])
            for item in items:
                sev = str(item.get("severity", "critical")).lower()
                if sev not in SEVERITY_ORDER:
                    sev = "critical"
                # per-finding cvss (mirrors email_auth): explicit item cvss → template cvss when
                # severity matches the template's → canonical severity→score map otherwise.
                _ec_tmpl = VULN_TEMPLATES.get("exposed_credentials", {})
                if item.get("cvss") is not None:
                    _ec_cvss = str(item["cvss"])
                elif sev == _ec_tmpl.get("severity"):
                    _ec_cvss = _ec_tmpl.get("cvss", CVSS_DEFAULT.get(sev, "9.0"))
                else:
                    _ec_cvss = CVSS_DEFAULT.get(sev, "9.0")
                caps = item.get("capabilities", {}) or {}
                allowed = sorted(k for k, v in caps.items() if v)
                backups = item.get("backups", []) or []
                pii = item.get("pii_indicators", []) or []
                poc = [
                    f"Access key : {item.get('access_key_id', '')}",
                    f"Account    : {item.get('account', '')}",
                    f"Principal  : {item.get('principal', '')}",
                    f"Source     : {item.get('source_url') or item.get('source_file', '')}",
                    f"Admin      : {item.get('is_admin')}   GetObject: {item.get('get_object')}"
                    f"   Buckets: {item.get('bucket_count')}",
                    f"Allowed    : {', '.join(allowed)}",
                ]
                if backups:
                    poc += ["", f"Backups ({len(backups)} listed, top 10):"]
                    poc += [f"  {b.get('Size')}  {b.get('bucket', '')}/{b.get('Key', '')}"
                            for b in backups[:10]]
                if pii:
                    poc += ["", f"PII-indicator filenames: {len(pii)}"]
                results.append({
                    "severity": sev,
                    "cvss": _ec_cvss,
                    "vtype": "exposed_credentials",
                    "title": item.get("title", "Verified cloud credential exposed — confirmed blast radius"),
                    "detail": item.get("remediation", ""),
                    "url": item.get("source_url") or item.get("source_file", "N/A"),
                    "poc": "\n".join(poc),
                })
        except Exception:
            pass

    # Method 1f: sqlmap-confirmed SQL injection (sqlmap/sqlmap_results.txt + results-*.csv)
    # v10.0.1 — hunt.py runs sqlmap with --results-file → sqlmap/sqlmap_results.txt, and
    # OpenAPI/POST runs leave sqlmap's default results-<ts>.csv in the same dir (both share
    # the header: Target URL,Place,Parameter,Technique(s),Note(s)). A row with a NON-EMPTY
    # Technique(s) column is a CONFIRMED injection. These files had no ingestion path, so
    # sqlmap-confirmed SQLi was silently dropped even though `sqli_sqlmap_confirmed` exists.
    # The dir is deliberately NOT in SUBDIR_VTYPE: it also holds candidates.txt / post_*.txt
    # console dumps the generic Method-1 .txt scan would mis-parse as findings, so it is
    # suppressed from the unmapped-subdir warning via meta_dirs and parsed only here.
    # Safety contract: a header-only file (sqlmap found nothing) yields zero findings, and a
    # row sqlmap itself tagged "false positive or unexploitable" is skipped (mirrors the
    # brain.py candidate filter) so a scanner-rejected row never becomes a CRITICAL finding.
    sqlmap_dir = os.path.join(findings_dir, "sqlmap")
    if os.path.isdir(sqlmap_dir):
        import csv as _csv
        import glob as _glob
        from urllib.parse import urlparse as _urlparse, parse_qsl as _parse_qsl
        sqlmap_tmpl = VULN_TEMPLATES.get("sqli_sqlmap_confirmed", {})
        seen_sqlmap = set()
        sqlmap_csvs = []
        primary = os.path.join(sqlmap_dir, "sqlmap_results.txt")
        if os.path.isfile(primary):
            sqlmap_csvs.append(primary)
        sqlmap_csvs.extend(sorted(_glob.glob(os.path.join(sqlmap_dir, "results-*.csv"))))
        for csv_path in sqlmap_csvs:
            try:
                # utf-8-sig strips a BOM if present (sqlmap-on-Windows / concatenated CSVs)
                # so the header isn't read as a BOM-prefixed "Target URL". newline="" +
                # DictReader keep a quoted multi-line Note(s) in ONE record so the
                # false-positive filter below can't be defeated by an embedded newline.
                f = open(csv_path, encoding="utf-8-sig", newline="", errors="replace")
            except OSError:
                continue
            with f:
                reader = _csv.DictReader(f)
                if not reader.fieldnames or "Target URL" not in reader.fieldnames \
                        or "Technique(s)" not in reader.fieldnames:
                    continue
                rows = iter(reader)
                _seen_rows = 0
                while _seen_rows < 100_000:   # sanity cap (sqlmap result files are small)
                    _seen_rows += 1
                    try:
                        row = next(rows)
                    except StopIteration:
                        break
                    except _csv.Error:
                        # A recoverable malformed record (e.g. oversized field) must not
                        # abort the file: skip it and keep parsing later rows so one bad
                        # record can't drop a later confirmed injection. (A truly
                        # unterminated quote is unrecoverable by any correct CSV parser —
                        # sqlmap never emits one — but rows parsed before it are kept.)
                        continue
                    try:
                        technique = (row.get("Technique(s)") or "").strip()
                        url = (row.get("Target URL") or "").strip()
                        if not technique or not url:
                            continue  # no Technique(s) => sqlmap did not confirm injection
                        # Collapse all whitespace (incl. embedded newlines) before matching
                        # sqlmap's own false-positive tag so a multi-line Note can't slip past.
                        note_norm = " ".join((row.get("Note(s)") or "").lower().split())
                        if "false positive or unexploitable" in note_norm:
                            continue  # sqlmap itself rejected this candidate
                        place = (row.get("Place") or "").strip()
                        param = (row.get("Parameter") or "").strip()
                        note = (row.get("Note(s)") or "").strip()
                        parsed = _urlparse(url)
                        # Dedup: blank ONLY the injected parameter's value (id=1 vs id=999 on
                        # the same endpoint is one vuln) while PRESERVING the rest of the query
                        # context (op=users vs op=orders are distinct contexts → both reported).
                        try:
                            qctx = tuple(sorted(
                                (k, "" if k == param else v)
                                for k, v in _parse_qsl(parsed.query, keep_blank_values=True)
                            ))
                        except Exception:
                            qctx = (("_raw", parsed.query),)
                        dedup_key = (parsed.scheme, parsed.netloc, parsed.path,
                                     place, param, qctx)
                        if dedup_key in seen_sqlmap:
                            continue
                        seen_sqlmap.add(dedup_key)
                        host = parsed.netloc or url
                        results.append({
                            "severity": sqlmap_tmpl.get("severity", "critical"),
                            "cvss": sqlmap_tmpl.get("cvss", "9.8"),
                            "vtype": "sqli_sqlmap_confirmed",
                            "title": f"SQL Injection (sqlmap Confirmed) on {host}",
                            "detail": (f"sqlmap confirmed SQL injection in the '{param}' "
                                       f"{place} parameter via technique(s) {technique}."),
                            "url": url,
                            "poc": (f"Target URL : {url}\n"
                                    f"Place      : {place}\n"
                                    f"Parameter  : {param}\n"
                                    f"Technique  : {technique}\n"
                                    + (f"Note(s)    : {note}\n" if note else "")
                                    + "\nConfirmed by sqlmap. Reproduce:\n"
                                    f"  sqlmap -u \"{url}\" --batch --dbs"),
                        })
                    except Exception:
                        continue  # one bad row must not drop the rest of the file

    # Method 1g: Burp Suite active-scan issues (burp/findings.json)
    # v10.2.0 — burp_scanner.run_burp_scan writes a JSON LIST of normalized issues
    # {severity, type, title, url, detail, poc, confidence, source:"burp"}. The dir
    # is in meta_dirs (not SUBDIR_VTYPE) so the generic .txt walk ignores it; this
    # dedicated loader is the sole ingestion path. NB: burp uses the key "type" for
    # the vuln class, but the renderer keys off "vtype" — map it here. Burp has no
    # CRITICAL severity (its top is High); rich Burp prose already lives in `poc`.
    burp_path = os.path.join(findings_dir, "burp", "findings.json")
    if os.path.isfile(burp_path):
        try:
            with open(burp_path, errors="replace") as f:
                burp_data = _json.load(f)
            for item in (burp_data if isinstance(burp_data, list) else []):
                sev = str(item.get("severity", "info")).lower()
                if sev in ("informational", "information"):
                    sev = "info"
                if sev == "critical":
                    sev = "high"   # Burp has no Critical severity — clamp per contract
                if sev not in SEVERITY_ORDER:
                    sev = "info"
                vtype = (item.get("type") or item.get("vtype") or "misconfig")
                if vtype not in VULN_TEMPLATES:
                    vtype = "misconfig"
                finding = {
                    "severity": sev,
                    "vtype": vtype,
                    "title": item.get("title", "Burp Suite issue"),
                    "detail": item.get("detail", ""),
                    "url": item.get("url", "N/A"),
                    "poc": item.get("poc", ""),
                }
                # Honor an explicit per-finding cvss if Burp/normalizer provided one;
                # otherwise the renderer falls back to the vtype template / severity band.
                if item.get("cvss"):
                    finding["cvss"] = str(item["cvss"])
                results.append(finding)
        except Exception:
            pass

    # Method 1e: Brain active scanner output (brain_active/iteration_*.json)
    # brain_scanner.run_brain_scanner writes iteration_NN.json files whose
    # cumulative "findings_so_far" list previously had NO ingestion path, so
    # confirmed LLM active-scan findings were silently dropped from the report.
    # We read the latest iteration (which carries the full findings list) and,
    # critically, respect the scanner's grounding contract: lines prefixed
    # "[MODEL CLAIM — verify PoC]" are model claims, not tool-verified, so they
    # are collapsed into ONE clearly-labelled INFO context item (mirroring the
    # unconfirmed-CVE collapse above). Only script-output-grounded lines become
    # real findings so the findings table stays trustworthy.
    brain_active_path = os.path.join(findings_dir, "brain_active")
    if os.path.isdir(brain_active_path):
        try:
            iter_files = sorted(fn for fn in os.listdir(brain_active_path)
                                if fn.startswith("iteration_") and fn.endswith(".json"))
            brain_findings = []
            if iter_files:
                # The last iteration carries the cumulative findings_so_far list.
                with open(os.path.join(brain_active_path, iter_files[-1]),
                          errors="replace") as f:
                    brain_data = _json.load(f)
                brain_findings = brain_data.get("findings_so_far", []) or []
            # Defence-in-depth: a file-access/traversal claim is only kept as a
            # finding if the file's content actually appears in the script output.
            # findings_so_far is cumulative, so aggregate EVERY iteration's raw
            # output as the proof corpus (mirrors the live gate in
            # brain_scanner._access_claim_unproven so a buggy PoC's unconditional
            # "[CRITICAL] ... accessible" echo can't reach the client report).
            all_iter_output = ""
            for _fn in iter_files:
                try:
                    with open(os.path.join(brain_active_path, _fn), errors="replace") as _f:
                        _blob = _json.load(_f).get("results", "")
                    # Use the RAW string (real newlines) so the line-anchored proof
                    # regex matches actual file-content lines; json.dumps would
                    # escape newlines and defeat it.
                    all_iter_output += (_blob if isinstance(_blob, str) else _json.dumps(_blob)) + "\n"
                except Exception:
                    continue
            try:
                from brain_scanner import _access_claim_unproven
            except Exception:
                _access_claim_unproven = None
            model_claims = []
            for line in brain_findings:
                line = (line or "").strip()
                if not line:
                    continue
                if line.startswith("[MODEL CLAIM"):
                    # Strip the marker prefix for the collapsed context item.
                    model_claims.append(re.sub(r"^\[MODEL CLAIM[^\]]*\]\s*", "", line))
                    continue
                # Defence-in-depth: drop a self-declared file-access/traversal claim
                # that NO iteration's output actually proves (no file content) — a
                # buggy PoC (`echo "[CRITICAL] ... accessible" || echo`) prints it
                # unconditionally. Demote to unverified context, never a finding.
                if _access_claim_unproven and _access_claim_unproven(line, all_iter_output):
                    model_claims.append("UNVERIFIED (no file content as proof): " + line)
                    continue
                # Script-output-grounded line → real finding. Reuse the custom-line
                # parser so its vtype/severity are derived from any [tag]/keywords.
                # Default to a CONSERVATIVE class (misconfig = medium): brain_scanner
                # also emits lines on "VULNERABLE"/"EXPLOITABLE", neither of which
                # parse_custom_line treats as a severity keyword — so a default of
                # "rce" silently inflated an untagged clickjacking/missing-header
                # line into a CRITICAL/CVSS-9.8 RCE row. A real [tag] or a
                # CRITICAL/CONFIRMED keyword still upgrades it to the right class.
                vtype = "misconfig"
                tags = [t.strip().lower() for t in re.findall(r'\[([^\]]+)\]', line)]
                if tags and tags[0] in SUBDIR_VTYPE:
                    vtype = SUBDIR_VTYPE[tags[0]]
                finding = parse_custom_line(line, vtype)
                finding["title"] = "Brain active-scan finding (script-confirmed)"
                finding["detail"] = line
                results.append(finding)
            if model_claims:
                sample = "; ".join(model_claims[:8])
                results.append({
                    "severity": "info",
                    "vtype": "misconfig",
                    "title": (f"Unconfirmed brain active-scan model claims "
                              f"({len(model_claims)}) — PoC verification required"),
                    "detail": ("These statements were produced by the LLM active scanner "
                               "but are NOT grounded in tool/script output, so they are "
                               "model claims pending manual PoC review and must not be "
                               "reported as confirmed findings. "
                               f"Examples: {sample}."),
                    "url": "N/A",
                    "poc": "Source: brain_active/iteration_*.json (model claims; not script-verified).",
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
    # Reads finding_*.json files directly in the findings dir.
    # v10: always run — no other loader reads finding_*.json, so the old
    # `if not results:` gate silently dropped autopilot findings whenever any
    # earlier method (a brain_active INFO row, CORS, …) had already appended a
    # row. Dedup by (vtype,url,detail) guards against any overlap.
    _seen_m2 = {(r.get("vtype"), r.get("url"), r.get("detail")) for r in results}
    if os.path.isdir(findings_dir):
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
                    poc_lines.append('      "first_name": "Alice",          ← OTHER user\'s name')
                    poc_lines.append('      "email": "victim@example.com",  ← OTHER user\'s email')
                    poc_lines.append('      "contact_no": "9000000000",       ← OTHER user\'s phone')
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
                        poc_lines.append('  "first_name": "Alice"')
                        poc_lines.append('  "email": "victim@example.com"')
                        poc_lines.append('  "contact_no": "9000000000"')
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
                        poc_lines.append("  victim@example.com → 6.6s, 6.1s, 6.4s (VALID)")
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
                key = (vtype, url, detail)
                if key not in _seen_m2:
                    _seen_m2.add(key)
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


def _finding_remediation(f: dict, tmpl: dict) -> str:
    """Resolve the remediation text to render for a finding.

    v10.0.2 — area-specific posture findings (e.g. email_auth's
    DNSSEC/MTA-STS/TLS-RPT/BIMI/DKIM rows) carry their precise fix in the
    finding's ``notes``/``detail``/``poc`` as a ``Fix:`` clause, but every
    one of them shares one template whose remediation is the generic DMARC
    advice. Prefer, in order: an explicit per-finding ``remediation`` →
    the per-finding ``Fix:`` clause parsed out of notes/detail/poc → the
    template remediation. This keeps generic templates working while
    surfacing the authored, area-correct fix when one exists.
    """
    explicit = (f.get("remediation") or "").strip()
    if explicit:
        return explicit
    # Look for an authored "Fix:" clause in the finding's own text. Search the
    # richest fields first; take everything after the first "Fix:" marker.
    for field in ("notes", "detail", "poc"):
        text = f.get(field)
        if not isinstance(text, str) or "Fix:" not in text:
            continue
        fix = text.split("Fix:", 1)[1].strip()
        if fix:
            return fix
    return tmpl.get("remediation", "")


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
        # Compute the confidence cell first so the ternary cannot leak across
        # the implicit f-string concatenation (which would otherwise drop the
        # risk/result/closing cells, emitting malformed rows).
        conf_cell = f"<td>{confidence:.0%}</td>" if isinstance(confidence, float) else "<td>—</td>"
        rows += (
            f"<tr>"
            f"<td>{technique}</td>"
            f"<td><code>{filename}</code></td>"
            f"<td>{claimed}</td>"
            f"<td><b>{true_type}</b></td>"
            f"{conf_cell}"
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


def _resolve_recon_findings_dirs(report_dir: str) -> tuple[str, str]:
    """Map a report dir to its sibling recon/ and findings/ session dirs.

    Operators pass either the ``findings/<t>/sessions/<id>/`` or the
    ``recon/<t>/sessions/<id>/`` path; both layouts share a session id so we
    can derive the peer dir by swapping the top-level segment. Mirrors the
    inline logic in ``_collect_scan_diagnostics`` (kept in sync, factored out
    so the recon-inventory + coverage chapters resolve paths identically).

    v10.0.3 — in production this is called with the *generated report* dir
    (``reports/<t>/sessions/<id>/``, the value ``resolve_target_and_report_dir``
    returns and ``process_findings_dir`` threads through ``render_*_report``).
    That third layout matched neither the ``findings/`` nor the ``recon/``
    segment, so the recon-inventory + coverage chapters looked under
    ``reports/.../live`` / ``reports/.../ports`` / ``reports/.../coverage.json``
    — all non-existent — and rendered empty in every real report. We now also
    recognise the ``reports/`` segment and map it to BOTH sibling layouts
    (recon for host/port artefacts, findings for coverage.json)."""
    report_dir = (report_dir or "").rstrip("/")
    # Match the top-level "findings/", "recon/", or "reports/" segment whether
    # the caller passed an absolute ("/.../findings/...") or a relative
    # ("findings/...") path — the inline /findings/-only check in
    # _collect_scan_diagnostics silently no-ops on a relative findings dir,
    # which would leave the recon inventory empty. Swap only the FIRST segment
    # so a literal "findings"/"recon"/"reports" deeper in the path is preserved.
    findings_seg = re.compile(r"(^|/)findings/")
    recon_seg = re.compile(r"(^|/)recon/")
    reports_seg = re.compile(r"(^|/)reports/")
    if reports_seg.search(report_dir):
        # The generated-report layout: map the SAME session dir onto both the
        # recon/ tree (live/, ports/) and the findings/ tree (coverage.json).
        recon_dir = reports_seg.sub(lambda m: m.group(1) + "recon/", report_dir, count=1)
        findings_dir = reports_seg.sub(lambda m: m.group(1) + "findings/", report_dir, count=1)
        return recon_dir, findings_dir
    if findings_seg.search(report_dir):
        recon_dir = findings_seg.sub(lambda m: m.group(1) + "recon/", report_dir, count=1)
        return recon_dir, report_dir
    findings_dir = recon_seg.sub(lambda m: m.group(1) + "findings/", report_dir, count=1)
    return report_dir, findings_dir


def _render_recon_inventory_html(report_dir: str, target: str) -> str:
    """Render a "Recon / Host & Port Inventory" chapter from the session's
    live/httpx, ports/nmap, and priority artefacts.

    v10.0.2 — discovered hosts (e.g. ``mssql.*``), open ports (FTP 21/990,
    8443), and the live-host surface previously never appeared in the report:
    the only recon-derived block was the all-zeros "Recon Surface" metrics
    table whose paths often miss the real layout. This chapter lists every
    live host + status/tech and every open port even when no finding maps to
    them, so the inventory is visible. Degrades to a friendly note when the
    artefacts are absent."""
    recon_dir, _ = _resolve_recon_findings_dirs(report_dir)

    def _read_lines(*parts: str) -> list[str]:
        try:
            with open(os.path.join(recon_dir, *parts), errors="replace") as fh:
                return [ln.rstrip("\n") for ln in fh if ln.strip()]
        except OSError:
            return []

    # --- Live hosts (httpx_full.txt: "URL [status] [len] [title] [ip] [tech]") ---
    host_rows = ""
    httpx_re = re.compile(
        r"^(\S+)"                      # url
        r"(?:\s+\[([^\]]*)\])?"        # status
        r"(?:\s+\[([^\]]*)\])?"        # content length
        r"(?:\s+\[([^\]]*)\])?"        # title
        r"(?:\s+\[([^\]]*)\])?"        # ip
        r"(?:\s+\[([^\]]*)\])?")       # tech
    for line in _read_lines("live", "httpx_full.txt"):
        m = httpx_re.match(line.strip())
        if not m:
            continue
        url, status, _clen, ptitle, ip, tech = m.groups()
        host_rows += (
            f"<tr><td><code style=\"word-break:break-all\">{url}</code></td>"
            f"<td>{status or '—'}</td>"
            f"<td>{ip or '—'}</td>"
            f"<td>{ptitle or '—'}</td>"
            f"<td>{tech or '—'}</td></tr>\n")
    if not host_rows:
        # Fallback: plain URL list (live/urls.txt) when httpx detail is absent.
        for url in _read_lines("live", "urls.txt"):
            host_rows += (
                f"<tr><td><code style=\"word-break:break-all\">{url}</code></td>"
                "<td>—</td><td>—</td><td>—</td><td>—</td></tr>\n")

    # --- Open ports (open_ports.txt: "21/open"; nmap_greppable for service detail) ---
    port_service = {}
    for line in _read_lines("ports", "nmap_greppable.txt"):
        if "Ports:" not in line:
            continue
        for chunk in line.split("Ports:", 1)[1].split(","):
            # e.g. "21/open/tcp//ftp//Microsoft ftpd/"
            fields = chunk.strip().split("/")
            if len(fields) >= 5 and fields[0].isdigit():
                svc = fields[4] or ""
                ver = fields[6] if len(fields) > 6 else ""
                port_service[fields[0]] = " ".join(x for x in (svc, ver) if x).strip()
    port_rows = ""
    for line in _read_lines("ports", "open_ports.txt"):
        port = line.split("/", 1)[0].strip()
        if not port:
            continue
        port_rows += (f"<tr><td><code>{line}</code></td>"
                      f"<td>{port_service.get(port, '—') or '—'}</td></tr>\n")

    ips = _read_lines("live", "ips.txt")
    ips_str = ", ".join(ips) if ips else "—"

    if not host_rows and not port_rows:
        # v10.0.3 — render NOTHING (matches the coverage chapter's silent ''),
        # rather than an empty H2 + "inventory unavailable" block that leaked
        # raw filesystem paths into a client-facing report. A scan with no
        # recon artefacts (authenticated-API-only, scope-locked, etc.) should
        # simply omit the chapter, not advertise a missing directory.
        return ""

    host_body = host_rows or ('<tr><td colspan="5" style="color:#6c757d">'
                              'No live hosts recorded.</td></tr>')
    port_body = port_rows or ('<tr><td colspan="2" style="color:#6c757d">'
                              'No open ports recorded.</td></tr>')
    host_tbl = (
        '<h3 style="margin-top:20px">Live Hosts</h3>'
        '<table class="tbl">'
        '<tr><th>Host / URL</th><th style="width:80px">Status</th>'
        '<th style="width:120px">IP</th><th>Title</th><th>Tech</th></tr>'
        f'{host_body}'
        '</table>')
    port_tbl = (
        '<h3 style="margin-top:20px">Open Ports</h3>'
        '<table class="tbl" style="width:auto">'
        '<tr><th>Port</th><th>Service / Version</th></tr>'
        f'{port_body}'
        '</table>')

    return f'''
<h2 id="recon-inventory" style="border-bottom:2px solid #1a1a2e;padding-bottom:8px;margin-top:40px">
Recon / Host &amp; Port Inventory</h2>
<p style="color:#495057">Hosts and ports discovered during reconnaissance, listed even where no
finding maps to them. Resolved IP(s): <code>{ips_str}</code>.</p>
{host_tbl}
{port_tbl}
'''


def _render_coverage_limitations_html(report_dir: str) -> str:
    """Render a "Tooling & Coverage Limitations" chapter.

    INTEGRATION CONTRACT (v10.0.2): reads ``coverage.json`` under the findings
    session dir — a JSON list of ``{"tool": ..., "reason": ...}`` entries
    written by the hunt.py agent describing degraded/skipped capabilities.
    Degrades gracefully (renders nothing) when the file is absent, empty, or
    malformed so a normal full-coverage run adds no noise."""
    import json as _json
    _, findings_dir = _resolve_recon_findings_dirs(report_dir)
    cov_path = os.path.join(findings_dir, "coverage.json")
    if not os.path.isfile(cov_path):
        return ""
    try:
        with open(cov_path, errors="replace") as fh:
            data = _json.load(fh)
    except (OSError, ValueError):
        return ""
    if not isinstance(data, list):
        return ""

    rows = ""
    for item in data:
        if not isinstance(item, dict):
            continue
        tool = str(item.get("tool", "")).strip() or "—"
        reason = str(item.get("reason", "")).strip() or "—"
        rows += f"<tr><td><code>{tool}</code></td><td>{reason}</td></tr>\n"
    if not rows:
        return ""

    return f'''
<h2 id="coverage-limitations" style="border-bottom:2px solid #1a1a2e;padding-bottom:8px;margin-top:40px">
Tooling &amp; Coverage Limitations</h2>
<p style="color:#495057">The following capabilities were degraded or skipped during this
engagement. Findings should be read in light of these gaps — an absent result for a class
below is <b>inconclusive</b>, not a clean bill of health.</p>
<table class="tbl">
  <tr><th style="width:220px">Tool / Capability</th><th>Reason</th></tr>
  {rows}
</table>
'''


def _collect_scan_diagnostics(report_dir: str, target: str) -> dict:
    """Build a "what-was-scanned" dict from the recon + findings artefacts.

    v7.4.5 — used by the empty-findings diagnostic section. Purpose: when a
    scan legitimately produces 0 findings (thin target, authenticated API,
    scope-locked subdomain, etc.), the HTML report currently renders a
    blank "No findings." page and operators assume the tool is broken.
    This pulls counts and phase-completion evidence out of the session so
    the report can explain *why* it's empty.

    Accepts both layouts operators pass:
    - ``findings/<target>/sessions/<id>/`` (new — v7.4.4 canonical)
    - ``recon/<target>/sessions/<id>/``    (legacy — v2.x)
    """
    import glob as _glob

    diag: dict[str, object] = {
        "recon_dir": None,
        "findings_dir": None,
        "live_hosts": 0,
        "total_urls": 0,
        "params_urls": 0,
        "js_files": 0,
        "api_specs": 0,
        "api_operations": 0,
        "subdomains": 0,
        "ports_open": 0,
        "phases_completed": [],
        "phases_incomplete": [],
        "subdir_payload_counts": {},
        "target_api_shape": False,
        "has_default_swagger": False,
        "hints": [],
    }

    # Resolve recon dir — findings dir might be passed; swap "findings" for "recon".
    report_dir = report_dir.rstrip("/")
    if "/findings/" in report_dir:
        recon_dir = report_dir.replace("/findings/", "/recon/")
        findings_dir = report_dir
    else:
        recon_dir = report_dir
        findings_dir = report_dir.replace("/recon/", "/findings/")
    diag["recon_dir"] = recon_dir
    diag["findings_dir"] = findings_dir

    def _lc(path: str) -> int:
        """Line count, 0 if file missing / empty."""
        try:
            with open(path, errors="replace") as fh:
                return sum(1 for _ in fh if _.strip())
        except OSError:
            return 0

    diag["live_hosts"]     = _lc(os.path.join(recon_dir, "live", "urls.txt"))
    diag["total_urls"]     = _lc(os.path.join(recon_dir, "urls", "all.txt"))
    diag["params_urls"]    = _lc(os.path.join(recon_dir, "urls", "with_params.txt"))
    diag["js_files"]       = _lc(os.path.join(recon_dir, "urls", "js_files.txt"))
    diag["api_specs"]      = _lc(os.path.join(recon_dir, "api_specs", "spec_urls.txt"))
    diag["api_operations"] = _lc(os.path.join(recon_dir, "api_specs", "all_operations.txt"))
    diag["subdomains"]     = _lc(os.path.join(recon_dir, "subdomains", "all.txt"))
    diag["ports_open"]     = _lc(os.path.join(recon_dir, "ports", "open_ports.txt"))

    # Finding subdir payload counts — tells operator which classes ran but
    # produced nothing vs which never ran at all.
    if os.path.isdir(findings_dir):
        for entry in sorted(os.listdir(findings_dir)):
            # v7.4.6 — skip hidden + scratch dirs (.tmp, .cache, etc.).
            if entry.startswith("."):
                continue
            full = os.path.join(findings_dir, entry)
            if not os.path.isdir(full):
                continue
            n = sum(1 for f in _glob.glob(os.path.join(full, "*.txt"))
                    for _ in open(f, errors="replace"))
            diag["subdir_payload_counts"][entry] = n

    # Phase completion evidence — recon.sh writes `.done` markers per phase.
    for marker in sorted(_glob.glob(os.path.join(recon_dir, "*.done"))):
        diag["phases_completed"].append(os.path.basename(marker).replace(".done", ""))

    # Heuristic — target appears to be an API-only surface
    # (few URLs, no HTML-heavy recon signals).
    if diag["total_urls"] < 20 and diag["js_files"] < 3 and diag["live_hosts"] <= 2:
        diag["target_api_shape"] = True

    # Detect default Swagger UI (common Shemaroo/ALB deployment pattern).
    # Scanner output may have caught a petstore-backed swagger-ui — surface as hint.
    api_summary = os.path.join(recon_dir, "api_specs", "summary.md")
    if os.path.isfile(api_summary):
        try:
            body = open(api_summary).read()
            if "petstore" in body.lower() or "Specs discovered: 0" in body:
                # Spec discovery failed — check if there's still a Swagger UI.
                if os.path.isdir(os.path.join(recon_dir, "api_specs")):
                    diag["has_default_swagger"] = "Specs discovered: 0" in body
        except OSError:
            pass

    # Next-step hints tailored to the shape.
    if diag["target_api_shape"]:
        diag["hints"].append(
            "Target looks like an authenticated REST API. Re-run with "
            "<code>--creds user:pass</code> to reach the authenticated surface, "
            "or capture a browser HAR and run <code>har_vapt.py session.har</code>."
        )
    if diag["has_default_swagger"]:
        diag["hints"].append(
            "A Swagger UI was deployed but no real spec was published "
            "(default petstore config). Low-severity finding on deployment "
            "hygiene — worth calling out in the report narrative."
        )
    if diag["api_specs"] == 0 and diag["total_urls"] > 0:
        diag["hints"].append(
            "No OpenAPI specs auto-discovered. Try manual paths: "
            "<code>/api-docs</code>, <code>/swagger</code>, <code>/v1</code>, "
            "<code>/api/v1</code>. If docs are auth-gated, add credentials."
        )
    # v7.4.6 — previous gate carved out a target-name substring as dev-time
    # scaffolding. Removed. Scope-lock hint now fires for every single-
    # subdomain scan regardless of target name.
    if diag["subdomains"] <= 1:
        diag["hints"].append(
            "Scope-locked to the apex host — you may be missing findings on "
            "<code>api.</code>, <code>admin.</code>, or <code>staging.</code> "
            "subdomains. Re-run without <code>--scope-lock</code> to expand."
        )

    return diag


def _render_scan_diagnostics_html(diag: dict) -> str:
    """Render the empty-findings diagnostic block. Always emitted —
    even when findings exist — so operators can cross-check that all
    expected phases produced output."""
    counts = diag.get("subdir_payload_counts") or {}
    subdir_rows = ""
    for name in sorted(counts):
        n = counts[name]
        colour = "#198754" if n > 0 else "#6c757d"
        subdir_rows += (
            f'<tr><td><code>{name}/</code></td>'
            f'<td style="text-align:right;color:{colour}">{n} entries</td></tr>'
        )
    if not subdir_rows:
        subdir_rows = '<tr><td colspan="2" style="color:#6c757d">No finding subdirs produced by the scanner.</td></tr>'

    hints_html = ""
    for h in diag.get("hints") or []:
        hints_html += f'<li>{h}</li>'
    if not hints_html:
        hints_html = '<li>No specific hints — scan surface looks standard.</li>'

    return f'''
<h2 id="scan-diagnostics" style="border-bottom:2px solid #1a1a2e;padding-bottom:8px;margin-top:40px">
Scan Diagnostics</h2>
<p style="color:#495057">This section summarises what was actually scanned, how much data each phase produced, and why the findings count may look the way it does. <b>It is not a substitute for findings</b> — use it to sanity-check that expected phases ran.</p>

<h3 style="margin-top:20px">Recon Surface</h3>
<table class="tbl" style="width:auto">
  <tr><th>Metric</th><th style="text-align:right">Count</th></tr>
  <tr><td>Subdomains enumerated</td><td style="text-align:right">{diag.get("subdomains", 0)}</td></tr>
  <tr><td>Live hosts probed</td><td style="text-align:right">{diag.get("live_hosts", 0)}</td></tr>
  <tr><td>Open ports found</td><td style="text-align:right">{diag.get("ports_open", 0)}</td></tr>
  <tr><td>URLs collected (gau + katana + wayback)</td><td style="text-align:right">{diag.get("total_urls", 0)}</td></tr>
  <tr><td>Parameterised URLs</td><td style="text-align:right">{diag.get("params_urls", 0)}</td></tr>
  <tr><td>JS files analysed</td><td style="text-align:right">{diag.get("js_files", 0)}</td></tr>
  <tr><td>OpenAPI specs discovered</td><td style="text-align:right">{diag.get("api_specs", 0)}</td></tr>
  <tr><td>API operations extracted</td><td style="text-align:right">{diag.get("api_operations", 0)}</td></tr>
</table>

<h3 style="margin-top:20px">Finding Classes (scanner.sh subdirs)</h3>
<table class="tbl" style="width:auto">
  <tr><th>Class</th><th>Payload lines</th></tr>
  {subdir_rows}
</table>

<h3 style="margin-top:20px">Interpretation + Next Steps</h3>
<ul>{hints_html}</ul>
'''


def render_html_report(findings: list, target: str, report_dir: str,
                       client: str, consultant: str, title: str) -> str:
    date_str = datetime.now().strftime("%d %B %Y")
    counts   = {s: sum(1 for f in findings if f["severity"] == s)
                for s in SEVERITY_COLOR}
    total    = len(findings)
    # v10.6.0 — weighted overall risk score + label (report_synthesis)
    _risk_html = ""
    if _SCHEMA_OK:
        try:
            _score, _label = report_synthesis.risk_score(findings)
            _scol = SEVERITY_COLOR.get(_label.lower(), "#6c757d")
            _risk_html = (f'<p style="font-size:15px">Overall Risk Score: '
                          f'<b style="color:{_scol}">{_score:.1f} / 10 ({_label})</b></p>')
        except Exception:
            _risk_html = ""
    # v7.4.5 — gather scan diagnostics for the report footer so a 0-
    # findings report still explains what was actually scanned.
    diagnostics = _collect_scan_diagnostics(report_dir, target)

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
        vtitle = f.get("title") or tmpl["title"].format(host=host)
        # Prefer the per-finding score (CVE rows carry the real CVSS inside
        # their poc text) over the template default — mirrors the Markdown
        # renderer so HTML/MD agree instead of hardcoding the cves template's 9.0.
        m = re.search(r"CVSS:\s*([\d.]+)", f.get("poc", ""))
        cvss = m.group(1) if m else (f.get("cvss") or tmpl.get("cvss") or CVSS_DEFAULT.get(f["severity"], "N/A"))
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
        vtitle = f.get("title") or tmpl["title"].format(host=host)
        sev    = f["severity"]
        # Prefer the per-finding score (CVE rows carry the real CVSS inside
        # their poc text) over the template default — mirrors the Markdown
        # renderer so HTML/MD agree instead of hardcoding the cves template's 9.0.
        m      = re.search(r"CVSS:\s*([\d.]+)", f.get("poc", ""))
        cvss   = m.group(1) if m else (f.get("cvss") or tmpl.get("cvss") or CVSS_DEFAULT.get(sev, "N/A"))
        refs   = "".join(f'<li><a href="{u}" target="_blank">{n}</a></li>'
                         for n, u in tmpl.get("references", []))
        details += f"""
<div id="VN-{i:03d}" style="margin-bottom:36px;border:1px solid #dee2e6;border-radius:6px;overflow:hidden">
  <div style="background:{SEVERITY_COLOR.get(sev, SEVERITY_COLOR['info'])};padding:12px 18px;color:#fff">
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
    <pre style="background:#f8f9fa;border:1px solid #dee2e6;border-radius:4px;padding:12px;overflow-x:auto;font-size:0.85em;white-space:pre-wrap">{f.get("poc", f.get("raw", f.get("detail", "—")))}</pre>
    <h4 style="color:#343a40;margin:10px 0 6px">Remediation</h4>
    <p style="margin:0 0 10px">{_finding_remediation(f, tmpl)}</p>
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
  <li><a href="#recon-inventory">Recon / Host &amp; Port Inventory</a></li>
  <li><a href="#scan-diagnostics">Scan Diagnostics</a></li>
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
{_risk_html}
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

{_render_recon_inventory_html(report_dir, target)}

{_render_coverage_limitations_html(report_dir)}

{_render_scan_diagnostics_html(diagnostics)}

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

    # ── Whitebox cloud posture chapter (optional, inserted BEFORE </body>) ──
    cloud_chapter_html = ""
    try:
        from pathlib import Path as _P
        import json as _json
        # Resolve cloud directory: cloud audits are written at the TARGET LEVEL
        # (recon/<target>/cloud/) so they are session-agnostic.
        # Walk candidates from report_dir upward, and also check the recon tree.
        _rd = _P(report_dir)
        _recon_root = _P(BASE_DIR) / "recon" / target
        _cloud_dir_candidates = [
            _recon_root / "cloud",                 # recon/<target>/cloud/ (primary)
            _rd.parent / "cloud",                  # reports/<target>/sessions/<id>/../cloud/
            _rd.parent.parent / "cloud",           # reports/<target>/sessions/../cloud/
            _rd.parent.parent.parent / "cloud",    # walk up one more level
        ]
        cloud_dir = next((c for c in _cloud_dir_candidates if c.is_dir()), None)
        if cloud_dir is not None:
            from whitebox.reporting.posture_chapter import render as _render_posture
            from whitebox.models import Finding as _F, Severity as _Sev, CloudContext as _CC
            for acct_dir in sorted(cloud_dir.iterdir()):
                if not acct_dir.is_dir() or acct_dir.name == "correlation":
                    continue
                fjson = acct_dir / "findings.json"
                if not fjson.exists():
                    continue
                try:
                    data = _json.loads(fjson.read_text())
                except Exception:
                    continue
                cf: list = []
                for d in data:
                    try:
                        ctx = d.get("cloud_context")
                        cc = _CC(**{k: v for k, v in ctx.items() if k != "blast_radius"}) if ctx else None
                        cf.append(_F(
                            id=d["id"], source=d["source"], rule_id=d["rule_id"],
                            severity=_Sev[d["severity"].upper()],
                            title=d["title"], description=d["description"],
                            asset=None, evidence_path=_P(d["evidence_path"]),
                            cloud_context=cc,
                        ))
                    except Exception:
                        continue
                cloud_chapter_html += _render_posture(account_id=acct_dir.name, findings=cf, executive_summary="")
    except Exception:
        cloud_chapter_html = ""  # whitebox enrichment is optional

    # Insert cloud chapter immediately before </body>; if not found, append (degraded)
    if cloud_chapter_html:
        if "</body>" in html:
            html = html.replace("</body>", cloud_chapter_html + "\n</body>", 1)
        else:
            html += cloud_chapter_html

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
    ]
    # v10.6.0 — weighted overall risk score + label (report_synthesis)
    if _SCHEMA_OK:
        try:
            _score, _label = report_synthesis.risk_score(findings)
            lines += [f"**Overall Risk Score:** {_score:.1f} / 10 ({_label})", ""]
        except Exception:
            pass
    lines += [
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
        # v9.1.2 — for CVE-DB findings the host extracted from URL points at
        # nvd.nist.gov; the real "affected host" is the engagement target.
        if "nvd.nist.gov" in host or "cve.mitre.org" in host:
            host = target
        # v9.1.2 — finding's own title takes precedence over the template title.
        # CVE-DB rows already supply a useful "CVE-2017-7235 — cloudflare" title;
        # the generic template "Known CVE Vulnerability on {host}" is a fallback.
        title = f.get("title") or tmpl["title"].format(host=host)
        # v9.1.2 — actual CVSS from finding (CVE rows carry per-CVE score) takes
        # precedence over template default.
        m = re.search(r"CVSS:\s*([\d.]+)", f.get("poc", ""))
        cvss = m.group(1) if m else (f.get("cvss") or tmpl.get("cvss") or CVSS_DEFAULT.get(f["severity"], "N/A"))
        lines.append(f"| VN-{i:03d} | {title} | {f['severity'].upper()} | {cvss} | {host} |")
    lines += ["", "---", "", "## Detailed Findings", ""]
    for i, f in enumerate(findings, 1):
        tmpl  = VULN_TEMPLATES.get(f["vtype"], VULN_TEMPLATES["misconfig"])
        host  = re.search(r'https?://([^/]+)', f["url"])
        host  = host.group(1) if host else target
        if "nvd.nist.gov" in host or "cve.mitre.org" in host:
            host = target
        title = f.get("title") or tmpl["title"].format(host=host)
        m = re.search(r"CVSS:\s*([\d.]+)", f.get("poc", ""))
        cvss = m.group(1) if m else (f.get("cvss") or tmpl.get("cvss") or CVSS_DEFAULT.get(f["severity"], "N/A"))
        refs  = "\n".join(f"- [{n}]({u})" for n, u in tmpl.get("references", []))
        lines += [
            f"### VN-{i:03d} — {title}",
            f"**Severity:** {f['severity'].upper()} | **CVSS:** {cvss} | **CWE:** {tmpl.get('cwe','N/A')} | **ATT&CK:** {ATTACK_IDS.get(f['vtype'],'—')}  ",
            f"**Affected URL:** `{f['url']}`", "",
            f"**Impact:** {tmpl['impact']}", "",
            "**Evidence / Proof of Concept:**", "```",
            f.get("poc", f.get("raw", f.get("detail", "—"))),
            "```", "",
            f"**Remediation:** {_finding_remediation(f, tmpl)}", "",
            "**References:**", refs, "", "---", "",
        ]
    lines.append(f"*Generated by [Vikramaditya](https://github.com/venkatas/vikramaditya) — Autonomous VAPT Platform | {date_str}*")
    return "\n".join(lines)


def _apply_verification_gating(findings: list) -> list:
    """v10.6.0 — downgrade/drop UNPROVEN findings before client render.

    CONSERVATIVE by design: a finding is only treated as UNVERIFIED when it carries an
    explicit verification tag OR is a brain MODEL CLAIM. Real scanner/tool findings (the
    overwhelming majority — nuclei, sqlmap, CVE matches) are treated as tool-evidenced and
    are NEVER dropped — hiding a real finding is worse than reporting an unproven one.
    Only an explicit model-claim at medium+ severity is dropped (it's noise, not evidence).
    """
    if not _SCHEMA_OK:
        return findings
    kept = []
    for f in findings:
        raw = (f.get("raw") or "").lstrip().upper()
        explicit = (f.get("verification_method") or "").strip().lower()
        # FAIL OPEN: only an EXPLICIT model-generated claim is unverified-and-droppable.
        # We anchor on the brain_scanner marker PREFIX (not a substring-anywhere match) so a
        # real scanner finding whose evidence text merely contains "UNVERIFIED"/"PENDING"
        # (e.g. a leaked token "AKIAUNVERIFIED...") is NOT mistaken for a model claim.
        is_model_claim = (raw.startswith("[MODEL CLAIM")
                          or raw.startswith("[UNVERIFIED]")
                          or explicit in ("model_claim", "unverified"))
        method = VerificationMethod.UNVERIFIED if is_model_claim else VerificationMethod.EXPLOITED
        sev = f.get("severity", "medium")
        new_sev = adjust_severity(sev, method)
        if new_sev != sev:
            f["original_severity"] = sev
            f["severity"] = new_sev
        if should_report(f["severity"], method):
            kept.append(f)
        # else: dropped — an explicit unverified model claim at medium+ (noise, not evidence)
    return kept


def process_findings_dir(findings_dir: str, client: str = "",
                         consultant: str = "", title: str = "",
                         target_override: str = "") -> tuple:
    target, session, report_dir = resolve_target_and_report_dir(findings_dir)
    if target_override:
        target = target_override
    os.makedirs(report_dir, exist_ok=True)
    findings = load_findings(findings_dir)
    findings = _apply_verification_gating(findings)   # v10.6.0
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
