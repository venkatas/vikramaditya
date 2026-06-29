"""technique_kb — attack-technique knowledge base + attack-chaining for Vikramaditya findings.

WHY: findings in isolation under-state risk. A lone IDOR is "high"; an IDOR that *chains to*
credential exposure that *chains to* account takeover is the real business impact. This module
gives every finding type a structured technique record — MITRE ATT&CK id + tactic, CWE,
detection guidance, remediation, and crucially `chains_to` (the techniques it commonly enables)
— so the reporter can render an ATT&CK mapping + an attack-path narrative, and the brain can
lazy-load a single technique for context (no bulk knowledge dump).

PROVENANCE: clean-room. The *pattern* (a structured technique record with chaining metadata)
is a common one in security knowledge bases; ALL content here is original prose written from
the PUBLIC standards — MITRE ATT&CK (attack.mitre.org), CWE (cwe.mitre.org), OWASP. No
third-party code or text is copied, and there is no copyleft dependency.

Keys are Vikramaditya's reporter vtypes; variant vtypes (sqli_sqlmap_confirmed, xss_dom, …)
resolve to their base technique via `_ALIAS`.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Technique:
    vtype: str
    title: str
    mitre_id: str
    mitre_tactic: str
    cwe: str
    summary: str
    chains_to: tuple = ()        # vtypes this finding commonly ENABLES next (attack chaining)
    detection: str = ""
    remediation: str = ""
    references: tuple = ()


# Variant / tool-specific vtypes that share a base technique.
_ALIAS = {
    "sqli_sqlmap_confirmed": "sqli",
    "xss_dom": "xss",
    "xss_dalfox_confirmed": "xss",
    "upload_type_bypass": "upload",
    "exposed_credentials": "exposure",
    "refresh_token_bypass": "oauth",
    "timing_oracle_user_enum": "auth_bypass",
    "score_manipulation": "business_logic",
}

_KB: dict[str, Technique] = {}


def _t(**kw) -> Technique:
    t = Technique(**kw)
    _KB[t.vtype] = t
    return t


_t(vtype="sqli", title="SQL Injection", mitre_id="T1190",
   mitre_tactic="Initial Access", cwe="CWE-89",
   summary="Untrusted input is concatenated into a SQL query, letting an attacker alter query "
           "logic to read, modify, or exfiltrate database contents, and on some engines reach "
           "the host.",
   chains_to=("exposure", "auth_bypass", "rce"),
   detection="Parameterized-query coverage review; WAF/RASP alerts on tautologies, UNION, and "
             "time-based payloads; DB error spikes and anomalous result-set sizes.",
   remediation="Use parameterized queries / prepared statements everywhere; least-privilege DB "
               "accounts; never build SQL by string concatenation; validate + canonicalize input.",
   references=("https://attack.mitre.org/techniques/T1190/",
               "https://cwe.mitre.org/data/definitions/89.html",
               "https://owasp.org/www-community/attacks/SQL_Injection"))

_t(vtype="rce", title="Remote Code Execution", mitre_id="T1190",
   mitre_tactic="Execution", cwe="CWE-94",
   summary="The attacker executes arbitrary code/commands on the server — typically the terminal "
           "objective of a chain and a full compromise of the host's trust boundary.",
   chains_to=("exposure", "takeover"),
   detection="Unexpected child processes from web/app workers; outbound C2 beacons; new files in "
             "web roots; EDR command-line telemetry.",
   remediation="Eliminate the injection sink (no eval/exec on input, safe deserialization, no "
               "shell concatenation); sandbox/seccomp the runtime; egress filtering; patch.",
   references=("https://attack.mitre.org/techniques/T1190/",
               "https://cwe.mitre.org/data/definitions/94.html"))

_t(vtype="idor", title="IDOR / Broken Object-Level Authorization", mitre_id="T1078",
   mitre_tactic="Discovery", cwe="CWE-639",
   summary="A reference to an object (id in URL/body) is honoured without verifying the caller "
           "owns it, so an authenticated user reads or modifies other users' objects by changing "
           "the identifier.",
   chains_to=("exposure", "auth_bypass", "business_logic"),
   detection="Per-endpoint access-control test matrix; anomaly detection on sequential-id access "
             "patterns and high distinct-object counts per session.",
   remediation="Enforce per-object authorization server-side on every read/write (the resource "
               "must belong to / be assigned to the caller); use unguessable references as "
               "defense-in-depth, never as the control.",
   references=("https://attack.mitre.org/techniques/T1078/",
               "https://cwe.mitre.org/data/definitions/639.html",
               "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"))

_t(vtype="auth_bypass", title="Broken Function-Level Authorization / Auth Bypass",
   mitre_id="T1078", mitre_tactic="Privilege Escalation", cwe="CWE-285",
   summary="A privileged function or page is reachable by a lower-privileged (or unauthenticated) "
           "actor because the role/permission check is missing or client-side only.",
   chains_to=("idor", "rce", "business_logic", "exposure"),
   detection="Differential role testing (low-priv vs admin vs unauth) on every privileged route; "
             "alert on privileged actions performed by non-privileged principals.",
   remediation="Enforce role/permission checks server-side on every privileged route AND action "
               "handler; deny-by-default; never rely on UI hiding or obscured URLs.",
   references=("https://attack.mitre.org/techniques/T1078/",
               "https://cwe.mitre.org/data/definitions/285.html",
               "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"))

_t(vtype="exposure", title="Sensitive Data / Credential Exposure", mitre_id="T1552",
   mitre_tactic="Credential Access", cwe="CWE-200",
   summary="Sensitive data (PII, secrets, credentials, tokens, internal directories) is disclosed "
           "to an actor who should not receive it — directly or via data-minimization failures.",
   chains_to=("auth_bypass", "rce", "takeover"),
   detection="DLP / response-body PII & secret scanning; alert on bulk record reads and secret "
             "patterns (keys, tokens) in responses, logs, and artifacts.",
   remediation="Data minimization (return only what the caller needs); encrypt at rest/in transit; "
               "rotate any disclosed secret; scope/paginate list endpoints; redact logs.",
   references=("https://attack.mitre.org/techniques/T1552/",
               "https://cwe.mitre.org/data/definitions/200.html"))

_t(vtype="xss", title="Cross-Site Scripting", mitre_id="T1059.007",
   mitre_tactic="Execution", cwe="CWE-79",
   summary="Untrusted input is reflected/stored and executed as script in a victim's browser, "
           "letting the attacker run JS in the app's origin — session theft, action-on-behalf, "
           "credential capture.",
   chains_to=("csrf", "exposure", "auth_bypass"),
   detection="CSP violation reports; output-encoding coverage review; alert on script-like "
             "payloads reflected into responses.",
   remediation="Context-aware output encoding; a strict Content-Security-Policy; framework "
               "auto-escaping; HttpOnly + SameSite cookies; sanitize rich-text on input.",
   references=("https://attack.mitre.org/techniques/T1059/007/",
               "https://cwe.mitre.org/data/definitions/79.html",
               "https://owasp.org/www-community/attacks/xss/"))

_t(vtype="ssrf", title="Server-Side Request Forgery", mitre_id="T1090",
   mitre_tactic="Discovery", cwe="CWE-918",
   summary="The server can be coerced into making requests to attacker-chosen URLs, reaching "
           "internal services and cloud metadata endpoints from a trusted network position.",
   chains_to=("exposure", "rce"),
   detection="Egress monitoring from app tier; alert on requests to link-local metadata "
             "(169.254.169.254) and internal RFC1918 ranges originating from web workers.",
   remediation="Allowlist outbound hosts/schemes; block link-local & internal ranges; require "
               "IMDSv2; resolve+validate the final IP after redirects; no raw user URLs.",
   references=("https://attack.mitre.org/techniques/T1090/",
               "https://cwe.mitre.org/data/definitions/918.html",
               "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"))

_t(vtype="lfi", title="Local File Inclusion / Path Traversal", mitre_id="T1083",
   mitre_tactic="Discovery", cwe="CWE-22",
   summary="A file path derived from input escapes the intended directory, disclosing arbitrary "
           "files (configs, secrets, source) and on some stacks reaching code execution.",
   chains_to=("exposure", "rce"),
   detection="Alert on traversal sequences (../, encoded variants) and access to sensitive paths "
             "(/etc/passwd, web.config, .env) in request logs.",
   remediation="Resolve to a canonical path and confirm it stays within an allowlisted base dir; "
               "map to opaque ids instead of filenames; drop traversal sequences; least-priv FS.",
   references=("https://attack.mitre.org/techniques/T1083/",
               "https://cwe.mitre.org/data/definitions/22.html"))

_t(vtype="ssti", title="Server-Side Template Injection", mitre_id="T1190",
   mitre_tactic="Execution", cwe="CWE-1336",
   summary="User input is evaluated by a server-side template engine, allowing expression "
           "evaluation that typically escalates to remote code execution.",
   chains_to=("rce", "exposure"),
   detection="Polyglot template probes ({{7*7}}, ${7*7}) returning evaluated output; engine "
             "error signatures in responses.",
   remediation="Never render user input as a template; use logic-less templates / sandboxed "
               "engines; pass user data only as bound variables, not template source.",
   references=("https://attack.mitre.org/techniques/T1190/",
               "https://cwe.mitre.org/data/definitions/1336.html",
               "https://owasp.org/www-project-web-security-testing-guide/"))

_t(vtype="upload", title="Unrestricted / Malicious File Upload", mitre_id="T1105",
   mitre_tactic="Execution", cwe="CWE-434",
   summary="The application accepts a file whose type/content is not safely constrained, enabling "
           "web-shell upload, content-type confusion, or storage of malicious payloads.",
   chains_to=("rce", "exposure"),
   detection="Alert on executable extensions/MIME in upload dirs; integrity-monitor web roots; "
             "scan stored files; flag uploads served from an executable path.",
   remediation="Allowlist extensions+MIME by magic bytes; store outside the web root with random "
               "names; serve via a non-executing handler; never trust client-supplied filename/type.",
   references=("https://attack.mitre.org/techniques/T1105/",
               "https://cwe.mitre.org/data/definitions/434.html"))

_t(vtype="deserialization", title="Insecure Deserialization", mitre_id="T1190",
   mitre_tactic="Execution", cwe="CWE-502",
   summary="Untrusted serialized data is deserialized into objects, enabling gadget-chain code "
           "execution or object-injection attacks (e.g. .NET ViewState, Java, PHP, pickle).",
   chains_to=("rce", "exposure"),
   detection="Alert on serialized blobs in input (rO0, gadget markers); integrity failures on "
             "signed tokens; unexpected object instantiation.",
   remediation="Don't deserialize untrusted data; use data-only formats (JSON) with strict "
               "schemas; sign+verify (MAC) any serialized state (e.g. ViewState MAC); allowlist types.",
   references=("https://attack.mitre.org/techniques/T1190/",
               "https://cwe.mitre.org/data/definitions/502.html"))

_t(vtype="cors", title="CORS Misconfiguration", mitre_id="T1557",
   mitre_tactic="Collection", cwe="CWE-942",
   summary="An overly permissive cross-origin policy (reflected/null origin with credentials) "
           "lets a malicious site read authenticated responses on the victim's behalf.",
   chains_to=("exposure", "auth_bypass"),
   detection="Review Access-Control-Allow-Origin reflection and Allow-Credentials=true pairings; "
             "alert on wildcard-with-credentials.",
   remediation="Strict origin allowlist (no reflection, no null); never combine "
               "Allow-Credentials:true with a wildcard or reflected origin; scope per-endpoint.",
   references=("https://attack.mitre.org/techniques/T1557/",
               "https://cwe.mitre.org/data/definitions/942.html"))

_t(vtype="jwt", title="JWT / Token Weakness", mitre_id="T1078",
   mitre_tactic="Privilege Escalation", cwe="CWE-347",
   summary="Weak JWT handling (alg=none, weak HMAC secret, missing signature/audience checks, "
           "kid injection) lets an attacker forge tokens and assume identities/roles.",
   chains_to=("auth_bypass", "idor"),
   detection="Reject alg=none and algorithm confusion at the verifier; alert on tokens failing "
             "signature/aud/exp validation; monitor for forged-claim patterns.",
   remediation="Pin the expected algorithm; verify signature, issuer, audience, and expiry; use "
               "strong asymmetric keys or high-entropy secrets; reject alg=none; rotate keys.",
   references=("https://attack.mitre.org/techniques/T1078/",
               "https://cwe.mitre.org/data/definitions/347.html"))

_t(vtype="oauth", title="OAuth / OIDC Flow Weakness", mitre_id="T1528",
   mitre_tactic="Credential Access", cwe="CWE-287",
   summary="Flaws in the OAuth/OIDC flow (implicit flow token leakage, weak/absent state & nonce, "
           "open redirect_uri, refresh-token misuse) enable token theft and account takeover.",
   chains_to=("auth_bypass", "takeover"),
   detection="Alert on implicit-flow id_token in URLs/referers, missing state/nonce, and "
             "redirect_uri mismatches; monitor refresh-token reuse.",
   remediation="Use authorization-code + PKCE (not implicit); enforce exact redirect_uri "
               "allowlist; require+verify state and nonce; rotate refresh tokens; short-lived "
               "access tokens.",
   references=("https://attack.mitre.org/techniques/T1528/",
               "https://cwe.mitre.org/data/definitions/287.html"))

_t(vtype="csrf", title="Cross-Site Request Forgery", mitre_id="T1185",
   mitre_tactic="Collection", cwe="CWE-352",
   summary="A state-changing request is accepted without proof of user intent, so a malicious "
           "site can cause the victim's authenticated browser to perform actions.",
   chains_to=("business_logic", "auth_bypass"),
   detection="Review state-changing endpoints for anti-CSRF tokens / SameSite; alert on "
             "cross-site referers on sensitive POSTs.",
   remediation="Per-request anti-CSRF tokens (synchronizer/double-submit); SameSite=Lax/Strict "
               "cookies; require re-auth for sensitive actions; verify origin/referer.",
   references=("https://attack.mitre.org/techniques/T1185/",
               "https://cwe.mitre.org/data/definitions/352.html"))

_t(vtype="open_redirect", title="Open Redirect", mitre_id="T1598",
   mitre_tactic="Initial Access", cwe="CWE-601",
   summary="A redirect target is taken from input without validation, lending the trusted domain "
           "to phishing and OAuth token-leak chains.",
   chains_to=("oauth", "exposure"),
   detection="Alert on redirect parameters pointing to external/attacker hosts; review all "
             "Location-from-input flows.",
   remediation="Allowlist redirect targets or use server-side mapping keys; never redirect to a "
               "raw user-supplied URL; strip absolute URLs.",
   references=("https://attack.mitre.org/techniques/T1598/",
               "https://cwe.mitre.org/data/definitions/601.html"))

_t(vtype="takeover", title="Subdomain / Resource Takeover", mitre_id="T1584",
   mitre_tactic="Resource Development", cwe="CWE-350",
   summary="A dangling DNS record points to a deprovisioned resource an attacker can claim, "
           "letting them serve content from the victim's trusted name.",
   chains_to=("xss", "exposure", "oauth"),
   detection="Continuous DNS hygiene scans for dangling CNAMEs to unclaimed providers; alert on "
             "NXDOMAIN/unclaimed fingerprints.",
   remediation="Remove dangling DNS records on decommission; claim/verify resources before "
               "publishing records; monitor third-party endpoints.",
   references=("https://attack.mitre.org/techniques/T1584/",
               "https://cwe.mitre.org/data/definitions/350.html"))

_t(vtype="graphql", title="GraphQL Abuse", mitre_id="T1190",
   mitre_tactic="Discovery", cwe="CWE-639",
   summary="Permissive GraphQL (introspection on, no depth/cost limits, field-level authz gaps) "
           "enables schema mapping, IDOR-style data access, and resource exhaustion.",
   chains_to=("idor", "exposure"),
   detection="Alert on introspection queries in prod, deeply nested/aliased queries, and "
             "high-cost operations.",
   remediation="Disable introspection in prod; enforce per-field authorization; add depth/cost "
               "limits and persisted queries; rate-limit.",
   references=("https://attack.mitre.org/techniques/T1190/",
               "https://owasp.org/www-project-web-security-testing-guide/"))

_t(vtype="smuggling", title="HTTP Request Smuggling", mitre_id="T1557",
   mitre_tactic="Collection", cwe="CWE-444",
   summary="Disagreement between front-end and back-end on request boundaries (CL/TE) lets an "
           "attacker prepend requests, poisoning other users' responses or bypassing controls.",
   chains_to=("auth_bypass", "xss"),
   detection="Alert on ambiguous CL/TE headers; differential timing probes; cache-poisoning "
             "indicators.",
   remediation="Normalize/reject ambiguous length headers at the edge; use HTTP/2 end-to-end; "
               "align front-end and origin parsing; disable connection reuse where unsafe.",
   references=("https://attack.mitre.org/techniques/T1557/",
               "https://cwe.mitre.org/data/definitions/444.html"))

_t(vtype="business_logic", title="Business-Logic Abuse", mitre_id="T1565",
   mitre_tactic="Impact", cwe="CWE-840",
   summary="The application's workflow can be driven into states the designers did not intend "
           "(skipped steps, negative quantities, race windows, approval bypass) for fraud or abuse.",
   chains_to=("exposure",),
   detection="Invariant/anomaly monitoring on critical workflows; alert on out-of-order steps, "
             "value bounds violations, and concurrent state changes.",
   remediation="Enforce server-side state machines and invariants; validate value bounds and "
               "step order; idempotency + locking on critical transitions; segregation of duties.",
   references=("https://attack.mitre.org/techniques/T1565/",
               "https://cwe.mitre.org/data/definitions/840.html",
               "https://owasp.org/www-project-web-security-testing-guide/"))

_t(vtype="misconfig", title="Security Misconfiguration", mitre_id="T1562",
   mitre_tactic="Defense Evasion", cwe="CWE-16",
   summary="Insecure defaults, missing hardening, verbose errors, or absent security headers "
           "weaken the app's defensive posture and ease other attacks.",
   chains_to=("exposure",),
   detection="Config drift / benchmark scanning (CIS); header and error-verbosity checks; "
             "surface-area review.",
   remediation="Harden to a benchmark; disable debug/verbose errors in prod; set security "
               "headers (CSP/HSTS/X-Frame-Options); remove unused features; patch.",
   references=("https://attack.mitre.org/techniques/T1562/",
               "https://cwe.mitre.org/data/definitions/16.html"))


# ── Active Directory / identity techniques (feed ad_hunt.py findings) ────────────
_t(vtype="kerberoasting", title="Kerberoasting", mitre_id="T1558.003",
   mitre_tactic="Credential Access", cwe="CWE-522",
   summary="Any domain user can request Kerberos service tickets (TGS) for accounts with an SPN; "
           "the ticket is encrypted with the service account's NTLM hash and can be cracked "
           "offline to recover the plaintext password.",
   chains_to=("exposure", "auth_bypass"),
   detection="Alert on anomalous TGS-REQ volume and RC4 (etype 23) ticket requests; honeypot SPN "
             "accounts; Event ID 4769 monitoring.",
   remediation="Use long (25+ char) random passwords or gMSAs for service accounts; enforce "
               "AES-only Kerberos; remove unnecessary SPNs; least-privilege service accounts.",
   references=("https://attack.mitre.org/techniques/T1558/003/",
               "https://cwe.mitre.org/data/definitions/522.html"))

_t(vtype="asrep_roast", title="AS-REP Roasting", mitre_id="T1558.004",
   mitre_tactic="Credential Access", cwe="CWE-522",
   summary="Accounts with Kerberos pre-authentication disabled return an AS-REP encrypted with "
           "the user's hash to any requester, enabling offline password cracking without prior "
           "authentication.",
   chains_to=("exposure", "auth_bypass"),
   detection="Inventory accounts with 'Do not require Kerberos preauthentication'; alert on "
             "AS-REQ without pre-auth (Event ID 4768 with preauth not required).",
   remediation="Require Kerberos pre-authentication on all accounts; strong passwords; review "
               "legacy accounts that disabled it.",
   references=("https://attack.mitre.org/techniques/T1558/004/",
               "https://cwe.mitre.org/data/definitions/522.html"))

_t(vtype="ntlm_relay", title="NTLM Relay / Coercion", mitre_id="T1557.001",
   mitre_tactic="Credential Access", cwe="CWE-294",
   summary="Coerced or poisoned NTLM authentication is relayed to a service that lacks signing, "
           "letting an attacker authenticate as the victim — often a path to AD CS or DC takeover.",
   chains_to=("auth_bypass", "dcsync"),
   detection="Monitor LLMNR/NBT-NS/mDNS poisoning, coercion RPC calls (PetitPotam, PrinterBug), "
             "and unexpected machine-account auth to HTTP/LDAP endpoints.",
   remediation="Enforce SMB and LDAP signing + channel binding (EPA); disable LLMNR/NBT-NS; "
               "patch coercion vectors; restrict who can authenticate to AD CS web enrollment.",
   references=("https://attack.mitre.org/techniques/T1557/001/",
               "https://cwe.mitre.org/data/definitions/294.html"))

_t(vtype="adcs_esc", title="AD CS Misconfiguration (ESC)", mitre_id="T1649",
   mitre_tactic="Privilege Escalation", cwe="CWE-269",
   summary="Misconfigured Active Directory Certificate Services templates (ESC1–ESC8) let a "
           "low-privileged user enrol a certificate that authenticates as a privileged account, "
           "yielding domain escalation.",
   chains_to=("dcsync", "auth_bypass"),
   detection="Audit certificate templates for dangerous flags (ENROLLEE_SUPPLIES_SUBJECT, "
             "client-auth EKU, weak enrol rights); monitor abnormal certificate enrolment.",
   remediation="Remediate vulnerable templates (remove SUPPLIES_SUBJECT, restrict enrol/EKU); "
               "enable CA enforcement of strong mapping; restrict web enrolment; audit with Certipy.",
   references=("https://attack.mitre.org/techniques/T1649/",
               "https://cwe.mitre.org/data/definitions/269.html"))

_t(vtype="dcsync", title="DCSync — Domain Credential Replication", mitre_id="T1003.006",
   mitre_tactic="Credential Access", cwe="CWE-269",
   summary="An account with directory-replication rights can ask a DC to replicate password "
           "hashes for any principal (including krbtgt), giving full domain credential access "
           "and effective domain dominance (golden-ticket capable).",
   chains_to=("rce",),
   detection="Alert on DRSUAPI replication (GetNCChanges) from non-DC hosts/accounts; monitor "
             "Replicating Directory Changes rights assignments.",
   remediation="Restrict replication rights to DCs only; tier-0 isolation; rotate krbtgt twice on "
               "suspected compromise; monitor and alert on DCSync primitives.",
   references=("https://attack.mitre.org/techniques/T1003/006/",
               "https://cwe.mitre.org/data/definitions/269.html"))


def get(vtype: str) -> Technique | None:
    """Return the Technique for a reporter vtype (resolving variants), or None if unknown."""
    if not vtype:
        return None
    return _KB.get(vtype) or _KB.get(_ALIAS.get(vtype, ""))


def techniques() -> list:
    """All base vtypes that have a technique record."""
    return sorted(_KB)


def chain_path(vtype: str, depth: int = 4) -> list:
    """Greedy attack-path from a starting vtype following the PRIMARY (first) chains_to edge,
    cycle-safe and capped at `depth`. Returns an ordered list of vtypes, e.g.
    sqli -> exposure -> auth_bypass -> idor. Good for a one-line 'attack path' in the report.
    """
    path, seen, cur, steps = [], set(), vtype, 0
    while cur and cur not in seen and steps < depth:
        t = get(cur)
        if t is None:
            break
        base = t.vtype
        path.append(base)
        seen.add(base)
        cur = t.chains_to[0] if t.chains_to else None
        steps += 1
    return path


def enrich(finding: dict) -> dict:
    """Return a shallow copy of a reporter finding annotated with technique knowledge under a
    'technique' key (mitre id/tactic, cwe, chains_to, detection, remediation, references,
    attack_path). Unknown vtypes are returned unchanged. Never mutates the input."""
    out = dict(finding)
    t = get(finding.get("vtype") or finding.get("type") or "")
    if t is None:
        return out
    out["technique"] = {
        "title": t.title,
        "mitre_id": t.mitre_id,
        "mitre_tactic": t.mitre_tactic,
        "cwe": t.cwe,
        "summary": t.summary,
        "chains_to": list(t.chains_to),
        "detection": t.detection,
        "remediation": t.remediation,
        "references": list(t.references),
        "attack_path": chain_path(t.vtype),
    }
    return out


def markdown_block(vtype: str) -> str:
    """Render a finding's technique knowledge as a Markdown block for the report. Empty string
    for an unknown vtype (so callers can append unconditionally)."""
    t = get(vtype)
    if t is None:
        return ""
    path = " → ".join(chain_path(t.vtype))
    lines = [
        f"**MITRE ATT&CK:** {t.mitre_id} ({t.mitre_tactic})  |  **{t.cwe}**",
        "",
        t.summary,
        "",
        f"**Attack chain:** {path}" if len(chain_path(t.vtype)) > 1 else "",
        f"**Detection:** {t.detection}" if t.detection else "",
        f"**Remediation:** {t.remediation}" if t.remediation else "",
    ]
    if t.references:
        lines.append("**References:** " + " · ".join(t.references))
    return "\n".join(ln for ln in lines if ln != "")
