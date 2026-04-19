"""Per-check import surface for the email_audit monolith.

v7.4.0 — the ``email_audit.py`` file is 3444 lines. Splitting the code
across eight physical modules would introduce cross-reference risk
(shared ``DNSClient``, helpers like ``parse_kv_record`` / ``describe_
network_width`` / ``estimate_dkim_rsa_bits`` used by multiple audits).
Instead, this package provides **logical** per-check modules — each
module just re-exports the stable functions for one audit class from
the monolith. Downstream code and tests can now target one check at a
time without importing the whole 3444-line file directly.

Later refactors can move the implementation bodies out of
``email_audit.py`` into these modules without breaking any downstream
code — as long as the re-export name set stays stable.

Usage:
    from email_audit_checks import spf, dmarc, dkim, mx
    spf.audit_spf(domain, dns_client, target_type="domain")
    dkim.estimate_dkim_rsa_bits(pubkey_b64)
"""

from __future__ import annotations

from email_audit_checks import (  # noqa: F401
    spf,
    dmarc,
    dkim,
    mx,
    mta_sts,
    tls_rpt,
    bimi,
    dnssec,
    message,
)

__all__ = [
    "spf", "dmarc", "dkim", "mx",
    "mta_sts", "tls_rpt", "bimi", "dnssec",
    "message",
]
