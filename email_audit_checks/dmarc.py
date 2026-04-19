"""DMARC check surface — re-exports from the email_audit monolith."""
from email_audit import (  # noqa: F401
    audit_dmarc,
    parse_kv_record,
    relaxed_aligns,
    parse_mailto_domains,
)
