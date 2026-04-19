"""MX check surface — re-exports from the email_audit monolith."""
from email_audit import (  # noqa: F401
    audit_mx,
    parse_mx_records,
    detect_provider,
    infer_provider_from_domain_hints,
    probe_smtp_starttls,
    smtp_read_response,
)
