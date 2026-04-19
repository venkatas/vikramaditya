"""DKIM check surface — re-exports from the email_audit monolith."""
from email_audit import (  # noqa: F401
    audit_dkim,
    estimate_dkim_rsa_bits,
    infer_dkim_selectors,
    load_selectors,
)
