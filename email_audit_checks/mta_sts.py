"""MTA-STS check surface — re-exports from the email_audit monolith."""
from email_audit import (  # noqa: F401
    audit_mta_sts,
    parse_mta_sts_policy,
    fetch_url_text,
)
