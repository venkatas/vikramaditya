"""SPF check surface — re-exports from the email_audit monolith."""
from email_audit import (  # noqa: F401
    audit_spf,
    fetch_spf_record,
    estimate_spf_lookups,
    describe_network_width,
    is_privateish_ip,
)
