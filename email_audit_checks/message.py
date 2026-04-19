"""Message (.eml) analysis surface — re-exports from the email_audit monolith."""
from email_audit import (  # noqa: F401
    build_message_analysis_report,
    read_message_file,
    extract_message_body_preview,
    collect_message_header_snapshot,
    parse_authentication_results_header,
    parse_received_spf_header,
    parse_arc_authentication_results_header,
)
