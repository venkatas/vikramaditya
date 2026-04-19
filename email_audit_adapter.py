"""Clean import surface + finding-schema adapter for ``email_audit.py``.

v7.3.0 — Path B of the subspace-sentinel integration. Instead of splitting
the 3444-line monolith (risky — lots of cross-references between audit_*
functions, shared DNS client, DER parser helpers), we add a thin adapter
module that:

1. Re-exports the stable audit primitives as a clean Python API so other
   Vikramaditya modules don't import the monolith directly.
2. Converts ``email_audit.py``'s JSON output into Vikramaditya's
   ``memory/schemas.py``-compatible finding shape — same
   ``{target, action, vuln_class, endpoint, result, severity, notes, tags}``
   structure used by every other scanner. The HTML reporter and
   hunt-memory pipeline then picks up email-auth findings without a
   separate code path.

This lets v7.3.0 "refactor" the integration without touching the audit
logic itself. Splitting the monolith into ``email_audit/`` per-check
modules is still viable later but not required for clean consumption.
"""

from __future__ import annotations

import json
import os
from typing import Any, Iterable

# Public re-exports — import here so downstream modules don't reach into
# the monolith. If email_audit.py later splits into a package, only this
# module changes.
from email_audit import (  # noqa: F401 — re-exports
    audit_spf,
    audit_dmarc,
    audit_dkim,
    audit_mx,
    audit_mta_sts,
    audit_tls_rpt,
    audit_bimi,
    audit_dnssec,
    build_message_analysis_report,
    DNSClient,
    derive_cross_findings,
    normalize_target,
    estimate_dkim_rsa_bits,
)


# Map email_audit.py severity strings to Vikramaditya's 4-level scale.
_SEVERITY_MAP = {
    "critical": "high",       # subspace "critical" = config gap, not RCE
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "notice": "info",
}

# Map email_audit.py check areas to Vikramaditya's ``vuln_class`` taxonomy.
_AREA_TO_VULN_CLASS = {
    "spf": "email_spf",
    "dmarc": "email_dmarc",
    "dkim": "email_dkim",
    "mx": "email_mx",
    "mta_sts": "email_mta_sts",
    "tls_rpt": "email_tls_rpt",
    "bimi": "email_bimi",
    "dnssec": "email_dnssec",
}


def _to_schema_severity(raw: str | None) -> str:
    if not raw:
        return "info"
    return _SEVERITY_MAP.get(raw.lower(), "info")


def _to_vuln_class(area: str) -> str:
    return _AREA_TO_VULN_CLASS.get(area.lower(), f"email_{area.lower()}")


def to_finding_entries(
    audit_report: dict[str, Any],
    target: str,
) -> list[dict[str, Any]]:
    """Convert an ``email_audit.py`` JSON report into Vikramaditya findings.

    Each issue across every check becomes a finding dict with the
    ``memory/schemas.py::make_journal_entry`` shape (subset — only fields
    meaningful at discovery time are set). Entries are safe to JSON-dump
    and pass into ``HuntJournal.append`` or the HTML reporter directly.

    Input ``audit_report`` is whatever ``email_audit.py --json`` writes:
    ``{"summary": {...}, "checks": {"spf": {...}, "dmarc": {...}, ...}}``.
    """
    findings: list[dict[str, Any]] = []
    if not isinstance(audit_report, dict):
        return findings
    checks = audit_report.get("checks") or {}
    if not isinstance(checks, dict):
        return findings

    for area, data in checks.items():
        if not isinstance(data, dict):
            continue
        issues = data.get("issues") or []
        if not isinstance(issues, list):
            continue
        for issue in issues:
            if not isinstance(issue, dict):
                continue
            severity = _to_schema_severity(issue.get("severity"))
            title = issue.get("title") or f"{area.upper()} issue"
            detail = issue.get("detail") or ""
            recommendation = issue.get("recommendation") or ""
            notes = detail
            if recommendation:
                notes = f"{detail}\n\nFix: {recommendation}" if detail else f"Fix: {recommendation}"
            findings.append({
                "target": target,
                "action": "recon",
                "vuln_class": _to_vuln_class(area),
                "endpoint": f"dns:{area}:{target}",
                "result": "confirmed",
                "severity": severity,
                "notes": notes,
                "tags": ["email_auth", area, "subspace_sentinel"],
                "title": title,
                "area": area,
            })

    # Cross-findings (e.g. "SPF+DMARC+DKIM all permissive → spoofable")
    for cross in audit_report.get("cross_findings", []) or []:
        if not isinstance(cross, dict):
            continue
        findings.append({
            "target": target,
            "action": "scan",
            "vuln_class": "email_posture",
            "endpoint": f"dns:posture:{target}",
            "result": "confirmed",
            "severity": _to_schema_severity(cross.get("severity")),
            "notes": cross.get("detail", ""),
            "tags": ["email_auth", "cross_finding", "subspace_sentinel"],
            "title": cross.get("title") or "Email auth cross-finding",
            "area": "cross",
        })

    return findings


def load_and_convert(audit_json_path: str, target: str) -> list[dict[str, Any]]:
    """Read a saved ``audit.json`` and return converted findings."""
    if not os.path.isfile(audit_json_path):
        return []
    try:
        report = json.load(open(audit_json_path))
    except (OSError, ValueError):
        return []
    return to_finding_entries(report, target)


def severity_histogram(findings: Iterable[dict[str, Any]]) -> dict[str, int]:
    """Quick ``{severity: count}`` roll-up for log lines."""
    hist: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info")
        hist[sev] = hist.get(sev, 0) + 1
    return hist


# ---------------------------------------------------------------------------
# v7.4.0 — brain.py LLM bridge
# ---------------------------------------------------------------------------
# ``email_audit.py`` ships its own ~300-line multi-provider LLM dispatcher
# (Ollama/Claude/OpenAI/xAI/Gemini) with a parallel ``.env`` schema. That's
# duplicated work — Vikramaditya's ``brain.py`` already does exactly this
# via ``LLMClient`` with shared env-var conventions and fallback chain.
#
# This bridge lets callers ask for an AI summary **through brain.py** so
# there's one provider config to maintain. The monolith's own dispatcher
# stays intact as a fallback for standalone-CLI users who don't want to
# depend on brain.py. Opt-in per call.

_BRAIN_SUMMARY_PROMPT = """You are a mail-security auditor. Summarise the JSON \
email-auth report below in 6-10 bullet points.

Cover: overall posture verdict (good / mixed / weak / spoofable), the 3 \
highest-severity issues in order, any cross-finding that escalates (e.g. \
SPF+DMARC+DKIM all permissive = spoofable), one recommendation per issue, \
and one line on what a bug-bounty triager should care about.

Be precise. Cite the actual record strings where relevant. Do not invent \
facts not present in the JSON.

REPORT:
{report_json}
"""


def run_brain_summary(audit_report: dict[str, Any],
                      *, max_tokens: int = 700,
                      model: str | None = None) -> str | None:
    """Summarise an audit report through Vikramaditya's brain.py LLMClient.

    Returns the generated summary string, or ``None`` if ``brain.py`` isn't
    importable or no LLM provider is reachable. Falls back silently — this
    is an optional augmentation of the audit, not a requirement.

    The summary is deterministic w.r.t. the input JSON (no hidden context)
    — safe to cache by report hash if desired.

    Preferred over ``email_audit.py``'s built-in ``--ai-provider`` flag
    because it reads from the same env vars Vikramaditya uses elsewhere
    (``ANTHROPIC_API_KEY``, ``OPENAI_API_KEY``, ``XAI_API_KEY``,
    ``OLLAMA_HOST``) rather than the subspace-specific ones.
    """
    try:
        from brain import LLMClient
    except Exception:
        return None

    try:
        client = LLMClient()
    except Exception:
        return None
    if not getattr(client, "available", False):
        return None

    payload = json.dumps(audit_report, separators=(",", ":"))
    # Clip extremely large reports — most LLMs cap at 128k context.
    if len(payload) > 60_000:
        payload = payload[:60_000] + "...[truncated]"

    prompt = _BRAIN_SUMMARY_PROMPT.format(report_json=payload)
    try:
        return client.chat(
            model=model,
            system="You are an email security auditor. Output only the summary.",
            user=prompt,
            max_tokens=max_tokens,
            temperature=0.1,
        ) or None
    except Exception:
        return None
