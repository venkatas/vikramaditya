from __future__ import annotations
from collections import Counter
from html import escape
from whitebox.models import Finding, Severity


def render(account_id: str, findings: list[Finding], executive_summary: str = "") -> str:
    if not findings:
        body = f"<p>No cloud findings for account <code>{escape(account_id)}</code>.</p>"
        return f'<section class="cloud-posture"><h2>Cloud Posture — Account {escape(account_id)} (0 findings)</h2>{body}</section>'

    by_sev = Counter(f.severity.label() for f in findings)
    by_source = Counter(f.source for f in findings)
    rows = "".join(
        f"<tr><td>{escape(f.severity.label())}</td><td>{escape(f.source)}</td>"
        f"<td>{escape(f.rule_id)}</td><td>{escape(f.title)}</td>"
        f"<td><code>{escape((f.cloud_context.arn if f.cloud_context else '') or '')}</code></td></tr>"
        for f in sorted(findings, key=lambda x: -int(x.severity))
    )
    sev_summary = " · ".join(f"{escape(k)}: {v}" for k, v in by_sev.most_common())
    src_summary = " · ".join(f"{escape(k)}: {v}" for k, v in by_source.most_common())
    return f"""
<section class="cloud-posture">
  <h2>Cloud Posture — Account {escape(account_id)}</h2>
  <p class="exec-summary">{escape(executive_summary)}</p>
  <p><strong>Severity:</strong> {sev_summary}<br>
     <strong>Source:</strong> {src_summary}</p>
  <table class="cloud-findings">
    <thead><tr><th>Severity</th><th>Source</th><th>Rule</th><th>Title</th><th>Resource</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>
"""
