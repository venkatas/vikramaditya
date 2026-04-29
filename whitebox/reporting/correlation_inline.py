from __future__ import annotations
from html import escape
from whitebox.models import Finding


def _format_ports(ports) -> str:
    """Compact list of ports for HTML display.
    - Detects full 0-65535 range and renders as "all ports".
    - Compacts contiguous runs into "lo-hi" segments.
    - Caps at 20 segments to keep reports compact.
    Each rendered token is HTML-escaped.
    """
    if not ports:
        return ""
    try:
        nums = sorted({int(p) for p in ports})
    except (TypeError, ValueError):
        # Fallback: stringify and escape each entry; defensible against malformed input
        return ", ".join(escape(str(p)) for p in ports)
    if not nums:
        return ""
    # Detect full range
    if nums[0] == 0 and nums[-1] == 65535 and len(nums) == 65536:
        return "all ports (0-65535)"
    # Compact contiguous runs
    segments: list[str] = []
    run_start = nums[0]
    prev = nums[0]
    for n in nums[1:]:
        if n == prev + 1:
            prev = n
            continue
        segments.append(f"{run_start}" if run_start == prev else f"{run_start}-{prev}")
        run_start = n
        prev = n
    segments.append(f"{run_start}" if run_start == prev else f"{run_start}-{prev}")
    if len(segments) > 20:
        segments = segments[:20] + [f"... +{len(segments) - 20} more"]
    return ", ".join(escape(s) for s in segments)


def render_for_finding(f: Finding) -> str:
    if not f.cloud_context:
        return ""
    ctx = f.cloud_context
    parts = [
        f'<div class="cloud-context"><h4>Cloud context</h4>',
        f'<p>Account: <code>{escape(ctx.account_id)}</code> · Region: <code>{escape(ctx.region)}</code> · Service: <code>{escape(ctx.service)}</code></p>',
        f'<p>ARN: <code>{escape(ctx.arn)}</code></p>',
    ]
    if ctx.iam_role_arn:
        parts.append(f'<p>IAM role: <code>{escape(ctx.iam_role_arn)}</code></p>')
    if ctx.blast_radius:
        br = ctx.blast_radius
        parts.append(
            f'<p>IAM blast radius: '
            f'{len(br.s3_buckets)} buckets · {len(br.kms_keys)} KMS keys · '
            f'{len(br.lambdas)} lambdas · {len(br.assumable_roles)} assumable roles</p>'
        )
    if ctx.exposed_ports:
        parts.append(f'<p>Exposed ports: <code>{_format_ports(ctx.exposed_ports)}</code></p>')
    if ctx.exposed_cidrs:
        parts.append(f'<p>Exposed CIDRs: <code>{", ".join(escape(str(c)) for c in ctx.exposed_cidrs)}</code></p>')
    if f.chain:
        c = f.chain
        parts.append('<h4>Auto-built chain</h4>')
        parts.append(f'<p><strong>Promoted severity: {escape(c.promoted_severity.label())}</strong> '
                     f'(rule: <code>{escape(c.promotion_rule)}</code>)</p>')
        parts.append(f'<p>{escape(c.narrative)}</p>')
        parts.append('<ol class="iam-path">' + "".join(
            f'<li><code>{escape(arn)}</code></li>' for arn in c.iam_path) + '</ol>')
    parts.append('</div>')
    return "\n".join(parts)
