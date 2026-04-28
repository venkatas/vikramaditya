from __future__ import annotations
from html import escape
from whitebox.models import Finding


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
        parts.append(f'<p>Exposed ports: <code>{", ".join(map(str, ctx.exposed_ports))}</code></p>')
    if ctx.exposed_cidrs:
        parts.append(f'<p>Exposed CIDRs: <code>{", ".join(map(escape, ctx.exposed_cidrs))}</code></p>')
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
