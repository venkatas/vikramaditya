# Remediation Pack — Generic Templates

Drop-in fix templates that map to common findings produced by the VAPT
engine. Use these as the starting point for an engagement-specific pack:

```bash
# Per-engagement workflow (the per-engagement copy is gitignored)
mkdir -p ../../client_remediation_pack/<engagement>
cp -r * ../../client_remediation_pack/<engagement>/
# Then edit each file, replacing placeholders below with engagement-specific values.
```

## Placeholders used in templates

| Placeholder | Replace with | Example |
|---|---|---|
| `<APEX_DOMAIN>` | client's apex domain | `example.com` |
| `<API_HOST>` | FastAPI / API app hostname | `api.example.com` |
| `<WP_USERNAME>` | confirmed WordPress username | (whatever user-enum surfaced) |
| `<ALB_NAME>` | AWS ALB name | from `aws elbv2 describe-load-balancers` |
| `<ALB_SG_ID>` | ALB security group ID | `sg-xxxxxxxxxxxxxxxxx` |
| `<WAF_ACL_NAME>` / `<WAF_ACL_ID>` | WAFv2 Web ACL identifier | from `aws wafv2 list-web-acls` |
| `<AWS_ACCOUNT_ID>` | client AWS account number | 12-digit |
| `<AWS_REGION>` | client AWS region | `ap-south-1` |
| `<S3_BUCKETS>` | bucket names lacking PAB | one per line |
| `<STRAY_INGRESS_PORT>` / `<STRAY_INGRESS_CIDR>` | stray SG ingress to remove | `943` / `1.2.3.4/32` |

## Files

| File | Fixes | Where it applies |
|---|---|---|
| `01_view_xss_fix.html.patch` | Stored XSS via unescaped CSV-cell rendering in eval-viewer style HTML | FastAPI / Flask / static template serving the viewer |
| `02_wordpress_cors_fix.php` | Reflective CORS + credentials on `/wp-json/*` | WP `wp-content/mu-plugins/` |
| `03_fastapi_auth_fix.py` | Unauth admin/data routes; oversize uploads; missing rate limits | FastAPI app constructor + route decorators |
| `04_fastapi_prod_config.py` | `/docs`, `/redoc`, `/openapi.json` exposed in production | FastAPI app entrypoint |
| `05_wp_user_enum_fix.php` | `/wp-json/wp/v2/users` + `?author=N` user enum | WP `wp-content/mu-plugins/` |
| `06_aws_devops_remediation.sh` | S3 PAB, ALB HTTP→HTTPS redirect, stray SG ingress, WAF rate-rule actions, log redaction, log lifecycle | DevOps (admin AWS profile) |

Each fix file ends with a "Verification" section showing the curl/AWS-CLI command
to run after deploy that should produce the new (safe) response.

## Why client-specific instances are gitignored

`client_remediation_pack/` is in `.gitignore` because instances of these
templates contain client identifiers (target hostnames, AWS account IDs,
ALB names, security-group IDs, IP addresses, usernames, PoC artifact IDs)
that are part of the engagement and should never appear in a public
repository.

When sharing a remediation pack with a client, hand over the local
`client_remediation_pack/<engagement>/` folder directly (encrypted email,
secure file-share, or the engagement's ticket system) — never as a git
push.
