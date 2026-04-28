#!/usr/bin/env bash
# AWS-side remediation script template
#
# Run with an admin AWS profile (NOT the read-only audit profile that the
# VAPT team uses). Every destructive command is gated by an interactive prompt.
#
# Before running, set the env vars below to engagement-specific values, OR
# edit the placeholders inline.
#
# What this script does:
#   1. Enable Public Access Block on N risky S3 buckets
#   2. Replace HTTP listener fixed-response with redirect to HTTPS
#   3. Remove a stray SG ingress rule (port + CIDR provided as args)
#   4. Print current WAF rate-rule actions for manual Count→Block flip
#   5. Stop redacting WAF log fields (Method, QueryString, UriPath)
#   6. Add a 30-day lifecycle policy on the WAF log bucket
#
# THIS IS A DESTRUCTIVE / LIVE-TRAFFIC SCRIPT. Read each command before
# confirming. Test in staging first if a staging WAF/ALB exists.

set -euo pipefail

PROFILE="${PROFILE:-<AWS_PROFILE_NAME>}"
REGION="${REGION:-<AWS_REGION>}"
ACCOUNT="${ACCOUNT:-<AWS_ACCOUNT_ID>}"

ALB_NAME="${ALB_NAME:-<ALB_NAME>}"
ALB_SG_ID="${ALB_SG_ID:-<ALB_SG_ID>}"
WAF_ACL_NAME="${WAF_ACL_NAME:-<WAF_ACL_NAME>}"
WAF_ACL_ID="${WAF_ACL_ID:-<WAF_ACL_ID>}"
WAF_LOG_BUCKET="${WAF_LOG_BUCKET:-<WAF_LOG_BUCKET>}"

STRAY_INGRESS_PORT="${STRAY_INGRESS_PORT:-<STRAY_INGRESS_PORT>}"
STRAY_INGRESS_CIDR="${STRAY_INGRESS_CIDR:-<STRAY_INGRESS_CIDR>}"

# Buckets that need PAB enabled — one per line.
BUCKETS=(
    "<S3_BUCKET_1>"
    "<S3_BUCKET_2>"
    "<S3_BUCKET_3>"
    # ...
)

confirm() {
    echo
    echo "ABOUT TO RUN: $1"
    read -r -p "  Proceed? [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] || { echo "  skipped"; return 1; }
}

# ─────────────────────────────────────────────────────────────────────────
# 1. S3 Public Access Block
# ─────────────────────────────────────────────────────────────────────────
for B in "${BUCKETS[@]}"; do
    [[ "$B" == "<"* ]] && continue  # skip un-substituted placeholder
    confirm "put-public-access-block on s3://$B" || continue
    aws s3api put-public-access-block \
        --bucket "$B" \
        --public-access-block-configuration \
            "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
        --profile "$PROFILE"
    echo "  ✓ PAB enabled on $B"
done

# ─────────────────────────────────────────────────────────────────────────
# 2. ALB port-80 listener: replace fixed-response with redirect to HTTPS
# ─────────────────────────────────────────────────────────────────────────
confirm "replace HTTP-listener fixed-response with 301 redirect to HTTPS" && {
    ALB_ARN=$(aws elbv2 describe-load-balancers \
        --names "$ALB_NAME" \
        --profile "$PROFILE" --region "$REGION" \
        --query 'LoadBalancers[0].LoadBalancerArn' --output text)

    LISTENER_80_ARN=$(aws elbv2 describe-listeners \
        --load-balancer-arn "$ALB_ARN" \
        --profile "$PROFILE" --region "$REGION" \
        --query 'Listeners[?Port==`80`].ListenerArn | [0]' --output text)

    aws elbv2 modify-listener \
        --listener-arn "$LISTENER_80_ARN" \
        --default-actions \
            'Type=redirect,RedirectConfig={Protocol=HTTPS,Port=443,Host=#{host},Path=/#{path},Query=#{query},StatusCode=HTTP_301}' \
        --profile "$PROFILE" --region "$REGION"
    echo "  ✓ port 80 now redirects to HTTPS"
}

# ─────────────────────────────────────────────────────────────────────────
# 3. Remove a stray SG ingress rule
# ─────────────────────────────────────────────────────────────────────────
confirm "revoke ingress tcp/${STRAY_INGRESS_PORT} from ${STRAY_INGRESS_CIDR} on ${ALB_SG_ID}" && {
    aws ec2 revoke-security-group-ingress \
        --group-id "$ALB_SG_ID" \
        --protocol tcp --port "$STRAY_INGRESS_PORT" \
        --cidr "$STRAY_INGRESS_CIDR" \
        --profile "$PROFILE" --region "$REGION"
    echo "  ✓ rule removed"
}

# ─────────────────────────────────────────────────────────────────────────
# 4. WAF — print current rate-rule actions for manual review
# ─────────────────────────────────────────────────────────────────────────
echo
echo "STEP 4 — WAF rate-rule action change is INTERACTIVE."
echo "  Current rule actions (review and flip Count → Block in the AWS console):"
aws wafv2 get-web-acl --scope REGIONAL \
    --name "$WAF_ACL_NAME" \
    --id "$WAF_ACL_ID" \
    --profile "$PROFILE" --region "$REGION" \
    --query 'WebACL.Rules[?contains(Name, `Rate`) || contains(Name, `DDoS`)].{Name:Name,Action:Action,Override:OverrideAction}'
echo
echo "  Recommended flip order:"
echo "    1. POST-rate rule       Count → Block  (safest first)"
echo "    2. GET-rate rule        Count → Block  (one week later)"
echo "    3. Global-rate rule     Count → Block  (one week later)"

# ─────────────────────────────────────────────────────────────────────────
# 5. WAF logging — stop redacting Method / QueryString / UriPath
# ─────────────────────────────────────────────────────────────────────────
confirm "remove Method/QueryString/UriPath redaction from WAF logging config" && {
    ACL_ARN="arn:aws:wafv2:${REGION}:${ACCOUNT}:regional/webacl/${WAF_ACL_NAME}/${WAF_ACL_ID}"
    cat > /tmp/waf_logging.json <<EOF
{
    "ResourceArn": "${ACL_ARN}",
    "LogDestinationConfigs": ["arn:aws:s3:::${WAF_LOG_BUCKET}"],
    "RedactedFields": [],
    "ManagedByFirewallManager": false,
    "LogType": "WAF_LOGS",
    "LogScope": "CUSTOMER"
}
EOF
    aws wafv2 put-logging-configuration \
        --logging-configuration "file:///tmp/waf_logging.json" \
        --profile "$PROFILE" --region "$REGION"
    echo "  ✓ redactions removed"
}

# ─────────────────────────────────────────────────────────────────────────
# 6. WAF log bucket — add 30-day lifecycle (cost + retention compliance)
# ─────────────────────────────────────────────────────────────────────────
confirm "add 30-day lifecycle expiration to s3://${WAF_LOG_BUCKET}" && {
    cat > /tmp/lifecycle.json <<'EOF'
{
    "Rules": [
        {
            "ID": "expire-waf-logs-after-30d",
            "Status": "Enabled",
            "Filter": {"Prefix": "AWSLogs/"},
            "Expiration": {"Days": 30},
            "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1}
        }
    ]
}
EOF
    aws s3api put-bucket-lifecycle-configuration \
        --bucket "$WAF_LOG_BUCKET" \
        --lifecycle-configuration file:///tmp/lifecycle.json \
        --profile "$PROFILE"
    echo "  ✓ 30-day lifecycle applied"
}

echo
echo "All requested AWS remediations complete or skipped per your choices."
echo "Re-run the read-only audit profile to verify."
