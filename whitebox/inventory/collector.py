from __future__ import annotations
import json
from pathlib import Path
from whitebox.profiles import CloudProfile

# Service → (boto3 client, list method, region scope)
# region scope: "regional" iterates profile.regions; "global" calls once.
SERVICE_PULLS = {
    "ec2":            ("ec2",            "describe_instances",                "regional"),
    "ec2_sg":         ("ec2",            "describe_security_groups",          "regional"),
    "ec2_vpc":        ("ec2",            "describe_vpcs",                     "regional"),
    "s3":             ("s3",             "list_buckets",                      "global"),
    "iam_users":      ("iam",            "list_users",                        "global"),
    "iam_roles":      ("iam",            "list_roles",                        "global"),
    "iam_policies":   ("iam",            "list_policies",                     "global"),
    "rds":            ("rds",            "describe_db_instances",             "regional"),
    "lambda":         ("lambda",         "list_functions",                    "regional"),
    "ecs":            ("ecs",            "list_clusters",                     "regional"),
    "eks":            ("eks",            "list_clusters",                     "regional"),
    "elbv2":          ("elbv2",          "describe_load_balancers",           "regional"),
    "apigateway":     ("apigateway",     "get_rest_apis",                     "regional"),
    "apigatewayv2":   ("apigatewayv2",   "get_apis",                          "regional"),
    "cloudfront":     ("cloudfront",     "list_distributions",                "global"),
    "route53":        ("route53",        "list_hosted_zones",                 "global"),
    "ssm":            ("ssm",            "describe_parameters",               "regional"),
    "secretsmanager": ("secretsmanager", "list_secrets",                      "regional"),
    "kms":            ("kms",            "list_keys",                         "regional"),
    "wafv2":          ("wafv2",          "list_web_acls",                     "regional"),
    "logs":           ("logs",           "describe_log_groups",               "regional"),
    "codecommit":     ("codecommit",     "list_repositories",                 "regional"),
    "ecr":            ("ecr",            "describe_repositories",             "regional"),
    "guardduty":      ("guardduty",      "list_detectors",                    "regional"),
    "cloudtrail":     ("cloudtrail",     "describe_trails",                   "regional"),
    "config":         ("config",         "describe_configuration_recorders",  "regional"),
}

DEFAULT_SERVICES = list(SERVICE_PULLS.keys())


def collect_service(profile: CloudProfile, service_key: str, out_dir: Path) -> dict:
    """Pull one service across all regions (or once for global). Writes JSON files."""
    if service_key not in SERVICE_PULLS:
        return {"service": service_key, "status": "unknown_service"}
    client_name, method, scope = SERVICE_PULLS[service_key]
    svc_dir = out_dir / service_key
    svc_dir.mkdir(parents=True, exist_ok=True)

    regions = ["global"] if scope == "global" else profile.regions
    region_results: dict[str, str] = {}

    for region in regions:
        try:
            kwargs = {} if scope == "global" else {"region_name": region}
            client = profile._session.client(client_name, **kwargs)
            if client.can_paginate(method):
                paginator = client.get_paginator(method)
                pages = list(paginator.paginate())
                # Merge pages by concatenating all top-level list values
                merged: dict = {}
                for page in pages:
                    page.pop("ResponseMetadata", None)
                    for k, v in page.items():
                        if isinstance(v, list):
                            merged.setdefault(k, []).extend(v)
                        else:
                            merged.setdefault(k, v)
                data = merged
            else:
                data = getattr(client, method)()
                data.pop("ResponseMetadata", None)
            (svc_dir / f"{region}.json").write_text(
                json.dumps(data, indent=2, default=str)
            )
            region_results[region] = "ok"
        except Exception as e:
            region_results[region] = f"error({type(e).__name__}): {e!s}"

    return {"service": service_key, "regions": region_results}


def collect_all(profile: CloudProfile, out_dir: Path,
                services: list[str] | None = None) -> dict:
    """Collect all (or selected) services. Returns summary dict."""
    services = services or DEFAULT_SERVICES
    summary = {
        "account_id": profile.account_id,
        "profile": profile.name,
        "services": {},
    }
    for svc in services:
        summary["services"][svc] = collect_service(profile, svc, out_dir)
    return summary
