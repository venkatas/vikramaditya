PLAN_PHASES = """You orchestrate a whitebox AWS audit of account {account_id}.
Inventory summary: {inventory_summary}
Choose phase order. Return JSON: {{"order": ["inventory", "prowler", "iam", "exposure", "secrets", "correlation", "report"]}}.
"""

SELECT_SECRET_TARGETS = """Pick which S3 buckets and CloudWatch log groups are most likely to contain secrets, based on names/tags.
Buckets: {buckets}
Log groups: {log_groups}
Return JSON: {{"buckets": ["..."], "log_groups": ["..."]}}.
"""

FILTER_CHAINS = """Review candidate exploit chains. Drop false positives. Keep all rule-traced chains intact.
Chains: {chains}
Return JSON list of chain IDs to keep.
"""

EXECUTIVE_SUMMARY = """Write a 200-word executive summary of these findings for the client.
Findings: {findings_summary}
Chains: {chains_summary}
"""
