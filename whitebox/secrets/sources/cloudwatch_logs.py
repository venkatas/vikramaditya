from __future__ import annotations
from pathlib import Path
from whitebox.models import Finding, Severity, CloudContext
from whitebox.profiles import CloudProfile
from whitebox.secrets.detectors import scan_text

MAX_EVENTS_PER_GROUP = 500


def scan(profile: CloudProfile, target_groups: list[str]) -> list[Finding]:
    if not target_groups:
        return []
    findings: list[Finding] = []
    for region in profile.regions:
        try:
            client = profile._session.client("logs", region_name=region)
        except Exception:
            continue
        for group in target_groups:
            try:
                streams = client.describe_log_streams(logGroupName=group, orderBy="LastEventTime", descending=True, limit=5)
            except Exception:
                continue
            count = 0
            for s in streams.get("logStreams", []):
                if count >= MAX_EVENTS_PER_GROUP:
                    break
                try:
                    events = client.get_log_events(logGroupName=group, logStreamName=s["logStreamName"], limit=200)
                except Exception:
                    continue
                for ev in events.get("events", []):
                    count += 1
                    for hit in scan_text(ev.get("message", ""), source=f"logs:{group}:{s['logStreamName']}"):
                        safe_group = group.strip('/').replace('/', '_')
                        fid = f"secret-logs-{profile.account_id}-{region}-{safe_group}-{hit['offset']}-{hit['detector']}"
                        findings.append(Finding(
                            id=fid,
                            source="secrets",
                            rule_id=f"secrets.cloudwatch_logs.{hit['detector']}",
                            severity=Severity.HIGH,
                            title=f"Secret in CloudWatch log ({group})",
                            description=f"{hit['detector']} matched in log group {group}, stream {s['logStreamName']} (region {region}, account {profile.account_id}). Preview: {hit['preview']}",
                            asset=None,
                            evidence_path=Path("secrets") / f"{fid}.json",
                            cloud_context=CloudContext(
                                account_id=profile.account_id, region=region, service="logs",
                                arn=f"arn:aws:logs:{region}:{profile.account_id}:log-group:{group}",
                            ),
                        ))
    return findings
