from __future__ import annotations
from pathlib import Path
from whitebox.models import Finding, Severity, CloudContext
from whitebox.profiles import CloudProfile
from whitebox.secrets.detectors import scan_text

MAX_STREAMS_PER_GROUP = 5
MAX_EVENTS_PER_STREAM = 200


def scan(profile: CloudProfile, target_groups: list[str],
         secrets_dir: Path | None = None) -> list[Finding]:
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
                streams = client.describe_log_streams(
                    logGroupName=group, orderBy="LastEventTime",
                    descending=True, limit=MAX_STREAMS_PER_GROUP,
                )
            except Exception:
                continue
            for s in streams.get("logStreams", []):
                try:
                    events = client.get_log_events(
                        logGroupName=group, logStreamName=s["logStreamName"],
                        limit=MAX_EVENTS_PER_STREAM,
                    )
                except Exception:
                    continue
                for ev in events.get("events", []):
                    msg = ev.get("message", "")
                    ev_ts = ev.get("timestamp", 0)
                    for hit in scan_text(msg, source=f"logs:{group}:{s['logStreamName']}"):
                        safe_group = group.strip('/').replace('/', '_')
                        safe_stream = s['logStreamName'].replace('/', '_')
                        fid = f"secret-logs-{profile.account_id}-{region}-{safe_group}-{safe_stream}-{ev_ts}-{hit['offset']}-{hit['detector']}"
                        if secrets_dir is not None:
                            from whitebox.secrets.redactor import write_evidence as _we
                            evidence = _we(secrets_dir, fid, [hit])
                        else:
                            evidence = Path("secrets") / f"{fid}.json"
                        findings.append(Finding(
                            id=fid,
                            source="secrets",
                            rule_id=f"secrets.cloudwatch_logs.{hit['detector']}",
                            severity=Severity.HIGH,
                            title=f"Secret in CloudWatch log ({group})",
                            description=f"{hit['detector']} matched in log group {group}, stream {s['logStreamName']} (region {region}, account {profile.account_id}). Preview: {hit['preview']}",
                            asset=None,
                            evidence_path=evidence,
                            cloud_context=CloudContext(
                                account_id=profile.account_id, region=region, service="logs",
                                arn=f"arn:aws:logs:{region}:{profile.account_id}:log-group:{group}",
                            ),
                        ))
    return findings
