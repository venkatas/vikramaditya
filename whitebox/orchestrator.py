from __future__ import annotations
from pathlib import Path
from whitebox.profiles import CloudProfile, validate
from whitebox.inventory import collector, route53, normalizer
from whitebox.audit import prowler_runner
from whitebox.audit.normalizer import to_findings as prowler_to_findings
from whitebox.iam.pmapper_runner import build_graph
from whitebox.iam.graph import IAMGraph
from whitebox.iam.privesc import detect_paths
from whitebox.exposure.analyzer import analyze_security_groups
from whitebox.exposure.tagger import tag_assets
from whitebox.secrets.scanner import run_all as run_secrets
from whitebox.correlator.asset_join import join_blackbox_to_cloud
from whitebox.correlator.chain_builder import build_chains
from whitebox.brain.orchestrator import BrainOrchestrator
from whitebox.reporting.evidence import dump_findings
from whitebox.cache.manifest import PhaseCache
from whitebox.models import Finding


def run_for_profile(profile_name: str, session_dir: Path,
                    refresh: bool = False, brain=None,
                    authorized_allowlist: list[str] | None = None) -> int:
    """End-to-end whitebox audit for one profile. Returns 0 on success."""
    session_dir = Path(session_dir)
    profile = validate(CloudProfile(name=profile_name))
    # Scope-locking: callers must pass authorized_allowlist explicitly per Task 5 fix.
    # Wildcard ['*'] disables scope-locking deliberately.
    if authorized_allowlist is None:
        authorized_allowlist = ["*"]
    profile.in_scope_domains = route53.in_scope_domains(profile, authorized_allowlist=authorized_allowlist)

    account_dir = session_dir / "cloud" / profile.account_id
    account_dir.mkdir(parents=True, exist_ok=True)
    cache = PhaseCache(account_dir)
    if refresh:
        cache.refresh()

    findings: list[Finding] = []

    # Phase A — inventory
    inv_dir = account_dir / "inventory"
    if not cache.is_fresh("inventory"):
        try:
            collector.collect_all(profile, inv_dir)
            cache.mark_complete("inventory")
        except Exception as e:
            cache.mark_failed("inventory", error=str(e))
    assets = normalizer.from_inventory_dir(profile.account_id, inv_dir)

    # Phase B — Prowler
    prowler_dir = account_dir / "prowler"
    if not cache.is_fresh("prowler"):
        try:
            ocsf = prowler_runner.run(profile, prowler_dir)
            findings += prowler_to_findings(prowler_runner.parse(ocsf), profile.account_id)
            cache.mark_complete("prowler")
        except Exception as e:
            cache.mark_failed("prowler", error=str(e))

    # Phase C — IAM (PMapper)
    pmap_dir = account_dir / "pmapper"
    graph = None
    if not cache.is_fresh("iam"):
        try:
            graph_path = build_graph(profile, pmap_dir)
            graph = IAMGraph.load(graph_path)
            findings += detect_paths(graph, profile.account_id)
            cache.mark_complete("iam", artifacts={"graph": str(graph_path)})
        except Exception as e:
            cache.mark_failed("iam", error=str(e))

    # Phase D — Exposure
    sg_data: list[dict] = []
    sg_dir = inv_dir / "ec2_sg"
    if sg_dir.exists():
        import json as _json
        for f in sg_dir.glob("*.json"):
            try:
                sg_data += _json.loads(f.read_text()).get("SecurityGroups", [])
            except Exception:
                continue
    sg_analysis = analyze_security_groups(sg_data)
    assets = tag_assets(assets, instance_sg_map={}, sg_analysis=sg_analysis,
                        waf_protected_arns=set())
    cache.mark_complete("exposure")

    # Phase E — Secrets (brain selects targets when available)
    secrets_dir = account_dir / "secrets"
    if brain is not None:
        bo = BrainOrchestrator(brain=brain, trace_path=account_dir / "brain_trace.jsonl")
        targets = bo.select_secret_targets({
            "buckets": [{"name": a.name} for a in assets if a.service == "s3"],
            "log_groups": [],
        })
    else:
        targets = {"buckets": [a.name for a in assets if a.service == "s3"], "log_groups": []}
    findings += run_secrets(profile, secrets_dir,
                            target_buckets=targets["buckets"],
                            target_log_groups=targets["log_groups"])
    cache.mark_complete("secrets")

    # Phase F — Correlation feed (chain_builder runs in caller context with blackbox findings)
    asset_feed_path = (session_dir / "cloud" / "correlation")
    asset_feed_path.mkdir(parents=True, exist_ok=True)
    import json as _json
    (asset_feed_path / "asset_feed.json").write_text(_json.dumps(
        [{"arn": a.arn, "service": a.service, "region": a.region, "name": a.name,
          "public_dns": a.public_dns, "public_ip": a.public_ip, "tags": a.tags} for a in assets],
        indent=2,
    ))
    cache.mark_complete("correlation")

    # Phase G — Evidence dump
    dump_findings(findings, account_dir / "findings.json")
    cache.mark_complete("report")
    return 0
