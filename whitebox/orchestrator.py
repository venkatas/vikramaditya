from __future__ import annotations
import json as _json
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
from whitebox.brain.orchestrator import BrainOrchestrator
from whitebox.reporting.evidence import dump_findings
from whitebox.cache.manifest import PhaseCache
from whitebox.models import Finding, Severity, CloudContext


def _persist_phase_findings(account_dir: Path, phase: str, findings: list[Finding]) -> None:
    """Write per-phase finding artifacts so cached re-runs can reload."""
    path = account_dir / f"phase_{phase}_findings.json"
    path.write_text(_json.dumps([f.to_dict() for f in findings], indent=2, default=str))


def _load_phase_findings(account_dir: Path, phase: str) -> list[Finding]:
    """Reload findings from a previously-completed phase. Returns [] if missing/malformed."""
    path = account_dir / f"phase_{phase}_findings.json"
    if not path.exists():
        return []
    try:
        data = _json.loads(path.read_text())
    except Exception:
        return []
    out: list[Finding] = []
    for d in data:
        try:
            ctx = d.get("cloud_context")
            cc = CloudContext(**{k: v for k, v in ctx.items() if k != "blast_radius"}) if ctx else None
            out.append(Finding(
                id=d["id"], source=d["source"], rule_id=d["rule_id"],
                severity=Severity[d["severity"].upper()],
                title=d["title"], description=d["description"],
                asset=None, evidence_path=Path(d["evidence_path"]),
                cloud_context=cc,
            ))
        except Exception:
            continue
    return out


def _build_instance_sg_map(inv_dir: Path) -> dict[str, list[str]]:
    """Walk EC2 inventory and build {instance_id: [sg_id, ...]}."""
    out: dict[str, list[str]] = {}
    ec2_dir = inv_dir / "ec2"
    if not ec2_dir.exists():
        return out
    for f in ec2_dir.glob("*.json"):
        try:
            data = _json.loads(f.read_text())
        except Exception:
            continue
        for resv in data.get("Reservations", []):
            for inst in resv.get("Instances", []):
                iid = inst.get("InstanceId")
                if not iid:
                    continue
                out[iid] = [g["GroupId"] for g in inst.get("SecurityGroups", []) if g.get("GroupId")]
    return out


def run_for_profile(profile_name: str, session_dir: Path,
                    refresh: bool = False, brain=None,
                    authorized_allowlist: list[str] | None = None) -> int:
    """End-to-end whitebox audit for one profile.
    Returns 0 if all phases completed successfully; nonzero (bitfield of failed phases) otherwise.
    Caller MUST pass authorized_allowlist explicitly. Pass ['*'] to disable scope-lock.
    """
    if authorized_allowlist is None:
        raise ValueError(
            "run_for_profile() requires authorized_allowlist. "
            "Pass the engagement's authorized domain list, or ['*'] to disable scope-locking."
        )
    session_dir = Path(session_dir)
    profile = validate(CloudProfile(name=profile_name))
    profile.in_scope_domains = route53.in_scope_domains(profile, authorized_allowlist=authorized_allowlist)

    account_dir = session_dir / "cloud" / profile.account_id
    account_dir.mkdir(parents=True, exist_ok=True)
    cache = PhaseCache(account_dir)
    if refresh:
        cache.refresh()
        # Clean phase artifact dirs so new evidence isn't polluted by stale runs
        import shutil as _shutil
        for sub in ("inventory", "prowler", "pmapper", "secrets", "exposure"):
            stale = account_dir / sub
            if stale.exists():
                _shutil.rmtree(stale, ignore_errors=True)
        # Also remove cached phase-finding artifacts
        for f in account_dir.glob("phase_*_findings.json"):
            try:
                f.unlink()
            except OSError:
                pass

    findings: list[Finding] = []
    failed_phases: list[str] = []

    # Phase A — inventory
    inv_dir = account_dir / "inventory"
    if not cache.is_fresh("inventory"):
        try:
            collector.collect_all(profile, inv_dir)
            cache.mark_complete("inventory")
        except Exception as e:
            cache.mark_failed("inventory", error=str(e))
            failed_phases.append("inventory")
    assets = normalizer.from_inventory_dir(profile.account_id, inv_dir)

    # Phase B — Prowler
    prowler_dir = account_dir / "prowler"
    if not cache.is_fresh("prowler"):
        try:
            ocsf = prowler_runner.run(profile, prowler_dir)
            phase_findings = prowler_to_findings(prowler_runner.parse(ocsf), profile.account_id)
            findings += phase_findings
            _persist_phase_findings(account_dir, "prowler", phase_findings)
            cache.mark_complete("prowler")
        except Exception as e:
            cache.mark_failed("prowler", error=str(e))
            failed_phases.append("prowler")
    else:
        findings += _load_phase_findings(account_dir, "prowler")

    # Phase C — IAM (PMapper)
    pmap_dir = account_dir / "pmapper"
    if not cache.is_fresh("iam"):
        try:
            graph_path = build_graph(profile, pmap_dir)
            graph = IAMGraph.load(graph_path)
            phase_findings = detect_paths(graph, profile.account_id)
            findings += phase_findings
            _persist_phase_findings(account_dir, "iam", phase_findings)
            cache.mark_complete("iam", artifacts={"graph": str(graph_path)})
        except Exception as e:
            cache.mark_failed("iam", error=str(e))
            failed_phases.append("iam")
    else:
        findings += _load_phase_findings(account_dir, "iam")

    # Phase D — Exposure
    if not cache.is_fresh("exposure"):
        try:
            sg_data: list[dict] = []
            sg_dir = inv_dir / "ec2_sg"
            if sg_dir.exists():
                for f in sg_dir.glob("*.json"):
                    try:
                        sg_data += _json.loads(f.read_text()).get("SecurityGroups", [])
                    except Exception:
                        continue
            sg_analysis = analyze_security_groups(sg_data)
            instance_sg_map = _build_instance_sg_map(inv_dir)
            assets = tag_assets(assets, instance_sg_map=instance_sg_map,
                                sg_analysis=sg_analysis, waf_protected_arns=set())
            cache.mark_complete("exposure")
        except Exception as e:
            cache.mark_failed("exposure", error=str(e))
            failed_phases.append("exposure")

    # Phase E — Secrets (brain selects targets when available; heuristic otherwise)
    secrets_dir = account_dir / "secrets"
    if not cache.is_fresh("secrets"):
        try:
            all_buckets = [a.name for a in assets if a.service == "s3"]
            # Discover log groups from inventory (logs/ subdir per region)
            all_log_groups: list[str] = []
            logs_dir = inv_dir / "logs"
            if logs_dir.exists():
                for f in logs_dir.glob("*.json"):
                    try:
                        d = _json.loads(f.read_text())
                        for lg in d.get("logGroups", []):
                            name = lg.get("logGroupName")
                            if name:
                                all_log_groups.append(name)
                    except Exception:
                        continue

            if brain is not None:
                bo = BrainOrchestrator(brain=brain, trace_path=account_dir / "brain_trace.jsonl")
                targets = bo.select_secret_targets({
                    "buckets": [{"name": n} for n in all_buckets],
                    "log_groups": [{"name": n} for n in all_log_groups],
                })
            else:
                # Default heuristic: name-match buckets/log groups whose names
                # suggest secret storage. Avoids the 79-minute scan-everything
                # behaviour observed in live smoke.
                _SECRET_HINTS = ("config", "secret", "backup", "dump", "infra",
                                 "dev", "env", "key", "cred", "private",
                                 "terraform", "tfstate", "passw", "token",
                                 ".env", "vault")
                def _looks_secret(name: str) -> bool:
                    n = (name or "").lower()
                    return any(h in n for h in _SECRET_HINTS)
                targets = {
                    "buckets": [b for b in all_buckets if _looks_secret(b)],
                    "log_groups": [g for g in all_log_groups if _looks_secret(g)],
                }
            phase_findings = run_secrets(profile, secrets_dir,
                                         target_buckets=targets["buckets"],
                                         target_log_groups=targets["log_groups"])
            findings += phase_findings
            _persist_phase_findings(account_dir, "secrets", phase_findings)
            cache.mark_complete("secrets")
        except Exception as e:
            cache.mark_failed("secrets", error=str(e))
            failed_phases.append("secrets")
    else:
        findings += _load_phase_findings(account_dir, "secrets")

    # Phase F — Per-profile asset feed (prevents multi-profile overwrite)
    if not cache.is_fresh("correlation"):
        try:
            asset_feed_path = (session_dir / "cloud" / "correlation")
            asset_feed_path.mkdir(parents=True, exist_ok=True)
            (asset_feed_path / f"asset_feed_{profile.account_id}.json").write_text(_json.dumps(
                [{"arn": a.arn, "service": a.service, "region": a.region, "name": a.name,
                  "public_dns": a.public_dns, "public_ip": a.public_ip, "tags": a.tags} for a in assets],
                indent=2,
            ))
            # Maintain combined asset_feed.json by merging all per-account feeds in this session
            all_feeds: list[dict] = []
            for feed in sorted(asset_feed_path.glob("asset_feed_*.json")):
                try:
                    all_feeds.extend(_json.loads(feed.read_text()))
                except Exception:
                    continue
            (asset_feed_path / "asset_feed.json").write_text(_json.dumps(all_feeds, indent=2))
            cache.mark_complete("correlation")
        except Exception as e:
            cache.mark_failed("correlation", error=str(e))
            failed_phases.append("correlation")

    # Phase G — Evidence dump (always runs to reflect current findings list)
    try:
        dump_findings(findings, account_dir / "findings.json")
        cache.mark_complete("report")
    except Exception as e:
        cache.mark_failed("report", error=str(e))
        failed_phases.append("report")

    # Return code: bitfield of failed phases. 0 if all good.
    PHASE_BITS = {"inventory": 1, "prowler": 2, "iam": 4, "exposure": 8,
                  "secrets": 16, "correlation": 32, "report": 64}
    rc = 0
    for p in failed_phases:
        rc |= PHASE_BITS.get(p, 128)
    return rc
