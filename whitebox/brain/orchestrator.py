from __future__ import annotations
import json
from pathlib import Path
from whitebox.brain.trace import BrainTrace
from whitebox.brain import prompts

DEFAULT_PHASE_ORDER = ["inventory", "prowler", "iam", "exposure", "secrets", "correlation", "report"]


class BrainOrchestrator:
    def __init__(self, brain, trace_path: Path):
        self.brain = brain
        self.trace = BrainTrace(trace_path)

    def _ask_json(self, prompt: str, fallback: dict) -> dict:
        try:
            raw = self.brain.ask(prompt)
            return json.loads(raw)
        except Exception:
            return fallback

    def plan_phases(self, ctx: dict) -> list[str]:
        prompt = prompts.PLAN_PHASES.format(
            account_id=ctx.get("profile"), inventory_summary=ctx.get("services"))
        decision = self._ask_json(prompt, fallback={"order": DEFAULT_PHASE_ORDER})
        order = decision.get("order", DEFAULT_PHASE_ORDER)
        self.trace.log("plan_phases", input_summary=ctx, decision={"order": order})
        return order

    def select_secret_targets(self, inventory_summary: dict) -> dict:
        all_buckets = [b.get("name") for b in inventory_summary.get("buckets", [])]
        all_lgs = [g.get("name") for g in inventory_summary.get("log_groups", [])]
        fallback = {"buckets": all_buckets, "log_groups": all_lgs}
        prompt = prompts.SELECT_SECRET_TARGETS.format(
            buckets=all_buckets, log_groups=all_lgs)
        decision = self._ask_json(prompt, fallback=fallback)
        out = {
            "buckets": decision.get("buckets", all_buckets),
            "log_groups": decision.get("log_groups", all_lgs),
        }
        self.trace.log("select_secret_targets",
                       input_summary={"bucket_count": len(all_buckets), "lg_count": len(all_lgs)},
                       decision=out)
        return out

    def filter_chains(self, candidates: list) -> list:
        # Defensibility: brain may only DROP chains, never ADD. Default keep all.
        prompt = prompts.FILTER_CHAINS.format(chains=[c.trigger_finding_id for c in candidates])
        decision = self._ask_json(prompt, fallback={"keep": [c.trigger_finding_id for c in candidates]})
        keep_ids = set(decision.get("keep", [c.trigger_finding_id for c in candidates]))
        kept = [c for c in candidates if c.trigger_finding_id in keep_ids]
        self.trace.log("filter_chains",
                       input_summary={"candidate_count": len(candidates)},
                       decision={"kept_count": len(kept)})
        return kept

    def write_executive_summary(self, findings: list, chains: list) -> str:
        try:
            return self.brain.ask(prompts.EXECUTIVE_SUMMARY.format(
                findings_summary=[f.title for f in findings[:20]],
                chains_summary=[c.narrative for c in chains[:5]],
            ))
        except Exception:
            return ""
