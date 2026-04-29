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
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                return fallback
            return parsed
        except Exception:
            return fallback

    def plan_phases(self, ctx: dict) -> list[str]:
        prompt = prompts.PLAN_PHASES.format(
            account_id=ctx.get("profile"), inventory_summary=ctx.get("services"))
        decision = self._ask_json(prompt, fallback={"order": DEFAULT_PHASE_ORDER})
        proposed = decision.get("order", DEFAULT_PHASE_ORDER)
        if not isinstance(proposed, list):
            proposed = DEFAULT_PHASE_ORDER
        # Defensibility: brain may reorder, but cannot drop required phases or
        # introduce unknown ones. Drop unknowns; append any missing required.
        valid_set = set(DEFAULT_PHASE_ORDER)
        cleaned = [p for p in proposed if p in valid_set]
        seen = set(cleaned)
        for required in DEFAULT_PHASE_ORDER:
            if required not in seen:
                cleaned.append(required)
        order = cleaned
        self.trace.log("plan_phases", input_summary=ctx,
                       decision={"order": order,
                                 "dropped": [p for p in (proposed or []) if p not in valid_set],
                                 "appended_missing": [p for p in DEFAULT_PHASE_ORDER if p not in (proposed or [])]})
        return order

    def select_secret_targets(self, inventory_summary: dict) -> dict:
        all_buckets = [b.get("name") for b in inventory_summary.get("buckets", []) if b.get("name")]
        all_lgs = [g.get("name") for g in inventory_summary.get("log_groups", []) if g.get("name")]
        fallback = {"buckets": all_buckets, "log_groups": all_lgs}
        prompt = prompts.SELECT_SECRET_TARGETS.format(
            buckets=all_buckets, log_groups=all_lgs)
        decision = self._ask_json(prompt, fallback=fallback)
        # Defensibility: brain selections MUST intersect with discovered inventory.
        # Any name not in the inventory is dropped (prevents hallucinated targets
        # from being scanned out-of-scope).
        bucket_set = set(all_buckets)
        lg_set = set(all_lgs)
        chosen_buckets = decision.get("buckets")
        chosen_lgs = decision.get("log_groups")
        if not isinstance(chosen_buckets, list):
            chosen_buckets = all_buckets
        if not isinstance(chosen_lgs, list):
            chosen_lgs = all_lgs
        out = {
            "buckets": [b for b in chosen_buckets if b in bucket_set],
            "log_groups": [g for g in chosen_lgs if g in lg_set],
        }
        self.trace.log("select_secret_targets",
                       input_summary={"bucket_count": len(all_buckets), "lg_count": len(all_lgs)},
                       decision={"buckets_chosen": len(out["buckets"]),
                                 "log_groups_chosen": len(out["log_groups"]),
                                 "dropped_buckets": [b for b in (chosen_buckets or []) if b not in bucket_set],
                                 "dropped_log_groups": [g for g in (chosen_lgs or []) if g not in lg_set]})
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
        used_fallback = False
        try:
            summary = self.brain.ask(prompts.EXECUTIVE_SUMMARY.format(
                findings_summary=[f.title for f in findings[:20]],
                chains_summary=[c.narrative for c in chains[:5]],
            ))
        except Exception:
            summary = ""
            used_fallback = True
        self.trace.log("write_executive_summary",
                       input_summary={"finding_count": len(findings), "chain_count": len(chains)},
                       decision={"summary_chars": len(summary), "used_fallback": used_fallback})
        return summary
