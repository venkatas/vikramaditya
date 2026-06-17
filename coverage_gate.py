"""Proportional finish-gating for the autonomous agent.

Adapted from xalgorix (MIT) — internal/agent/hooks.go (hookWorkTracker /
hookFinishGatekeeper).

The old gate was a flat `step_count < 6`: an agent could run recon + one tool against a
200-endpoint app and declare "done", silently missing whole vuln classes. This replaces it
with (1) an adaptive minimum scaled to the attack-surface size, and (2) a hard requirement
that the core high-value vuln classes are each at least attempted before a confident finish —
with a specific nudge naming what's still untested.
"""

# Agent tool name -> the vuln class it exercises.
TOOL_CLASS = {
    "run_recon": "recon",
    "run_vuln_scan": "web-vulns",
    "run_js_analysis": "js",
    "run_secret_hunt": "secrets",
    "run_param_discovery": "params",
    "run_post_param_discovery": "params",
    "run_api_fuzz": "api",
    "run_cors_check": "cors",
    "run_cms_exploit": "cms",
    "run_rce_scan": "rce",
    "run_sqlmap_targeted": "sqli",
    "run_sqlmap_on_file": "sqli",
    "run_jwt_audit": "jwt",
}

# High-value active test classes that should each be attempted before a confident
# finish. (recon/secrets/js are passive/always-run, so not gated on.)
CORE_CLASSES = {"web-vulns", "sqli", "rce", "cors", "jwt"}


def surface_tier(n_endpoints: int):
    """(tier, min_tool_floor) scaled to attack-surface size."""
    n = n_endpoints or 0
    if n <= 10:
        return ("small", 6)
    if n <= 100:
        return ("medium", 9)
    return ("large", 12)


def tested_classes(completed_steps) -> set:
    return {TOOL_CLASS[s] for s in (completed_steps or []) if s in TOOL_CLASS}


def untested_core(completed_steps) -> set:
    return CORE_CLASSES - tested_classes(completed_steps)


def can_finish(completed_steps, n_endpoints: int = 0, hard_floor: int = 6):
    """Return (allowed: bool, reason: str).

    Blocks finish when (a) fewer scan tools than the surface-scaled floor have run, or
    (b) a core vuln class has not been attempted. The reason names exactly what's missing
    so the agent can act on it instead of looping blindly.
    """
    steps = completed_steps or []
    tier, floor = surface_tier(n_endpoints)
    floor = max(floor, hard_floor)
    n_scan_tools = sum(1 for s in steps if s in TOOL_CLASS)

    if n_scan_tools < floor:
        return (False,
                f"only {n_scan_tools} scan tool(s) run on a {tier} surface "
                f"({n_endpoints} endpoints) — run at least {floor} before finishing.")

    missing = untested_core(steps)
    if missing:
        # map class -> a representative tool to suggest
        rep = {"web-vulns": "run_vuln_scan", "sqli": "run_sqlmap_targeted",
               "rce": "run_rce_scan", "cors": "run_cors_check", "jwt": "run_jwt_audit"}
        suggestions = ", ".join(sorted(rep.get(c, c) for c in missing))
        return (False,
                f"core vuln classes not yet tested: {sorted(missing)} — "
                f"run {suggestions} before finishing.")

    return (True, "coverage sufficient")
