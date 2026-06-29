"""tool_router — deterministic, LLM-free tool selection + graceful degradation.

Centralizes the question "for capability X, which INSTALLED tool(s) do I run?" so the
orchestration layer stops hand-rolling ``shutil.which`` + ad-hoc fallback chains (today
scattered across ad_hunt._which, waf_bypass._which, and recon.sh's nmap->naabu->fingerprintx /
subzy->nuclei). Routing costs ZERO local-LLM cycles, and scans degrade gracefully when a binary
is missing on the operator box (a recurring macOS pain) instead of silently producing nothing.

CAPABILITY MODES (the key design point — a single-winner swap router loses most recon yield):
  * substitute — tools are interchangeable; run the first installed, SWAP to the next on failure
                 (e.g. http_probe httpx->curl, web_content_discovery, nuclei, sqlmap).
  * accumulate — tools are COMPLEMENTARY; run EVERY installed one and merge+dedupe their output
                 (e.g. subdomain_enum subfinder+assetfinder+amass, passive url_crawl gau+wayback).
  * pipeline   — tools are STAGES; a fast discoverer feeds an enricher
                 (e.g. port_scan: naabu/rustscan discover -> nmap -sV version-detect).

BOUNDARY (honest limitation): this module decides WHICH tool(s) run; it does NOT normalize their
heterogeneous output. accumulate/pipeline results still require the calling engine to merge/parse
into its canonical artifact paths — a per-capability output-adapter layer is the natural next
piece, not built here. Treat this as routing + degradation visibility, not a drop-in shim.

PROVENANCE: the capability->tool-effectiveness + tiered-fallback + failure-classifier shape is
inspired by hexstrike-ai's IntelligentDecisionEngine (MIT, github.com/0x4m4/hexstrike-ai), and
the substitute/accumulate/pipeline split + failure-action mapping were refined via adversarial
review (codex/grok/agy). Clean-room reimplementation in Vikramaditya's idiom — no code copied;
chains are Vikramaditya's own toolset (a subset of brain._CMD_ALLOWLIST). Unlike hexstrike it is
LOCAL/offline and drives no cloud MCP agent.
"""
import shutil

# Indirection so tests can inject availability without touching the real filesystem.
_which = shutil.which

# capability -> ordered preference chain (most-preferred first). Order favours yield-then-speed
# for an authorized engagement. Reordered per review: amass last (slow/hang-prone), passive vs
# active crawl split, nmap-led service fingerprint.
_CHAINS = {
    "port_scan":             ["naabu", "rustscan", "masscan", "nmap"],
    "service_fingerprint":   ["nmap", "fingerprintx"],
    "subdomain_enum":        ["subfinder", "assetfinder", "amass"],
    "subdomain_takeover":    ["subzy", "nuclei"],
    "http_probe":            ["httpx", "curl"],
    "url_crawl_passive":     ["gau", "waybackurls"],
    "url_crawl_active":      ["katana", "hakrawler"],
    "web_content_discovery": ["feroxbuster", "ffuf", "gobuster", "dirb"],
    "vuln_templates":        ["nuclei"],
    "xss":                   ["dalfox"],
    "sqli":                  ["sqlmap"],
    "dns_resolve":           ["dnsx", "dig", "host"],
    "secret_scan":           ["trufflehog", "gitleaks"],
    "cve_lookup":            ["cvemap"],
}

# How each capability's tools relate (see module docstring). Default is substitute.
_MODE = {
    "port_scan": "pipeline",
    "subdomain_enum": "accumulate",
    "url_crawl_passive": "accumulate",
}

# pipeline structure: a fast discoverer feeds an enricher. Each list is resolved to its first
# installed member; enrich is None when absent (discovery still runs, just without enrichment).
_PIPELINES = {
    "port_scan": {"discover": ["naabu", "rustscan", "masscan", "nmap"], "enrich": ["nmap"]},
}

# objective profiles: which capabilities to attempt, in order. 'quick' = high-yield only.
_OBJECTIVES = {
    "quick": ["http_probe", "vuln_templates", "web_content_discovery"],
    "comprehensive": [
        "subdomain_enum", "dns_resolve", "port_scan", "service_fingerprint",
        "http_probe", "url_crawl_passive", "url_crawl_active", "web_content_discovery",
        "vuln_templates", "subdomain_takeover", "xss", "sqli", "secret_scan",
    ],
    "stealth": ["http_probe", "vuln_templates"],
}

# Capabilities meaningless for a bare IP / CIDR (no DNS name to enumerate).
_HOST_ONLY_CAPS = {"subdomain_enum", "subdomain_takeover"}

_avail_cache: dict[str, bool] = {}


def reset_cache() -> None:
    """Clear memoized availability (call after the toolset/PATH changes, or in tests)."""
    _avail_cache.clear()


def available(tool: str) -> bool:
    """True if ``tool`` is on PATH. Memoized — a tool's presence does not change mid-run."""
    if tool not in _avail_cache:
        _avail_cache[tool] = _which(tool) is not None
    return _avail_cache[tool]


def mode(capability: str) -> str:
    """'substitute' (default) | 'accumulate' | 'pipeline' for ``capability``."""
    return _MODE.get(capability, "substitute")


def available_chain(capability: str) -> list:
    """INSTALLED tools for ``capability`` in preference order (empty if none / unknown)."""
    return [t for t in _CHAINS.get(capability, []) if available(t)]


def resolve(capability: str):
    """Highest-preference INSTALLED tool for ``capability``, or None (caller skips gracefully).

    For a pipeline capability this is the discovery tool. For substitute/accumulate it is the
    most-preferred installed tool (use tools_for()/accumulate_tools() to get the full set)."""
    if mode(capability) == "pipeline":
        return pipeline_plan(capability).get("discover")
    chain = available_chain(capability)
    return chain[0] if chain else None


def accumulate_tools(capability: str) -> list:
    """All INSTALLED tools for an accumulate capability (run them all, merge+dedupe output)."""
    return available_chain(capability)


def pipeline_plan(capability: str) -> dict:
    """For a pipeline capability, {'discover': tool|None, 'enrich': tool|None}; {} otherwise.

    The discover/enrich ROLES are the bridging CONTRACT for the calling engine: it runs the
    discover tool, then feeds that tool's results into the enrich tool (e.g. naabu's open ports
    become `nmap -sV -p <ports>`). The router names the roles; converting one stage's output into
    the next stage's input is the engine's job (the documented output-normalization boundary)."""
    spec = _PIPELINES.get(capability)
    if not spec:
        return {}
    def first(names):
        return next((t for t in names if available(t)), None)
    return {"discover": first(spec["discover"]), "enrich": first(spec["enrich"])}


def tools_for(capability: str) -> list:
    """The concrete tool(s) to run for ``capability`` given what's installed, in run order.
    substitute -> [winner]; accumulate -> [all installed]; pipeline -> [discover(, enrich)].
    Empty list == fully degraded (every option absent) -> the capability is skipped."""
    m = mode(capability)
    if m == "accumulate":
        return accumulate_tools(capability)
    if m == "pipeline":
        pp = pipeline_plan(capability)
        ordered = []
        for t in (pp.get("discover"), pp.get("enrich")):
            if t and t not in ordered:
                ordered.append(t)
        return ordered
    winner = resolve(capability)
    return [winner] if winner else []


def next_after(capability: str, failed_tool: str):
    """Next INSTALLED tool in the chain after ``failed_tool`` (substitute swap-on-failure), or None.
    ``failed_tool`` need not still be installed; located by position in the full chain."""
    full = _CHAINS.get(capability, [])
    if failed_tool not in full:
        return None
    for t in full[full.index(failed_tool) + 1:]:
        if available(t):
            return t
    return None


# ── failure classification ────────────────────────────────────────────────────
_RATE_LIMIT_SIGNS = ("429", "too many requests", "rate limit", "rate-limit", "ratelimited")
_PERMISSION_SIGNS = ("permission denied", "eacces", "operation not permitted",
                     "must be run as root", "requires root", "are you root")
_NETWORK_SIGNS = ("could not resolve", "name or service not known", "no route to host",
                  "connection refused", "network is unreachable", "connection timed out",
                  "no such host", "temporary failure in name resolution")
# NB: deliberately NOT "no such file or directory" — that also fires when a tool can't open an
# input artifact (wordlist/target file), and misclassifying THAT as a missing binary would swap
# to an alternative that hits the very same missing input. rc 127 + these specific strings only.
_MISSING_SIGNS = ("command not found", "not installed", "executable file not found")
_TIMEOUT_SIGNS = ("timed out", "timeout", "deadline exceeded", "context deadline")
_NOT_FOUND_SIGNS = ("404 not found", "404 ", "http 404", "not found (404)")


def classify_failure(returncode: int, stderr: str = "", stdout: str = "") -> str:
    """Classify a tool outcome: ok | missing | timeout | permission | rate_limit | network |
    not_found | other. Return-code signals are authoritative; otherwise message text is matched."""
    if returncode == 0:
        return "ok"
    if returncode == 127:
        return "missing"
    if returncode in (124, 137, 142):          # GNU timeout / 128+SIGKILL / 128+SIGALRM
        return "timeout"
    blob = f"{stderr}\n{stdout}".lower()
    if any(s in blob for s in _MISSING_SIGNS):
        return "missing"
    if any(s in blob for s in _PERMISSION_SIGNS):
        return "permission"
    if any(s in blob for s in _RATE_LIMIT_SIGNS):
        return "rate_limit"
    if any(s in blob for s in _NETWORK_SIGNS):
        return "network"
    if any(s in blob for s in _TIMEOUT_SIGNS):
        return "timeout"
    if any(s in blob for s in _NOT_FOUND_SIGNS):
        return "not_found"
    return "other"


# What to DO about each category (refined via review — biased toward graceful degradation, not
# aborting a whole phase):
#   continue -> success / empty-but-fine, proceed
#   swap     -> try the next available tool (this tool, not the target, is the problem)
#   retry    -> same tool, lower concurrency / longer timeout, then the caller may swap
#   backoff  -> same tool, wait out transient throttling / network blip, then retry
_ACTIONS = {
    "ok": "continue",
    "not_found": "continue",     # empty result (dead host / 404-heavy fuzz) must not kill the phase
    "missing": "swap",
    "permission": "swap",        # an unprivileged alternative may exist (naabu->nmap -sT)
    "other": "swap",
    "timeout": "retry",          # retry slower before giving up on the tool
    "rate_limit": "backoff",
    "network": "backoff",        # transient archive/DNS stalls; caller escalates after a retry budget
}


def recommend_action(category: str) -> str:
    """Map a classify_failure category to continue | swap | retry | backoff."""
    return _ACTIONS.get(category, "swap")


# Per-tool retry budget for the retry/backoff categories before escalating to a swap.
MAX_RETRIES = 2


def recover(capability: str, failed_tool: str, category: str, attempt: int = 0, tried=()):
    """Bounded recovery step for the caller's execution loop — GUARANTEES termination.

    Returns ``(action, tool)`` where action is one of continue | retry | backoff | swap | give_up
    and ``tool`` is the binary to run next (the same tool for retry/backoff, the next available
    chain member for swap, or None for continue/give_up).

    Loop-safety (the review concern): retry/backoff are capped at MAX_RETRIES per tool, then
    escalate to swap; swap walks the chain via next_after, skips already-``tried`` tools, and
    yields give_up once the chain is exhausted. The chain is finite and next_after advances
    monotonically, so no infinite retry or swap ping-pong is possible."""
    action = recommend_action(category)
    if action == "continue":
        return ("continue", None)
    if action in ("retry", "backoff"):
        if attempt < MAX_RETRIES:
            return (action, failed_tool)
        action = "swap"  # retry budget exhausted -> escalate
    if action == "swap":
        seen = set(tried) | {failed_tool}
        nxt = next_after(capability, failed_tool)
        while nxt and nxt in seen:
            nxt = next_after(capability, nxt)
        return ("swap", nxt) if nxt else ("give_up", None)
    return ("give_up", None)


# ── objective -> plan ─────────────────────────────────────────────────────────
def select_capabilities(objective: str = "comprehensive", target_type: str = None,
                        scope_lock: bool = False) -> list:
    """Ordered capabilities for ``objective``, filtered for target.

    Host-name-only capabilities (subdomain enum/takeover) are dropped when ``target_type`` is
    ip/cidr (no DNS name) OR ``scope_lock`` is set (exact-host engagement — mirrors the
    platform's --scope-lock, so the caller no longer has to remember to filter)."""
    caps = list(_OBJECTIVES.get(objective, []))
    if scope_lock or target_type in ("ip", "cidr"):
        caps = [c for c in caps if c not in _HOST_ONLY_CAPS]
    return caps


def plan(objective: str = "comprehensive", target_type: str = None,
         scope_lock: bool = False) -> list:
    """Deterministic scan plan: list of (capability, mode, tools) in run order. An empty tools
    list means the capability is fully degraded and will be SKIPPED."""
    return [(c, mode(c), tools_for(c))
            for c in select_capabilities(objective, target_type, scope_lock)]


def missing_capabilities(objective: str = "comprehensive", target_type: str = None,
                         scope_lock: bool = False) -> list:
    """Capabilities in ``objective`` with NO installed tool (fully degraded / will be skipped)."""
    return [c for c, _m, tools in plan(objective, target_type, scope_lock) if not tools]


def _main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Deterministic tool router / availability planner.")
    ap.add_argument("--objective", default="comprehensive",
                    choices=sorted(_OBJECTIVES), help="scan objective profile")
    ap.add_argument("--target-type", default=None,
                    choices=["url", "domain", "ip", "cidr"], help="narrow capabilities by target")
    args = ap.parse_args(argv)
    rows = plan(args.objective, args.target_type)
    print(f"# tool plan — objective={args.objective} target_type={args.target_type or 'any'}")
    for cap, m, tools in rows:
        shown = " + ".join(tools) if tools else "— (no tool installed; SKIPPED)"
        print(f"  {cap:24} [{m:10}] -> {shown}")
    missing = [c for c, _m, tools in rows if not tools]
    if missing:
        print(f"\n# degraded ({len(missing)}): {', '.join(missing)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
