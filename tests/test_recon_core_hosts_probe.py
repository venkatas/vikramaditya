"""P1 — recon must ALWAYS probe the core hosts (apex/www/target) in isolation, so a
CDN/WAF-throttled mass probe (huge wildcard/brute set) or an empty enumeration can't
yield a false "0 live hosts" for a site that is actually up.

Real runs: a wildcard-inflated domain (1502-host flood → CDN throttle → live www marked dead) and
a WAF-fronted apex with 0 enumerated subdomains both returned 0 live.
"""
from pathlib import Path
RECON = (Path(__file__).resolve().parent.parent / "recon.sh").read_text()


def test_core_hosts_probe_exists_isolated_and_browser_ua():
    assert ".core_hosts.txt" in RECON, "no dedicated core-hosts probe"
    i = RECON.index(".core_hosts.txt")
    seg = RECON[i:i+1400]
    assert 'echo "$TARGET"' in seg and 'www.$TARGET' in seg, "core set is not apex/www/target"
    assert "User-Agent: Mozilla" in seg, "core probe lacks a browser User-Agent"
    assert "-rate-limit 5" in seg and "-threads 2" in seg, "core probe is not low-concurrency/isolated"
    assert "-retries 1" in seg, "core probe has no retries"


def test_core_probe_runs_before_mass_loop():
    # must be seeded before the batch split, so the flood can't collateral-kill it
    assert RECON.index(".core_hosts.txt") < RECON.index('split -l "$BATCH_SIZE"'), \
        "core-hosts probe runs AFTER the mass batch loop (flood can throttle it first)"


def test_httpx_full_deduped_by_url():
    assert "!seen[$1]++" in RECON, "httpx_full.txt not deduped by URL (core result must win)"


def test_core_probe_respects_scope_lock():
    # www is force-added only when in scope; the core set is scope-filtered too
    i = RECON.index(".core_hosts.txt")
    seg = RECON[i:i+1400]
    assert '_host_in_scope "www.$TARGET"' in seg and "_scope_filter_file" in seg


def test_core_probe_has_curl_fallback():
    # httpx intermittently trips CDN bot-mitigation; a curl fallback must recover the core hosts
    i = RECON.index(".core_hosts.txt")
    seg = RECON[i:i+2200]
    assert "curl fallback" in seg.lower(), "no curl fallback when httpx core-probe returns empty"
    assert "curl -sk" in seg and "%{http_code}" in seg, "curl fallback does not synthesize a live line"

