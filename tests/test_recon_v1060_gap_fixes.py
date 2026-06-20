"""v10.6.0 recon.sh gap fixes — grep-style guards (synthetic, no live targets).

Each test pins a specific CONFIRMED-finding fix so a regression that silently
reverts the behaviour fails CI. These are intentionally text/structure assertions
(recon.sh is a long bash pipeline that can't be unit-imported); they encode the
exact invariant each fix establishes.
"""
import os
import re

RECON = os.path.join(os.path.dirname(__file__), "..", "recon.sh")


def _t():
    return open(RECON, encoding="utf-8", errors="replace").read()


# ── Finding 2/3: wildcard dig-filter ────────────────────────────────────────
def test_wildcard_dig_filter_gated_on_not_validated():
    t = _t()
    # The dig-filter block must be gated so it does NOT prune a dnsx-validated set.
    assert re.search(r'WILDCARD_DNS_IP:-\}.*\n.*DNS_VALIDATED:-0\} != "1"', t) or \
        '[ "${DNS_VALIDATED:-0}" != "1" ]' in t, \
        "wildcard dig-filter is not gated on DNS_VALIDATED!=1"


def test_wildcard_dig_filter_input_capped():
    t = _t()
    assert "DIG_FILTER_CAP" in t, "wildcard dig-filter second DNS pass is unbounded (no DIG_FILTER_CAP)"


def test_wildcard_dig_filter_fail_open():
    t = _t()
    # empty/timeout dig must KEEP the host (fail-open), not drop it
    assert re.search(r'if \[ -z "\$real" \]; then\s*\n\s*echo "\$host"', t), \
        "dig-filter is not fail-open on an empty/timeout dig"


# ── Finding 7: PROBE_CAP honesty + random sample ────────────────────────────
def test_probe_cap_keeps_resolved_count_honest():
    t = _t()
    assert "PROBED_COUNT" in t, "no separate PROBED_COUNT — RESOLVED_COUNT is still overwritten by the cap"
    # batch math must use the probe-set size, not the (now honest) RESOLVED_COUNT
    assert "(PROBED_COUNT + BATCH_SIZE - 1)" in t, "batch math does not use PROBED_COUNT"


def test_probe_cap_uses_random_sample_not_head():
    t = _t()
    assert "_rand_head" in t, "PROBE_CAP fill still uses deterministic alphabetical head truncation"
    assert re.search(r'shuf\b.*\n.*gshuf|gshuf', t) or "gshuf" in t, \
        "no gshuf/sort -R fallback for macOS (shuf absent)"


# ── Finding 8: katana host list ─────────────────────────────────────────────
def test_katana_host_cap_and_priority_order():
    t = _t()
    assert "KATANA_HOST_CAP" in t, "katana target cap not env-controllable"
    assert "medium_hosts.txt" in t and "low_hosts.txt" in t, \
        "katana list does not draw from all priority tiers"
    # order-preserving dedup (awk), not alphabetical sort -u | head
    assert "awk 'NF && !seen[$0]++'" in t, "katana list dedup does not preserve priority order"


# ── Finding 4: completion markers, not data artefacts ───────────────────────
def test_resume_gates_on_completion_markers():
    t = _t()
    assert 'phase_done "$RECON_DIR/subdomains/.enum.done"' in t, "Phase-1 resume not gated on .enum.done"
    assert 'phase_done "$RECON_DIR/subdomains/.dns.done"' in t, "Phase-2 resume not gated on .dns.done"
    assert '> "$RECON_DIR/subdomains/.enum.done"' in t, ".enum.done is never written"
    assert '> "$RECON_DIR/subdomains/.dns.done"' in t, ".dns.done is never written"


def test_emergency_merge_does_not_write_enum_done():
    """The early-exit safety-net merge must NOT mark enumeration complete."""
    t = _t()
    start = t.index("_emergency_merge_subs()")
    end = t.index("trap _emergency_merge_subs EXIT")
    body = t[start:end]
    assert ".enum.done" not in body, "emergency merge writes .enum.done (partial set looks complete)"


# ── Finding 5: passive transport-vs-empty distinction ───────────────────────
def test_crtsh_otx_distinguish_transport_failure():
    t = _t()
    assert "_CRTSH_RAW" in t and "_OTX_RAW" in t, "crt.sh/OTX no longer capture the raw body to validate it"
    # JSON-shape check before parsing
    assert re.search(r"grep -q '\^\[\[:space:\]\]\*\\\['", t), "crt.sh body is not validated as a JSON array"
    assert "transport failure" in t, "no warning distinguishing transport failure from genuine-empty"
    assert "--max-time 45" in t, "passive curl max-time not raised to >=45"
