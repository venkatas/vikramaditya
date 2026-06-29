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


# ── fixB group recon.sh: additional confirmed-finding guards ─────────────────

# IDX 0: single-pass dnsx must NOT swallow timeout/SIGKILL and must fail-open
def test_single_pass_dnsx_captures_exit_and_fails_open():
    t = _t()
    # The single-pass branch must initialise DNSX_FAILED_CHUNKS and set it on failure
    assert "DNSX_FAILED_CHUNKS=0" in t, "DNSX_FAILED_CHUNKS not initialised (single-pass path leaves it unset)"
    assert "DNSX_FAILED_CHUNKS=1" in t, "single-pass dnsx failure does not mark DNSX_FAILED_CHUNKS"
    # The single-pass dnsx must be guarded by an if (exit captured), not `|| true`
    assert re.search(
        r'if timeout -k 30 300 dnsx -silent -a -l "\$RECON_DIR/subdomains/all\.txt"',
        t,
    ), "single-pass dnsx still swallows exit with `|| true` instead of capturing it"
    # On failure it must union the full candidate set back (fail-open)
    assert 'cat "$RECON_DIR/subdomains/all.txt" >> "$RECON_DIR/subdomains/resolved.txt"' in t, \
        "single-pass dnsx failure does not fail-open (union candidates back into resolved.txt)"


# IDX 1: Phase 3 / Phase 6 resume gate on completion markers, not partial data
def test_phase3_phase6_gate_on_completion_markers():
    t = _t()
    assert 'phase_done "$RECON_DIR/live/.probe.done"' in t, \
        "Phase-3 HTTP probe resume not gated on .probe.done completion marker"
    assert '> "$RECON_DIR/live/.probe.done"' in t, ".probe.done marker is never written"
    assert 'phase_done "$RECON_DIR/urls/.urls.done"' in t, \
        "Phase-6 URL collection resume not gated on .urls.done completion marker"
    assert '> "$RECON_DIR/urls/.urls.done"' in t, ".urls.done marker is never written"
    # The Phase-3 gate must NOT key on the partial-able httpx_full.txt data artefact
    assert 'phase_done "$RECON_DIR/live/httpx_full.txt"' not in t, \
        "Phase-3 still gates resume on the partial-able httpx_full.txt"


# IDX 2: Wayback + HackerTarget folded into the passive failure tally
def test_wayback_hackertarget_in_passive_tally():
    t = _t()
    assert "_WB_RAW" in t, "Wayback no longer captures raw body for transport-vs-empty distinction"
    assert "_HT_RAW" in t, "HackerTarget no longer captures raw body for transport-vs-empty distinction"
    # HackerTarget rate-limit sentinel must be detected before parsing
    assert "API count exceeded" in t, "HackerTarget rate-limit sentinel not detected"
    # All four sources named in the coverage warning
    assert "crt.sh/OTX/Wayback/HackerTarget" in t, \
        "passive-failure warning still names only crt.sh/OTX (Wayback/HackerTarget uncounted)"


# IDX 3: empty passive-source array must not abort under set -u on bash 3.2
def test_passive_merge_guards_empty_array():
    t = _t()
    # The authoritative merge must guard the zero-length array expansion.
    assert '[ "${#_PASSIVE_SUB_FILES[@]}" -eq 0 ]' in t, \
        "authoritative passive merge does not guard empty-array expansion (set -u abort on bash 3.2)"


# IDX 4: wildcard detection records the FULL round-robin IP set, not just r1
def test_wildcard_detection_collects_full_ip_set():
    t = _t()
    assert "WILDCARD_DNS_IPS" in t, "wildcard detection still records only the first A record (no WILDCARD_DNS_IPS set)"
    # The dig-filter must match against the wildcard IP set via grep -Fxv -f
    assert "grep -Fxv -f" in t, "dig-filter does not match against the full wildcard IP set"
    # head -1 must no longer truncate the per-label dig output in _detect_dns_wildcard
    start = t.index("_detect_dns_wildcard()")
    end = t.index("}", t.index("DNS wildcard detected", start))
    body = t[start:end]
    assert 'A 2>/dev/null | head -1' not in body, \
        "_detect_dns_wildcard still truncates each probe to the first A record with head -1"
