"""Regression tests for recon.sh audit fixes (v9.23).

End-to-end audit of a real run against clientd.com surfaced five bugs in
recon.sh. recon.sh is a large interactive shell pipeline that cannot be executed
wholesale in CI, so these tests assert (a) the script still parses (`bash -n`)
and (b) the corrected source-level invariants for each fix are present and the
known-bad patterns are gone. Where a fix has a self-contained shell predicate
(cdncheck flag-detection, JSON validation, the 301-catchall pre-flight), that
snippet is executed directly to prove the logic.

Fixes covered:
  1. SEVERE — Phase 2 did `cp all.txt resolved.txt` with NO resolution but logged
     "Resolved candidates: N". Now resolves with dnsx (when present) and labels
     unresolved candidates honestly; wildcard filter runs unconditionally.
  2. MED — cdncheck used `-json` (removed; current flag is `-jsonl`); the error
     string was written into cdn_map.json and logged as success. Now feature-
     detects the flag and validates output is real JSON.
  3. MED — asnmap blocks on an interactive PDCP key prompt and persists the
     prompt text as JSON. Now skips cleanly when no key, feeds </dev/null.
  4. LOW/perf — Phase-8 ffuf had no -maxtime, a fixed huge wordlist, and did not
     filter the 301 catchall. Now adds -maxtime-job, scales the wordlist for
     tiny surfaces, and excludes 301 when a catchall is detected.
  5. LOW — passive enum (crt.sh/OTX) used a single no-retry curl; failures were
     invisible. Now retries with a connect-timeout and warns on N/M-source-zero.
"""

import os
import subprocess

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RECON_SH = os.path.join(HERE, "recon.sh")


def _src():
    with open(RECON_SH, encoding="utf-8") as f:
        return f.read()


def test_bash_syntax_ok():
    """The whole script must still parse after the edits."""
    r = subprocess.run(["bash", "-n", RECON_SH], capture_output=True, text=True)
    assert r.returncode == 0, f"bash -n failed:\n{r.stderr}"


# ── Fix 1: real DNS resolution + honest labelling + unconditional wildcard ────
def test_fix1_dnsx_resolution_present():
    s = _src()
    # dnsx is invoked with -a (A-record filter), fed </dev/null so it cannot block
    assert "dnsx -silent -a -l" in s
    assert "dnsx -silent -a -l" in s and "</dev/null" in s
    # The misleading unconditional "Resolved candidates: N" log for an unresolved
    # cp is gone; replaced by branch-accurate labelling.
    assert "Resolved hosts:" in s          # dnsx path
    assert "Brute-force candidates:" in s  # no-resolver path, honest label
    assert "UNRESOLVED" in s


def test_fix1_wildcard_filter_not_dead_gated():
    s = _src()
    # The old extra gate `WILDCARD_DNS=1` must no longer guard the dig filter;
    # it now triggers solely on a captured wildcard IP (the correct signal).
    assert 'if [ -n "${WILDCARD_DNS_IP:-}" ] && command -v dig' in s
    assert '[ "${WILDCARD_DNS:-0}" = "1" ] && [ -n "${WILDCARD_DNS_IP:-}" ]' not in s


# ── Fix 2: cdncheck -jsonl + JSON validation ─────────────────────────────────
def test_fix2_no_bare_dash_json_invocation():
    s = _src()
    # The bug: literal `-json` passed to cdncheck. Ensure that exact bad call
    # (with -silent) is gone; only the feature-detected variable form remains.
    assert "cdncheck -i" in s
    assert '-resp -json -silent' not in s          # the original broken call
    assert 'cdncheck -i "$RECON_DIR/live/ips.txt" -resp "$CDN_JSON_FLAG"' in s
    assert "cdncheck: failed / produced no valid JSON" in s


def test_fix2_flag_detection_logic_executes():
    """The flag-detection predicate must pick -jsonl for new cdncheck help,
    and -json for an old help that exposes it."""
    detect = r'''
        CDN_JSON_FLAG="-jsonl"
        printf '%s\n' "$HELP" | grep -qE '(^|[^-])-json([^l]|$)' && CDN_JSON_FLAG="-json"
        echo "$CDN_JSON_FLAG"
    '''
    new_help = "   -j, -jsonl          write output in json(line) format"
    old_help = "   -json               write output in json format"
    new = subprocess.run(["bash", "-c", detect], env={**os.environ, "HELP": new_help},
                         capture_output=True, text=True)
    old = subprocess.run(["bash", "-c", detect], env={**os.environ, "HELP": old_help},
                         capture_output=True, text=True)
    assert new.stdout.strip() == "-jsonl", new.stdout
    assert old.stdout.strip() == "-json", old.stdout


def test_fix2_json_validation_rejects_error_string():
    """The 'first line must look like JSON' guard rejects an error line and
    accepts a JSON object line."""
    guard = r'''
        printf '%s\n' "$LINE" > "$TMP"
        if head -1 "$TMP" | grep -q '^[[:space:]]*[{[]'; then echo VALID; else echo INVALID; fi
    '''
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as t:
        tmp = t.name
    try:
        err = subprocess.run(["bash", "-c", guard],
                             env={**os.environ, "TMP": tmp,
                                  "LINE": "flag provided but not defined: -json"},
                             capture_output=True, text=True)
        ok = subprocess.run(["bash", "-c", guard],
                            env={**os.environ, "TMP": tmp,
                                 "LINE": '{"ip":"1.2.3.4","cdn":"cloudflare"}'},
                            capture_output=True, text=True)
        assert err.stdout.strip() == "INVALID", err.stdout
        assert ok.stdout.strip() == "VALID", ok.stdout
    finally:
        os.unlink(tmp)


# ── Fix 3: asnmap PDCP-key skip + </dev/null + no prompt-as-JSON ─────────────
def test_fix3_asnmap_skips_without_pdcp_key():
    s = _src()
    assert "ASNMAP_HAS_KEY" in s
    assert "asnmap: skipped — no PDCP_API_KEY set" in s
    # Must feed </dev/null so the interactive prompt can never block.
    assert 'asnmap -d "$TARGET" -silent -json </dev/null' in s
    # Must guard against persisting non-JSON (the prompt) as data.
    assert "discarded non-JSON output" in s


# ── Fix 4: ffuf -maxtime, wordlist scaling, 301-catchall filter ──────────────
def test_fix4_ffuf_maxtime_and_scaling_present():
    s = _src()
    assert "-maxtime-job" in s
    assert 'FFUF_MAXTIME="${FFUF_MAXTIME:-300}"' in s
    assert "FFUF_SMALL_WL" in s
    assert "tiny surface" in s
    # 301-catchall pre-flight must conditionally drop 301 from the match codes.
    assert "301 catchall" in s
    assert 'FFUF_MC="200,201,302,401,403,405"' in s   # 301 excluded variant


def test_fix4_catchall_preflight_logic():
    """A 301 catchall response must drop 301 from the match codes; any other
    code keeps the default match set (which still includes 301)."""
    logic = r'''
        FFUF_MC="200,201,301,302,401,403,405"
        CATCHALL_CODE="$CODE"
        if [ "$CATCHALL_CODE" = "301" ]; then
            FFUF_MC="200,201,302,401,403,405"
        fi
        echo "$FFUF_MC"
    '''
    is301 = subprocess.run(["bash", "-c", logic],
                           env={**os.environ, "CODE": "301"},
                           capture_output=True, text=True)
    is404 = subprocess.run(["bash", "-c", logic],
                           env={**os.environ, "CODE": "404"},
                           capture_output=True, text=True)
    assert "301" not in is301.stdout, is301.stdout
    assert "301" in is404.stdout, is404.stdout


# ── Fix 5: passive enum retries + N/M-zero warning ───────────────────────────
def test_fix5_passive_retries_and_warning():
    s = _src()
    # Both crt.sh and OTX curls now retry with a connect-timeout.
    assert s.count("--retry 2 --retry-delay 2") >= 2
    assert "--connect-timeout 10 --retry 2 --retry-delay 2" in s
    # Source tallies passive sources and warns when all returned zero.
    assert "PASSIVE_SOURCES_TOTAL" in s
    assert "PASSIVE_SOURCES_EMPTY" in s
    assert "passive returned 0 from" in s
