"""recon.sh must RESOLVE large candidate lists (deduped, suffix-safe chunks), never SKIP
resolution, and must BOUND the alterx permutation explosion at the source.

A government-scale wildcard estate enumerated ~860k unique / 24M raw candidates (alterx permutations).
The old code skipped dnsx resolution whenever the list exceeded DNSX_CAP and `cp all.txt resolved.txt`'d
the raw UNRESOLVED list — httpx then surfaced only a handful of apex hosts, silently missing every real
application/admin subdomain. The "0 verified vulns" result was a coverage failure. These guard the fix and
the issues independent review caught (split-suffix exhaustion + unbounded alterx + dedup).
"""
import os
import re

RECON = os.path.join(os.path.dirname(__file__), "..", "recon.sh")


def _t():
    return open(RECON, encoding="utf-8", errors="replace").read()


def test_large_lists_resolved_in_chunks():
    t = _t()
    # -a 4 -> 456,976-chunk ceiling; the default 2-char suffix caps at 676 and silently truncates.
    assert 'split -a 4 -l "$DNSX_CAP"' in t, "no suffix-safe (-a 4) DNSX_CAP-sized chunking"
    assert re.search(r'for\s+_chunk\b', t), "no per-chunk loop"
    assert re.search(r'dnsx -silent -a -l "\$_chunk"', t), "chunks are not fed to dnsx"


def test_dedup_before_resolve():
    # 24M dup-heavy all.txt must be deduped before chunking (else ~23M wasted lookups)
    assert re.search(r'sort -u "\$RECON_DIR/subdomains/all\.txt"\s*>\s*"\$DEDUP"', _t()), \
        "all.txt is not deduped before chunked resolution"


def test_empty_chunk_glob_guarded():
    assert '[ -f "$_chunk" ] || continue' in _t(), "no guard against an empty chunk glob"


def test_no_silent_skip_resolve_on_large_list():
    assert "skipping resolve" not in _t(), "recon.sh still SKIPS resolution on large lists"


def test_alterx_permutation_explosion_bounded():
    t = _t()
    assert "ALTERX_LIMIT" in t and re.search(r'alterx .*-limit "\$ALTERX_LIMIT"', t), \
        "alterx permutation output is not bounded (-limit)"


def test_chunked_dnsx_tracks_failed_chunks():
    """v10.6.0 — a failed dnsx chunk must NOT be swallowed by `|| true`; it must
    be counted and its candidates kept (fail-open) instead of mislabelled validated."""
    t = _t()
    assert "DNSX_FAILED_CHUNKS" in t, "failed-chunk counter missing"
    assert ".dnsx_failed" in t, "failed chunk candidates are not accumulated for fail-open re-union"
    # a chunked run with any failed chunk must NOT be marked DNS_VALIDATED=1
    assert '${DNSX_FAILED_CHUNKS:-0}" -eq 0' in t, \
        "DNS_VALIDATED gate does not require zero failed chunks"


def test_alterx_merge_capped():
    """v10.6.0 — default limit lowered and merge skipped when count exceeds the cap."""
    t = _t()
    assert 'ALTERX_LIMIT="${ALTERX_LIMIT:-100000}"' in t, "ALTERX_LIMIT default not lowered to 100000"
    assert "ALTERX_MERGE_CAP" in t, "no independent merge cap for alterx permutations"


def test_dnsx_cap_nonpositive_routes_single_pass():
    """v10.6.0 — DNSX_CAP<=0 must be treated as uncapped (single pass), not fed to split -l 0."""
    assert '${DNSX_CAP:-0}" -le 0' in _t(), "non-positive DNSX_CAP not normalised to uncapped"


def test_passive_merge_is_source_restricted():
    """v10.6.0 — all.txt merge must NOT re-glob derived files (alterx/resolved/...)."""
    t = _t()
    assert "_PASSIVE_SUB_FILES" in t, "passive merge still uses a blind *.txt glob"
    # the blind glob form must be gone from the authoritative merge
    assert 'cat "$RECON_DIR/subdomains/"*.txt 2>/dev/null \\\n    | tr' not in t, \
        "authoritative merge still globs all *.txt (re-ingests derived artefacts)"
