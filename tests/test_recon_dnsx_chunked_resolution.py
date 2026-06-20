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
