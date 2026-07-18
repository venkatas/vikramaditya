"""P0 wiring assertions — recon.sh/scanner.sh/hunt.py must consult the exact-host allowlist at every
host-synthesis / URL-merge / active-scan site under scope-lock. (Matcher correctness: test_scope_lock_escape.)"""
from pathlib import Path
REPO = Path(__file__).resolve().parent.parent
RECON = (REPO / "recon.sh").read_text()
SCANNER = (REPO / "scanner.sh").read_text()
HUNT = (REPO / "hunt.py").read_text()


def test_recon_defines_scope_shim():
    assert "_host_in_scope()" in RECON and "_scope_filter_file()" in RECON
    assert "scope_checker.py" in RECON and "--scope-lock-check" in RECON and "--scope-lock-filter" in RECON

def test_www_forceadd_gated_by_in_scope():
    # www is force-added only when in scope (apex-only scope-lock drops it)
    assert '_host_in_scope "www.$TARGET" && echo "www.$TARGET"' in RECON

def test_archive_merge_filtered():
    assert '_scope_filter_file "$RECON_DIR/urls/all.txt"' in RECON

def test_probe_set_filtered():
    assert '_scope_filter_file "$_PROBE_WITH_APEX"' in RECON

def test_vhost_skipped_under_scope_lock():
    # the FUZZ.$TARGET vhost block must be gated off under scope-lock
    assert "virtual-host fuzzing SKIPPED under scope-lock" in RECON
    # and the skip is guarded by the SCOPE_LOCK branch that empties found.txt
    i = RECON.index("virtual-host fuzzing SKIPPED under scope-lock")
    seg = RECON[i-120:i+180]
    assert 'SCOPE_LOCK" = "1"' in seg and 'vhosts/found.txt"' in seg

def test_origin_ip_hunt_gated():
    i = RECON.index("cf_origin_hunt.py")
    seg = RECON[i:i+600]
    assert 'SCOPE_LOCK" = "1"' in seg and "SKIPPED under scope-lock" in seg

def test_scanner_boundary_refilter():
    assert "scope/allow.txt" in SCANNER and "--scope-lock-filter" in SCANNER
    assert "fail closed" in SCANNER.lower()

def test_hunt_persists_allowlist_and_threads_env():
    assert "scope" in HUNT and "allow.txt" in HUNT and "SCOPE_ALLOW_FILE=" in HUNT
    # apex-only: www is NOT auto-added to the allowlist
    assert "_allow_hosts = [domain]" in HUNT
