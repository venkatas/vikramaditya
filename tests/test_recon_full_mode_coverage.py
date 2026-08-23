from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_hunt_propagates_full_mode_into_recon():
    source = (ROOT / "hunt.py").read_text(encoding="utf-8")
    assert 'full: bool = False' in source
    assert '"FULL_RECON=1 " if full else "FULL_RECON=0 "' in source
    assert source.count("full=full,") >= 3


def test_full_recon_defaults_to_uncapped_katana_without_overriding_operator():
    source = (ROOT / "recon.sh").read_text(encoding="utf-8")
    assert 'if [ -z "${KATANA_HOST_CAP+x}" ]; then' in source
    assert '[ "${FULL_RECON:-0}" = "1" ]' in source
    assert "KATANA_HOST_CAP=0" in source
    assert '-o "$RECON_DIR/urls/katana.txt" >/dev/null 2>&1' in source


def test_archive_discovery_uses_resolved_scope_not_only_label_domain():
    source = (ROOT / "recon.sh").read_text(encoding="utf-8")
    assert 'ARCHIVE_TARGETS="$RECON_DIR/urls/archive_targets.txt"' in source
    assert '"$RECON_DIR/subdomains/resolved.txt" "$ARCHIVE_TARGETS" "$TARGET"' in source
    assert '< "$ARCHIVE_TARGETS"' in source
    assert 'echo "$TARGET" | timeout -k 15 "$GAU_TIMEOUT" gau' not in source
    assert 'echo "$TARGET" | timeout -k 15 "$WAYBACK_TIMEOUT" waybackurls' not in source
