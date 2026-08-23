from pathlib import Path


RECON_SH = Path(__file__).resolve().parents[1] / "recon.sh"


def _source() -> str:
    return RECON_SH.read_text(encoding="utf-8")


def test_port_scanning_uses_resolved_scope_not_only_apex():
    source = _source()
    assert 'PORT_TARGET_FILE="$RECON_DIR/ports/targets.txt"' in source
    assert '"$RECON_DIR/subdomains/resolved.txt"' in source
    assert 'naabu -list "$PORT_TARGET_FILE"' in source
    assert 'nmap -Pn -sV -p "$PORT_CSV" -T4 --open -iL "$PORT_TARGET_FILE"' in source
    assert 'naabu -host "$TARGET"' not in source


def test_port_scanning_preserves_host_to_port_evidence():
    source = _source()
    assert '"$RECON_DIR/ports/open_host_ports.txt"' in source
