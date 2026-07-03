"""Regression guard: recon binaries that recon.sh invokes must be installable
via hunt.py's self-repair (TOOL_REGISTRY / --repair-tools), not only setup.sh.

Codex review (2026-07-03, arsenal-modernization v10.7) caught that setup.sh was
fixed to install tlsx/shuffledns/fingerprintx/massdns but hunt.py's TOOL_REGISTRY
still lacked them, so `--repair-tools` could not restore them. This test keeps the
two install paths in sync.
"""
import hunt


# Binaries recon.sh actually shells out to (cert-SAN harvest L1306, wildcard-safe
# mass-resolve L796 which requires massdns, service banners L337) + jsluice (JS
# endpoint/secret extraction used by hunt.py).
RECON_BINARIES = ["tlsx", "shuffledns", "massdns", "fingerprintx", "jsluice"]


def test_recon_binaries_registered_for_repair():
    for tool in RECON_BINARIES:
        assert tool in hunt.TOOL_LIST, (
            f"{tool} is called by recon.sh/hunt.py but missing from TOOL_REGISTRY "
            f"— `hunt.py --repair-tools` cannot install it"
        )


def test_registry_entries_are_wellformed():
    reg = {name: (binp, hint) for (name, binp, hint) in hunt.TOOL_REGISTRY}
    for tool in RECON_BINARIES:
        binp, hint = reg[tool]
        assert binp, f"{tool}: empty binary path"
        assert hint, f"{tool}: empty install hint"


def test_massdns_is_brew_autoinstallable():
    # shuffledns is a massdns wrapper; massdns ships via Homebrew, so it must be in
    # the auto-install (brew/pip system-tool) set to be restored non-interactively.
    assert "massdns" in hunt.AUTO_INSTALL_SYSTEM_TOOLS
    reg = {name: hint for (name, _binp, hint) in hunt.TOOL_REGISTRY}
    assert "brew install massdns" in reg["massdns"]


def test_go_installed_recon_tools_use_go_install_hint():
    reg = {name: hint for (name, _binp, hint) in hunt.TOOL_REGISTRY}
    for tool in ["tlsx", "shuffledns", "fingerprintx", "jsluice"]:
        assert reg[tool].startswith("go install "), (
            f"{tool} should be a `go install ...` hint, got: {reg[tool]!r}"
        )
