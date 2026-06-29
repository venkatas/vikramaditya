"""Regression tests for cve.check_exposed_configs silent-coverage-cap fix.

Audit finding (HIGH — silent coverage cap): check_exposed_configs() previously
truncated the live-host list with a hardcoded ``[:20]`` (cve.py:611). Because
``live/urls.txt`` is built with ``sort -u`` (alphabetical, NOT risk-ranked),
the cap silently dropped every live host after the 20th, never probing them for
exposed ``/.env`` / ``/config.js`` etc., and still printed
"No exposed config files found" — a false-clean result with no degradation
marker. This contradicts the CLAUDE.md "URL surface is uncapped" contract.

The fix:
  - default is uncapped (probe ALL live hosts);
  - an explicit cap is gated behind CVE_CONFIG_MAX_HOSTS (0 = unlimited);
  - when a cap truncates the list, a "Coverage degraded" marker is printed;
  - a priority-ranked file (priority/prioritized_hosts.txt) is preferred over
    the alphabetical live/urls.txt so a cap keeps the highest-risk hosts.

All data here is synthetic (example.invalid / 127.0.0.1).
"""

import os

import cve


def _probe_recorder():
    """run_cmd stand-in that records every host probed and never finds a 200."""
    probed_urls = []

    def fake_run_cmd(cmd, timeout=30):
        # The config-probe curl always embeds the URL as the last quoted arg.
        if cmd.startswith("curl "):
            probed_urls.append(cmd)
            return True, "404"  # no exposed config
        return True, ""

    return fake_run_cmd, probed_urls


def _write_live(recon_dir, n):
    live = os.path.join(recon_dir, "live")
    os.makedirs(live, exist_ok=True)
    # sort -u => alphabetical; pad so ordering is deterministic and >20.
    hosts = sorted(f"https://h{i:03d}.example.invalid" for i in range(n))
    with open(os.path.join(live, "urls.txt"), "w") as f:
        f.write("\n".join(hosts) + "\n")
    return hosts


def test_default_is_uncapped_probes_all_hosts(monkeypatch, tmp_path):
    """With no cap env, ALL live hosts must be probed (uncapped contract)."""
    monkeypatch.delenv("CVE_CONFIG_MAX_HOSTS", raising=False)
    # Reload the module-level constant for this test.
    monkeypatch.setattr(cve, "CVE_CONFIG_MAX_HOSTS", 0, raising=False)

    recon_dir = str(tmp_path / "recon")
    hosts = _write_live(recon_dir, 35)

    fake, probed = _probe_recorder()
    monkeypatch.setattr(cve, "run_cmd", fake)

    cve.check_exposed_configs("example.invalid", recon_dir=recon_dir)

    # Every one of the 35 hosts must appear in at least one probe URL.
    for h in hosts:
        assert any(h in cmd for cmd in probed), f"{h} was never probed"


def test_explicit_cap_marks_degraded(monkeypatch, tmp_path, capsys):
    """An explicit CVE_CONFIG_MAX_HOSTS cap must print a degradation marker."""
    monkeypatch.setattr(cve, "CVE_CONFIG_MAX_HOSTS", 10, raising=False)

    recon_dir = str(tmp_path / "recon")
    _write_live(recon_dir, 35)

    fake, probed = _probe_recorder()
    monkeypatch.setattr(cve, "run_cmd", fake)

    cve.check_exposed_configs("example.invalid", recon_dir=recon_dir)

    out = capsys.readouterr().out
    # The operator must be warned that the clean result is incomplete.
    assert "Coverage degraded" in out
    assert "10" in out and "35" in out

    # Only 10 distinct hosts probed (10 hosts * len(config_paths) probes each).
    probed_hosts = {
        cmd.split("https://")[1].split("/")[0]
        for cmd in probed
        if "https://" in cmd
    }
    assert len(probed_hosts) == 10


def test_priority_ranked_file_preferred_when_capping(monkeypatch, tmp_path):
    """When a ranked file exists, a cap keeps the highest-risk hosts, not A-Z."""
    monkeypatch.setattr(cve, "CVE_CONFIG_MAX_HOSTS", 2, raising=False)

    recon_dir = str(tmp_path / "recon")
    _write_live(recon_dir, 10)  # alphabetical h000..h009

    # Risk order intentionally inverts the alphabetical order.
    prio = os.path.join(recon_dir, "priority")
    os.makedirs(prio, exist_ok=True)
    ranked = [
        "https://zzz-crown-jewel.example.invalid",
        "https://yyy-admin.example.invalid",
        "https://h001.example.invalid",
    ]
    with open(os.path.join(prio, "prioritized_hosts.txt"), "w") as f:
        f.write("\n".join(ranked) + "\n")

    fake, probed = _probe_recorder()
    monkeypatch.setattr(cve, "run_cmd", fake)

    cve.check_exposed_configs("example.invalid", recon_dir=recon_dir)

    # The top-2 risk hosts must be probed; the alphabetical h00x must not leak in.
    assert any("zzz-crown-jewel" in cmd for cmd in probed)
    assert any("yyy-admin" in cmd for cmd in probed)
    assert not any("h001.example.invalid" in cmd for cmd in probed)
