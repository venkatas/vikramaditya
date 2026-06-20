"""Regression tests for the fixB REWORK — the 4 items the friends-verifiers
flagged after the combined Pass B + Pass A fix pass:

  1. hunt.py — the 'scan' phase must map to the real "VULN SCAN" watch_phase
     label (prefix-aware, covering "VULN SCAN (Batch X/Y)"), and the sticky
     .recon_truncated sentinel must be cleared at the start of a fresh recon run.
  2/3. autopilot_api_hunt._coverage_dir_from must write coverage.json to the
     SAME path reporter.py reads it from (recon->findings swap of the saver dir).
  4. scopeguard fail-closed branch must block only tokens that DECODE to
     loopback/unspecified, not any bare numeric (ports/timeouts).

Synthetic data only.
"""
import os

import autopilot_api_hunt as ap
import reporter
import scopeguard as sg

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ── 4. scopeguard fail-closed narrowing ─────────────────────────────────────
def test_scopeguard_failclosed_blocks_loopback_allows_ports(monkeypatch):
    # simulate the platform whose resolver returns [] for encoded literals
    monkeypatch.setattr(sg, "LOOKUP_HOST", lambda h: [])
    for loopback in ("2130706433", "0x7f000001", "127.1", "0"):
        assert sg.is_local_or_listener(loopback) is True, f"{loopback} not blocked"
    for benign in ("4444", "86400", "3600", "8080", "22"):
        assert sg.is_local_or_listener(benign) is False, f"{benign} wrongly blocked"
    assert sg.is_local_or_listener("nonexistent.example.invalid") is False


def test_scopeguard_scan_command_allows_port_blocks_encoded_loopback(monkeypatch):
    monkeypatch.setattr(sg, "LOOKUP_HOST", lambda h: [])
    assert sg.scan_command("nc target.example 4444") is None        # port not swept up
    assert sg.scan_command("sleep 86400") is None                   # timeout not swept up
    assert sg.scan_command("nc 2130706433 9000") == "2130706433"    # encoded loopback caught


# ── 2/3. autopilot coverage-dir path matches reporter reader ────────────────
class _FakeSaver:
    def __init__(self, d):
        self.dir = d


def test_coverage_dir_matches_reporter_reader():
    # report_dir for the API path IS the saver's category dir (recon tree).
    report_dir = "recon/acme.invalid/sessions/20990101_x_autopilot/autopilot"
    _, reader_dir = reporter._resolve_recon_findings_dirs(report_dir)
    writer_dir = ap._coverage_dir_from(_FakeSaver(report_dir))
    assert writer_dir == reader_dir, f"writer {writer_dir} != reporter reader {reader_dir}"
    # the swap actually changed recon -> findings (not a no-op)
    assert writer_dir.startswith("findings/") and "/autopilot" in writer_dir


def test_coverage_dir_noop_without_recon_segment():
    writer = ap._coverage_dir_from(_FakeSaver("/tmp/out/autopilot"))
    assert writer == "/tmp/out/autopilot"   # no recon/ segment -> writer == reader


# ── 1. hunt.py scan-phase label + sentinel cleanup (source-level) ───────────
def test_hunt_scan_phase_maps_vuln_scan_label():
    src = open(os.path.join(REPO, "hunt.py"), encoding="utf-8").read()
    assert '"VULN SCAN", "SCAN", "scan"' in src, "scan phase still missing the VULN SCAN label"
    assert "_dt.upper().startswith(_lab.upper())" in src, "phase-degraded match is not prefix-aware"


def test_hunt_recon_truncated_sentinel_cleared_on_fresh_run():
    src = open(os.path.join(REPO, "hunt.py"), encoding="utf-8").read()
    assert 'os.remove(os.path.join(recon_dir, ".recon_truncated"))' in src, \
        "fresh recon run never clears the sticky .recon_truncated sentinel"
