"""Regression tests for cve.run_nuclei_cve_scan timeout-safe result capture.

Audit finding (LOW/perf + latent data-loss): the nuclei CVE scan buffered all
output in the subprocess stdout pipe and was hard-capped at timeout=300. On
timeout, run_cmd kills the process and discards its buffered stdout, so any CVE
found in the final seconds before the cap was lost. The fix routes nuclei output
to a file via -o and reads that file (complete on clean exit, partial on
timeout), preserving coverage while hardening result capture.
"""

import os
import tempfile

import cve


def _make_fake_run_cmd(out_payload, success, cmd_sink):
    """Build a run_cmd stand-in that simulates nuclei writing to its -o file."""

    def fake_run_cmd(cmd, timeout=30):
        cmd_sink.append(cmd)
        # Emulate nuclei -o: extract the -o "<path>" target and write to it.
        import re
        m = re.search(r'-o "([^"]+)"', cmd)
        if m:
            with open(m.group(1), "w") as f:
                f.write(out_payload)
        # On the timeout path nuclei is killed and stdout is discarded.
        stdout = "" if not success else out_payload
        return success, stdout if success else "timeout after 300s"

    return fake_run_cmd


def test_partial_results_recovered_on_timeout(monkeypatch, tmp_path):
    """Findings written to the -o file before a timeout must be recovered."""
    out_file = str(tmp_path / "nuclei_cve_confirmed.txt")
    # nuclei wrote two CVEs to disk, then run_cmd returns a timeout (stdout lost).
    payload = (
        "[CVE-2021-1234] [http] [high] https://t.example/a\n"
        "[CVE-2022-5678] [http] [critical] https://t.example/b\n"
    )
    cmds = []
    monkeypatch.setattr(
        cve, "run_cmd", _make_fake_run_cmd(payload, success=False, cmd_sink=cmds)
    )

    findings = cve.run_nuclei_cve_scan("t.example", recon_dir=None, out_file=out_file)

    assert len(findings) == 2
    assert any("CVE-2021-1234" in f for f in findings)
    assert any("CVE-2022-5678" in f for f in findings)
    # Coverage knobs preserved.
    assert "-tags cve" in cmds[0]
    assert "-severity medium,high,critical" in cmds[0]
    assert "-rate-limit 30" in cmds[0]
    assert f'-o "{out_file}"' in cmds[0]


def test_clean_exit_dedups_and_returns(monkeypatch, tmp_path):
    out_file = str(tmp_path / "out.txt")
    payload = (
        "[CVE-2021-1] [http] [high] https://t.example/a\n"
        "[CVE-2021-1] [http] [high] https://t.example/a\n"  # duplicate line
        "[CVE-2021-2] [http] [medium] https://t.example/b\n"
    )
    cmds = []
    monkeypatch.setattr(
        cve, "run_cmd", _make_fake_run_cmd(payload, success=True, cmd_sink=cmds)
    )

    findings = cve.run_nuclei_cve_scan("t.example", recon_dir=None, out_file=out_file)

    assert len(findings) == 2  # duplicate collapsed
    assert sorted(findings) == [
        "[CVE-2021-1] [http] [high] https://t.example/a",
        "[CVE-2021-2] [http] [medium] https://t.example/b",
    ]


def test_no_findings_returns_empty(monkeypatch, tmp_path):
    out_file = str(tmp_path / "out.txt")
    cmds = []
    monkeypatch.setattr(
        cve, "run_cmd", _make_fake_run_cmd("", success=True, cmd_sink=cmds)
    )

    findings = cve.run_nuclei_cve_scan("t.example", recon_dir=None, out_file=out_file)

    assert findings == []


def test_default_tempfile_is_cleaned_up(monkeypatch):
    """When no out_file is supplied, the temp file must not be left behind."""
    created = {}

    def fake_run_cmd(cmd, timeout=30):
        import re
        m = re.search(r'-o "([^"]+)"', cmd)
        if m:
            created["path"] = m.group(1)
            with open(m.group(1), "w") as f:
                f.write("[CVE-2020-9] [http] [high] https://t.example/x\n")
        return True, ""

    monkeypatch.setattr(cve, "run_cmd", fake_run_cmd)

    findings = cve.run_nuclei_cve_scan("t.example", recon_dir=None)

    assert len(findings) == 1
    assert created.get("path", "").startswith(tempfile.gettempdir())
    assert not os.path.exists(created["path"])  # cleaned up
