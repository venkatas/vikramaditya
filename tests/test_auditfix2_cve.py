"""Regression tests for cve.run_nuclei_cve_scan masked-tool-failure fix.

Audit finding (MED — masked tool failure): run_nuclei_cve_scan() previously
ignored a non-timeout command failure. If nuclei was missing or errored before
writing its -o file, stderr was swallowed by `2>/dev/null`, the False success
flag was ignored, and the function printed "No CVEs detected by nuclei" — i.e.
a tool failure was reported as a clean, vulnerability-free result.

The fix distinguishes three outcomes and surfaces a degraded/failed signal:
  - clean exit (0 findings)  -> status "ok"      -> "No CVEs detected" allowed
  - timeout (partial)        -> status "degraded"-> partial findings recovered
  - non-timeout non-zero exit-> status "failed"  -> WARN + degraded signal, and
                                NOT reported as "No CVEs detected"

These tests assert the real behaviour (status sidecar contents, the
introspectable last_status attribute, and the absence/presence of the
misleading "No CVEs detected" line) rather than mocking the classifier.
"""

import json
import os

import cve


def _fail_run_cmd(stderr_payload, cmd_sink, returncode_ok=False):
    """run_cmd stand-in: nuclei errors BEFORE writing -o (writes only stderr)."""

    def fake_run_cmd(cmd, timeout=30):
        cmd_sink.append(cmd)
        import re
        # Emulate nuclei failing before producing any -o output, but writing a
        # diagnostic line to its stderr file (2>"<path>").
        m = re.search(r'2>"([^"]+)"', cmd)
        if m:
            with open(m.group(1), "w") as f:
                f.write(stderr_payload)
        # Non-timeout, non-zero exit: stdout empty, success False.
        return returncode_ok, ""

    return fake_run_cmd


def test_tool_failure_is_not_reported_as_no_cves(monkeypatch, tmp_path, capsys):
    """nuclei missing/errored -> degraded/failed signal, NOT 'No CVEs detected'."""
    out_file = str(tmp_path / "nuclei_cve_confirmed.txt")
    cmds = []
    monkeypatch.setattr(
        cve,
        "run_cmd",
        _fail_run_cmd("sh: nuclei: command not found\n", cmds),
    )

    findings = cve.run_nuclei_cve_scan("t.example", recon_dir=None, out_file=out_file)

    # No findings (tool never produced any) — but this is a FAILURE, not clean.
    assert findings == []

    out = capsys.readouterr().out
    # The misleading clean-result line must NOT appear on a tool failure.
    assert "No CVEs detected by nuclei" not in out
    # A clear WARN about incomplete coverage must appear, surfacing the stderr.
    assert "WARN" in out
    assert "FAILED" in out
    assert "command not found" in out

    # The introspectable status reflects a real failure the caller can mark.
    status = cve.run_nuclei_cve_scan.last_status
    assert status is not None
    assert status["status"] == "failed"
    assert "command not found" in (status["error"] or "")
    assert status["findings"] == 0

    # A persisted status sidecar lets a caller that prefers files mark the run.
    sidecar = out_file + ".status.json"
    assert os.path.exists(sidecar)
    with open(sidecar) as f:
        data = json.load(f)
    assert data["status"] == "failed"
    assert data["tool"] == "nuclei"
    assert "command not found" in (data["error"] or "")


def test_clean_zero_findings_is_ok_not_degraded(monkeypatch, tmp_path, capsys):
    """A genuine clean run with 0 findings must stay 'ok' and say so."""
    out_file = str(tmp_path / "out.txt")
    cmds = []

    def clean_run_cmd(cmd, timeout=30):
        cmds.append(cmd)
        import re
        # Clean exit: create an empty -o file, no stderr.
        m = re.search(r'-o "([^"]+)"', cmd)
        if m:
            open(m.group(1), "w").close()
        return True, ""

    monkeypatch.setattr(cve, "run_cmd", clean_run_cmd)

    findings = cve.run_nuclei_cve_scan("t.example", recon_dir=None, out_file=out_file)

    assert findings == []
    out = capsys.readouterr().out
    # The clean-result line is correct here and SHOULD appear.
    assert "No CVEs detected by nuclei" in out
    assert "WARN" not in out

    status = cve.run_nuclei_cve_scan.last_status
    assert status["status"] == "ok"

    sidecar = out_file + ".status.json"
    assert os.path.exists(sidecar)
    with open(sidecar) as f:
        assert json.load(f)["status"] == "ok"


def test_timeout_partial_recovery_is_degraded_not_failed(monkeypatch, tmp_path, capsys):
    """Timeout path stays 'degraded' with findings recovered (regression guard)."""
    out_file = str(tmp_path / "out.txt")
    cmds = []

    def timeout_run_cmd(cmd, timeout=30):
        cmds.append(cmd)
        import re
        m = re.search(r'-o "([^"]+)"', cmd)
        if m:
            with open(m.group(1), "w") as f:
                f.write("[CVE-2021-1234] [http] [high] https://t.example/a\n")
        # nuclei killed at the cap: stdout discarded, success False, timeout msg.
        return False, f"timeout after {timeout}s"

    monkeypatch.setattr(cve, "run_cmd", timeout_run_cmd)

    findings = cve.run_nuclei_cve_scan("t.example", recon_dir=None, out_file=out_file)

    # Partial finding recovered from the -o file.
    assert len(findings) == 1
    assert "CVE-2021-1234" in findings[0]

    out = capsys.readouterr().out
    # Timeout is NOT a tool failure and must NOT be a clean "no CVEs" either.
    assert "No CVEs detected by nuclei" not in out
    assert "FAILED" not in out  # not the failed branch

    status = cve.run_nuclei_cve_scan.last_status
    assert status["status"] == "degraded"
    assert "timeout" in (status["error"] or "")


def test_failure_with_no_stderr_still_signals_failed(monkeypatch, tmp_path, capsys):
    """A non-zero exit with no stderr captured is still a failure, not clean."""
    out_file = str(tmp_path / "out.txt")
    cmds = []
    # Empty stderr payload simulates a silent non-zero exit.
    monkeypatch.setattr(cve, "run_cmd", _fail_run_cmd("", cmds))

    findings = cve.run_nuclei_cve_scan("t.example", recon_dir=None, out_file=out_file)

    assert findings == []
    out = capsys.readouterr().out
    assert "No CVEs detected by nuclei" not in out
    assert "WARN" in out

    status = cve.run_nuclei_cve_scan.last_status
    assert status["status"] == "failed"
    # A non-empty diagnostic is still recorded even without stderr.
    assert status["error"]


def test_default_tempfile_failure_cleans_up_all_artifacts(monkeypatch):
    """On the default-temp path a failed run must not leak out/stderr/status files."""
    created = {}

    def fake_run_cmd(cmd, timeout=30):
        import re
        mo = re.search(r'-o "([^"]+)"', cmd)
        me = re.search(r'2>"([^"]+)"', cmd)
        if mo:
            created["out"] = mo.group(1)
        if me:
            created["err"] = me.group(1)
            with open(me.group(1), "w") as f:
                f.write("nuclei: panic\n")
        return False, ""

    monkeypatch.setattr(cve, "run_cmd", fake_run_cmd)

    findings = cve.run_nuclei_cve_scan("t.example", recon_dir=None)

    assert findings == []
    # Status still reflects failure even though artifacts are cleaned up.
    assert cve.run_nuclei_cve_scan.last_status["status"] == "failed"
    # No temp artifacts left behind.
    assert not os.path.exists(created.get("out", ""))
    assert not os.path.exists(created.get("err", ""))
    assert not os.path.exists(created.get("out", "") + ".status.json")
