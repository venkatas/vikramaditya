"""The model bake-off must invoke brain.py with its CURRENT CLI.

BUG (model bake-off, 2026-06-17): brain_model_bench.py shelled out
`brain.py scan <findings> --recon-dir <recon>` — the old positional form. brain.py's
CLI is now `--phase scan --findings-dir <dir> --recon-dir <dir>`, so every model
errored on argparse in ~0.3s and the leaderboard was all zeros (SUBMIT=0). The bench
silently measured nothing.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import brain_model_bench as bmb  # noqa: E402


def test_brain_scan_cmd_uses_phase_and_findings_dir():
    cmd = bmb._brain_scan_cmd("/tmp/f", "/tmp/r")
    s = " ".join(cmd)
    assert "--phase scan" in s, f"must use --phase scan; got: {s}"
    assert "--findings-dir /tmp/f" in s, f"findings must be passed via --findings-dir; got: {s}"
    assert "--recon-dir /tmp/r" in s
    # the old broken positional form must be gone
    assert " scan /tmp/f" not in s


def test_brain_scan_cmd_runs_brain_py_with_interpreter():
    cmd = bmb._brain_scan_cmd("/f", "/r")
    assert cmd[0] == sys.executable
    assert cmd[-1] != ""
    assert any(c.endswith("brain.py") for c in cmd)


def test_brain_scan_cmd_passes_explicit_model():
    """The bake-off must force the model via --model (brain.env file-wins over env,
    so env BRAIN_MODEL alone is silently overridden → every model ran as qwen3-coder)."""
    cmd = bmb._brain_scan_cmd("/f", "/r", model="gemma-4:x")
    s = " ".join(cmd)
    assert "--model gemma-4:x" in s


def test_run_one_model_disables_brain_env_override(monkeypatch, tmp_path):
    """run_one_model must set BRAIN_ENV_NOLOAD=1 so ~/.config/vikramaditya/brain.env
    cannot clobber the bench's chosen model back to the pinned default."""
    captured = {}

    class _R:
        returncode = 0

    def _fake_run(cmd, env=None, **kw):
        captured["env"] = env
        captured["cmd"] = cmd
        return _R()

    monkeypatch.setattr(bmb.subprocess, "run", _fake_run)
    findings = tmp_path / "findings"
    findings.mkdir()
    out = tmp_path / "out"
    bmb.run_one_model("some-model:tag", findings, tmp_path, out)
    assert captured["env"].get("BRAIN_ENV_NOLOAD") == "1"
    assert "--model" in captured["cmd"] and "some-model:tag" in captured["cmd"]
