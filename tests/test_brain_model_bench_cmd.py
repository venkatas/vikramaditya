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


# ---------------------------------------------------------------------------
# Regression: hallucination scoring must NOT use substring containment.
#
# BUG (audit 2026-06-18): _score_hallucination used `fp in u or u in fp`, a
# bidirectional substring test. A genuine novel SUBMIT URL was counted as a
# sqlmap false positive merely because a shorter FP URL was a path-prefix of
# it (http://x/a is a prefix of http://x/admin), inflating halluc_rate and
# mis-ranking the recommended BRAIN_MODEL.
# ---------------------------------------------------------------------------
def test_score_hallucination_prefix_collision_is_not_a_hit():
    """A SUBMIT URL whose path merely contains an FP URL as a prefix is NOT
    a false positive — only an exact (normalised) match counts."""
    submit = ["http://x.invalid/admin"]
    fps = {"http://x.invalid/a"}
    out = bmb._score_hallucination(submit, fps)
    assert out["submit_fp"] == 0, out
    assert out["halluc_rate"] == 0.0


def test_score_hallucination_reverse_prefix_collision_is_not_a_hit():
    """The reverse direction (short SUBMIT, longer FP) must also not match."""
    submit = ["http://x.invalid/a"]
    fps = {"http://x.invalid/admin"}
    out = bmb._score_hallucination(submit, fps)
    assert out["submit_fp"] == 0, out


def test_score_hallucination_exact_match_counts():
    submit = ["http://x.invalid/admin", "http://x.invalid/clean"]
    fps = {"http://x.invalid/admin"}
    out = bmb._score_hallucination(submit, fps)
    assert out["submit_fp"] == 1, out
    assert out["submit_total"] == 2
    assert out["halluc_rate"] == 0.5


def test_score_hallucination_normalises_trailing_slash_and_fragment():
    submit = ["http://x.invalid/admin/", "http://x.invalid/login#frag"]
    fps = {"http://x.invalid/admin", "http://x.invalid/login"}
    out = bmb._score_hallucination(submit, fps)
    assert out["submit_fp"] == 2, out


# ---------------------------------------------------------------------------
# Regression: run_one_model must restore the operator's real findings/brain
# even when the brain.py subprocess raises (Ctrl-C / SIGTERM / unexpected
# exception). Previously the restore was not in a finally block, so an
# interrupt orphaned the operator's triage output in .brain_snapshot_<ts>.
# ---------------------------------------------------------------------------
def test_run_one_model_restores_brain_on_interrupt(monkeypatch, tmp_path):
    findings = tmp_path / "findings"
    brain = findings / "brain"
    brain.mkdir(parents=True)
    sentinel = brain / "real_triage.md"
    sentinel.write_text("operator triage output")

    def _boom(*a, **k):
        raise KeyboardInterrupt()

    monkeypatch.setattr(bmb.subprocess, "run", _boom)

    out = tmp_path / "out"
    try:
        bmb.run_one_model("m:tag", findings, tmp_path, out)
    except KeyboardInterrupt:
        pass

    # The operator's real brain/ must be back in place with its content intact.
    assert brain.is_dir()
    assert sentinel.exists()
    assert sentinel.read_text() == "operator triage output"
    # No orphaned snapshot dirs left behind.
    leftovers = list(findings.parent.glob(".brain_snapshot_*"))
    assert leftovers == [], f"orphaned snapshot(s): {leftovers}"


def test_run_one_model_snapshot_name_is_collision_proof(monkeypatch, tmp_path):
    """Two snapshots taken in the same wall-clock second must not collide:
    the name embeds pid + a uuid suffix."""
    findings = tmp_path / "findings"
    (findings / "brain").mkdir(parents=True)

    seen = []
    real_move = bmb.shutil.move

    def _spy_move(src, dst):
        seen.append(str(dst))
        return real_move(src, dst)

    monkeypatch.setattr(bmb.shutil, "move", _spy_move)
    monkeypatch.setattr(bmb.time, "time", lambda: 1700000000)

    class _R:
        returncode = 0

    monkeypatch.setattr(bmb.subprocess, "run", lambda *a, **k: _R())

    out = tmp_path / "out"
    bmb.run_one_model("m:tag", findings, tmp_path, out)
    snap_names = [s for s in seen if ".brain_snapshot_" in s]
    assert snap_names, seen
    name = snap_names[0]
    assert str(os.getpid()) in name, name
    # uuid hex suffix present (8 hex chars after the pid)
    import re as _re
    assert _re.search(r"\.brain_snapshot_1700000000_\d+_[0-9a-f]{8}$", name), name
