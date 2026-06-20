"""A bare invocation must run the FULLEST assessment; coverage narrows ONLY behind an explicit flag.

ROOT CAUSE (real engagement, 2026-06-16): autonomous mode (autonomous = has_ollama,
the default whenever Ollama is installed) silently forced --scope-lock, so subdomain enumeration was
turned OFF for every bare domain run. The same run also dropped 13,967 discovered URLs to a hardcoded
MAX_URLS=100 cap that vikramaditya.py never surfaced. Neither could be controlled from the CLI.

SPEC (user's rule): "If nothing is given in the param, the tool should enable EVERYTHING by default
unless explicitly flagged to skip." So:
  * subdomain enumeration is ON by default (scope_lock OFF), even in autonomous mode;
  * the URL cap is OFF by default (MAX_URLS=0 = unlimited);
  * IP/CIDR and the fingerprint-error fallback run the FULL checklist by default;
  * explicit opt-outs exist: --scope-lock / --no-scope-lock, --max-urls N, --focused.
The active-cloud gates (assess_creds, whitebox autonomous_default) stay opt-in — out of scope here.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import vikramaditya  # noqa: E402


# ── CLI parsing: new coverage flags ───────────────────────────────────────────

def _parse(argv, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["vikramaditya.py"] + argv)
    return vikramaditya.parse_cli_args()


def test_defaults_are_fullest_coverage(monkeypatch):
    cli = _parse(["example.com"], monkeypatch)
    assert cli["scope_lock"] is None, "scope_lock must be tri-state UNSET by default (not forced)"
    assert cli["max_urls"] == 0, "URL cap must be unlimited (0) by default"
    assert cli["full"] is True, "full checklist must be the default"
    assert cli["target"] == "example.com"


def test_scope_lock_flag_opts_in(monkeypatch):
    cli = _parse(["example.com", "--scope-lock"], monkeypatch)
    assert cli["scope_lock"] is True


def test_no_scope_lock_flag_opts_out(monkeypatch):
    cli = _parse(["example.com", "--no-scope-lock"], monkeypatch)
    assert cli["scope_lock"] is False


def test_max_urls_flag(monkeypatch):
    cli = _parse(["example.com", "--max-urls", "250"], monkeypatch)
    assert cli["max_urls"] == 250


# ── --max-urls robustness (Codex MED): must not swallow a following flag, must validate ──

def test_max_urls_does_not_swallow_following_flag(monkeypatch):
    """`--max-urls --scope-lock` must NOT consume --scope-lock as the value (was: int() raised,
    swallowed, and --scope-lock was silently dropped)."""
    with pytest.raises(SystemExit):
        _parse(["example.com", "--max-urls", "--scope-lock"], monkeypatch)


def test_max_urls_rejects_non_integer(monkeypatch):
    with pytest.raises(SystemExit):
        _parse(["example.com", "--max-urls", "lots"], monkeypatch)


def test_max_urls_rejects_negative(monkeypatch):
    with pytest.raises(SystemExit):
        _parse(["example.com", "--max-urls", "-5"], monkeypatch)


def test_max_urls_rejects_missing_value(monkeypatch):
    with pytest.raises(SystemExit):
        _parse(["example.com", "--max-urls"], monkeypatch)


# ── active-cloud blast-radius stays opt-in even in autonomous (Codex HIGH) ─────

def test_assess_creds_flag_parsed(monkeypatch):
    assert _parse(["example.com", "--assess-creds"], monkeypatch)["assess_creds"] is True
    assert _parse(["example.com"], monkeypatch)["assess_creds"] is None


def test_assess_creds_not_auto_fired_in_autonomous():
    """A leaked key may belong to a THIRD party — autonomous must NOT auto-fire active AWS calls."""
    assert vikramaditya.resolve_assess_creds(None, autonomous=True) is False


def test_assess_creds_explicit_flag_honored():
    assert vikramaditya.resolve_assess_creds(True, autonomous=True) is True
    assert vikramaditya.resolve_assess_creds(False, autonomous=False) is False


def test_assess_creds_interactive_prompts():
    assert vikramaditya.resolve_assess_creds(None, autonomous=False, prompt=lambda: True) is True
    assert vikramaditya.resolve_assess_creds(None, autonomous=False, prompt=lambda: False) is False


def test_focused_flag_opts_out_of_full(monkeypatch):
    cli = _parse(["example.com", "--focused"], monkeypatch)
    assert cli["full"] is False


# ── run_hunt: --max-urls is always forwarded explicitly ────────────────────────

def _capture_cmd(monkeypatch):
    captured = {}

    # v10.6.0 — run_hunt launches through the fork-safe streaming helper
    # (procutil posix_spawn) rather than raw subprocess.run. Patch that so the
    # test never actually spawns hunt.py.
    def _fake_stream(cmd, **kw):
        captured["cmd"] = cmd
        return 0

    monkeypatch.setattr(vikramaditya, "_run_streaming", _fake_stream)
    return captured


def test_run_hunt_forwards_unlimited_max_urls_by_default(monkeypatch):
    cap = _capture_cmd(monkeypatch)
    vikramaditya.run_hunt("example.com")
    cmd = cap["cmd"]
    assert "--max-urls" in cmd
    assert cmd[cmd.index("--max-urls") + 1] == "0", "default must forward unlimited (0)"


def test_run_hunt_forwards_explicit_max_urls(monkeypatch):
    cap = _capture_cmd(monkeypatch)
    vikramaditya.run_hunt("example.com", max_urls=500)
    cmd = cap["cmd"]
    assert cmd[cmd.index("--max-urls") + 1] == "500"


def test_run_hunt_full_off_omits_full_flag(monkeypatch):
    cap = _capture_cmd(monkeypatch)
    vikramaditya.run_hunt("example.com", full=False)
    assert "--full" not in cap["cmd"]


# ── resolve_scope_lock: explicit flag wins; autonomous defaults to FULL enum ───

def test_autonomous_no_flag_defaults_to_full_enum(monkeypatch):
    """THE BUG: autonomous must NOT silently force scope-lock. No flag + autonomous => enum ON."""
    assert vikramaditya.resolve_scope_lock(None, autonomous=True) is False


def test_autonomous_explicit_scope_lock_is_honored():
    assert vikramaditya.resolve_scope_lock(True, autonomous=True) is True


def test_autonomous_explicit_no_scope_lock_is_honored():
    assert vikramaditya.resolve_scope_lock(False, autonomous=True) is False


def test_interactive_no_flag_prompts_and_defaults_off():
    # prompt returns False (operator declined / pressed enter) => full enum
    assert vikramaditya.resolve_scope_lock(None, autonomous=False, prompt=lambda: False) is False
    # operator opts in via prompt => scope-locked
    assert vikramaditya.resolve_scope_lock(None, autonomous=False, prompt=lambda: True) is True


def test_explicit_flag_skips_prompt():
    calls = {"n": 0}

    def _prompt():
        calls["n"] += 1
        return False

    assert vikramaditya.resolve_scope_lock(True, autonomous=False, prompt=_prompt) is True
    assert calls["n"] == 0, "explicit flag must short-circuit the interactive prompt"
