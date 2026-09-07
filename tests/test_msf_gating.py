"""P1 — live Metasploit must FAIL CLOSED behind --allow-destructive.

Regression: run_msf fired a live `exploit` (php/java meterpreter reverse_tcp staging)
gated only by the undocumented, fail-OPEN MSF_DRYRUN env var. --full and even the bare
default profile enabled cms_exploit/rce_scan, so a documented "full checklist by default"
run staged a live reverse shell on any confirmed-vulnerable Drupal/WP/Tomcat/JBoss host.

Now: absent --allow-destructive, every run_msf site only WRITES the inspect-ready _auto.rc
— no msfconsole is launched. run_live(msfconsole) fires ONLY when allow_destructive=True AND
MSF_DRYRUN is unset. No msfconsole is ever launched by these tests (run_live is mocked).
"""
import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import hunt  # noqa: E402


@pytest.fixture
def rc_file(tmp_path):
    p = tmp_path / "exploit.rc"
    p.write_text("use exploit/multi/http/example\nset LHOST YOUR_IP\nexploit -j -z\n")
    return str(p)


@pytest.fixture(autouse=True)
def _no_msf_dryrun(monkeypatch):
    monkeypatch.delenv("MSF_DRYRUN", raising=False)


def _wire(monkeypatch, calls):
    """Mock the danger surface: msfconsole present, LHOST fixed, run_live captured."""
    monkeypatch.setattr(hunt.shutil, "which", lambda b: "/usr/bin/msfconsole" if b == "msfconsole" else None)
    monkeypatch.setattr(hunt, "_get_lhost", lambda: "10.0.0.1")
    monkeypatch.setattr(hunt, "run_live", lambda *a, **k: calls.append((a, k)) or True)


# ── _msf_live_allowed truth table ────────────────────────────────────────────
def test_decision_default_is_dry_run():
    ok, why = hunt._msf_live_allowed(False)
    assert ok is False and "allow-destructive" in why


def test_decision_live_when_allowed():
    assert hunt._msf_live_allowed(True) == (True, "")


def test_decision_msf_dryrun_overrides_allowed(monkeypatch):
    monkeypatch.setenv("MSF_DRYRUN", "1")
    ok, why = hunt._msf_live_allowed(True)
    assert ok is False and "MSF_DRYRUN" in why


# ── run_msf fail-closed behavior ──────────────────────────────────────────────
def test_run_msf_default_writes_rc_but_never_fires(monkeypatch, rc_file):
    calls = []
    _wire(monkeypatch, calls)
    result = hunt.run_msf(rc_file, label="unit", allow_destructive=False)
    assert result is False, "dry-run must report no session"
    assert calls == [], "run_live(msfconsole) was called without --allow-destructive"
    # the inspect-ready _auto.rc IS written (LHOST patched), just never executed
    auto = rc_file.replace(".rc", "_auto.rc")
    assert os.path.isfile(auto)
    body = open(auto).read()
    assert "YOUR_IP" not in body and "10.0.0.1" in body


def test_run_msf_fires_only_when_allowed(monkeypatch, rc_file):
    calls = []
    _wire(monkeypatch, calls)
    hunt.run_msf(rc_file, label="unit", allow_destructive=True)
    assert len(calls) == 1, "live msfconsole not launched under --allow-destructive"
    cmd = calls[0][0][0]
    assert "msfconsole" in cmd and "_auto.rc" in cmd


def test_run_msf_dryrun_env_blocks_even_when_allowed(monkeypatch, rc_file):
    monkeypatch.setenv("MSF_DRYRUN", "1")
    calls = []
    _wire(monkeypatch, calls)
    result = hunt.run_msf(rc_file, label="unit", allow_destructive=True)
    assert result is False and calls == [], "MSF_DRYRUN did not block a destructive-allowed run"


def test_run_msf_default_arg_is_fail_closed(monkeypatch, rc_file):
    # a caller that forgets the kwarg must still fail closed (default False)
    calls = []
    _wire(monkeypatch, calls)
    hunt.run_msf(rc_file, label="unit")
    assert calls == [], "run_msf default is not fail-closed"


# ── the flag is threaded end-to-end (source-assertions) ──────────────────────
def test_flag_threaded_through_wrappers_and_dispatch():
    h = (REPO / "hunt.py").read_text()
    # wrappers accept + forward the flag
    assert "def run_cms_exploit(domain: str, allow_destructive: bool = False)" in h
    assert "def run_rce_scan(domain: str, allow_destructive: bool = False)" in h
    assert h.count("run_msf(") - 1 == sum(  # every call site (minus the def) forwards it
        1 for ln in h.splitlines() if "run_msf(" in ln and "def run_msf" not in ln and "allow_destructive=allow_destructive" in ln)
    # hunt_target threads it into both destructive phases
    assert "run_cms_exploit(domain, allow_destructive=allow_destructive)" in h
    assert "run_rce_scan(domain, allow_destructive=allow_destructive)" in h
    # sync dispatcher + autonomous executor + planner all pass it
    assert "allow_destructive=args.allow_destructive" in h
    assert "ok = run_cms_exploit(domain, allow_destructive=allow_destructive)" in h


def test_vikramaditya_gates_allow_destructive():
    v = (REPO / "vikramaditya.py").read_text()
    assert "allow_destructive: bool = False" in v
    # appended ONLY under the explicit opt-in — bare runs stay dry-run
    assert 'if allow_destructive:\n        cmd.append("--allow-destructive")' in v


def test_help_and_docs_call_out_live_msf():
    h = (REPO / "hunt.py").read_text()
    assert "LIVE msfconsole" in h and "meterpreter" in h.lower()
    claude = (REPO / "CLAUDE.md").read_text()
    assert "--allow-destructive" in claude and "Fail-closed" in claude
