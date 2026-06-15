"""run_hunt must make the discovered-credential assessment reachable from the main entry.

GAP (audit 2026-06-14): vikramaditya.py built the hunt.py command WITHOUT --assess-creds, so the
v10.4.0 cred-blast-radius feature was orphaned — on a real run TruffleHog verified 4 live AWS keys
in a JS bundle and none reached the report. run_hunt now passes --assess-creds by default.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import vikramaditya  # noqa: E402


def _capture_cmd(monkeypatch):
    captured = {}

    def _fake_run(cmd, **kw):
        captured["cmd"] = cmd
        class _R:  # noqa: D401
            returncode = 0
        return _R()

    monkeypatch.setattr(vikramaditya.subprocess, "run", _fake_run)
    return captured


def test_run_hunt_passes_assess_creds_when_enabled(monkeypatch):
    """The flag must be REACHABLE from the wrapper (was orphaned before the fix)."""
    cap = _capture_cmd(monkeypatch)
    vikramaditya.run_hunt("example.com", full=True, scope_lock=True, assess_creds=True)
    assert "--assess-creds" in cap["cmd"]
    assert "--target" in cap["cmd"] and "example.com" in cap["cmd"]
    assert "--full" in cap["cmd"] and "--scope-lock" in cap["cmd"]


def test_run_hunt_assess_creds_off_by_default(monkeypatch):
    """ACTIVE third-party credential use is scope-sensitive → explicit opt-in, not default-on.
    (Passive reporting of a verified secret still happens unconditionally inside hunt.py.)"""
    cap = _capture_cmd(monkeypatch)
    vikramaditya.run_hunt("example.com")
    assert "--assess-creds" not in cap["cmd"]
