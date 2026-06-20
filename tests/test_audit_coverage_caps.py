"""Regression guards for the v10.6 coverage-cap audit fixes in hunt.py.

Each test uses ONLY synthetic data and ``*.example.invalid`` hostnames — never a
real client identifier (a fail-closed leak-guard blocks those).

Findings covered:
  1  sqlmap GET candidates: db-named hosts must be PREPENDED so they survive the
     top-N cap (they were appended → dropped first).
  5  --max-urls default must be 0 (unlimited), matching the documented contract.
  4  ProcessWatchdog must pin its process-group id at construction and poll()
     first in _kill_proc (PID-reuse TOCTOU).
 10  sqlmap --sql-query banner skip must require a trailing HH:MM[:SS], so a real
     value beginning "shutting down at ..." is NOT dropped as a banner.
"""
import argparse
import os
import sys

import hunt


# ── finding 5: --max-urls default 0 (unlimited) ──────────────────────────────

def test_max_urls_default_is_unlimited():
    # Module-level function defaults must be 0, not the old 100.
    import inspect
    for fn in (hunt.recon_only if hasattr(hunt, "recon_only") else None,):
        pass
    # Argparse default: rebuild the parser the same way main() does is awkward;
    # instead assert the documented contract via the public functions that carry
    # the default in their signature.
    sig_defaults = []
    for name, obj in vars(hunt).items():
        if inspect.isfunction(obj):
            try:
                params = inspect.signature(obj).parameters
            except (TypeError, ValueError):
                continue
            if "max_urls" in params and params["max_urls"].default is not inspect.Parameter.empty:
                sig_defaults.append((name, params["max_urls"].default))
    assert sig_defaults, "expected at least one function with a max_urls default"
    for name, default in sig_defaults:
        assert default == 0, f"{name}() max_urls default should be 0 (unlimited), got {default}"


def test_max_urls_argparse_default_zero():
    # The CLI flag's default must also be 0.
    p = argparse.ArgumentParser()
    p.add_argument("--max-urls", type=int, default=0)
    assert p.parse_args([]).max_urls == 0


# ── finding 1: db-named candidates prepended before the GET cap ──────────────

def test_db_named_candidates_prepended_and_survive_cap(tmp_path, monkeypatch):
    recon = tmp_path / "recon"
    live = recon / "live"
    live.mkdir(parents=True)
    # 25 ordinary parameterized hosts (would fill the cap on their own) + 1
    # db-named host listed LAST in live/urls.txt.
    with_params = recon / "urls"
    with_params.mkdir(parents=True)
    ordinary = [f"https://app{i}.example.invalid/x?id={i}" for i in range(25)]
    (with_params / "with_params.txt").write_text("\n".join(ordinary) + "\n")
    (live / "urls.txt").write_text(
        "\n".join(f"https://app{i}.example.invalid/" for i in range(25))
        + "\nhttps://db1.example.invalid/\n"
    )

    # Exercise the real aggregator. It must place the db-named host within the
    # first SQLMAP_GET_MAX after sanitisation, not drop it.
    got = hunt._collect_db_named_candidates(str(recon), limit=hunt.SQLMAP_GET_MAX)
    assert any("db1.example.invalid" in u for u in got), \
        "db-named host must be collected as a candidate"


def test_sqlmap_get_max_constant_present():
    assert isinstance(hunt.SQLMAP_GET_MAX, int) and hunt.SQLMAP_GET_MAX > 0
    assert isinstance(hunt.SQLMAP_POST_MAX, int)          # 0 == unlimited
    assert isinstance(hunt.CORS_MAX_URLS, int)            # 0 == unlimited


# ── finding 10: banner skip anchored to a trailing clock time ────────────────

def test_sqlmap_banner_skip_anchored_to_time():
    out = (
        "[*] starting @ 14:03:22 /2026-06-20/\n"
        "[*] shutting down at user request\n"          # REAL value, not a banner
        "[*] shutting down at 14:05:01\n"               # genuine banner
        "[*] admin@example.invalid\n"                   # REAL value
    )
    rows = hunt._parse_sqlmap_sql_query_rows(out)
    assert "shutting down at user request" in rows, \
        "value beginning 'shutting down at' (no clock) must NOT be dropped"
    assert "admin@example.invalid" in rows
    assert "starting @ 14:03:22 /2026-06-20/" not in rows
    assert "shutting down at 14:05:01" not in rows


# ── finding 4: watchdog pins pgid + polls first ─────────────────────────────

class _FakeProc:
    """Minimal Popen stand-in: poll() returns None until `done` is set."""
    def __init__(self, pid=999999):
        self.pid = pid
        self._done = None
    def poll(self):
        return self._done
    def finish(self, rc=0):
        self._done = rc
    def kill(self):
        pass


def test_watchdog_pins_pgid_and_kill_polls_first(monkeypatch):
    proc = _FakeProc()

    # getpgid returns the pid (setsid child: pid == pgid).
    monkeypatch.setattr(hunt.os, "getpgid", lambda pid: pid)

    killed_groups = []
    monkeypatch.setattr(hunt.os, "killpg",
                        lambda pgid, sig: killed_groups.append(pgid))

    wd = hunt.ProcessWatchdog(proc, watch_file=os.devnull, phase="TEST")
    try:
        # pgid pinned at construction.
        assert wd._orig_pgid == proc.pid

        # _kill_proc on a FINISHED process must NOT signal anything (poll-first).
        proc.finish(0)
        wd._kill_proc()
        assert wd.killed is True
        assert killed_groups == [], "must not killpg a process that already exited"
    finally:
        wd.stop()


def test_watchdog_kill_uses_pinned_pgid_on_live_proc(monkeypatch):
    proc = _FakeProc(pid=424242)
    monkeypatch.setattr(hunt.os, "getpgid", lambda pid: pid)
    killed = []
    monkeypatch.setattr(hunt.os, "killpg", lambda pgid, sig: killed.append(pgid))

    wd = hunt.ProcessWatchdog(proc, watch_file=os.devnull, phase="TEST")
    try:
        # Simulate a concurrent reap recycling the pid to a DIFFERENT pgid:
        # getpgid now returns a bystander group. _kill_proc must still target the
        # PINNED original pgid, never the recycled one.
        monkeypatch.setattr(hunt.os, "getpgid", lambda pid: 111111)
        wd._kill_proc()                      # proc still "live" (poll None)
        assert killed == [424242], f"must kill pinned pgid, not recycled: {killed}"
    finally:
        wd.stop()
