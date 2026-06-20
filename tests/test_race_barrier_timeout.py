"""Regression test for race.py barrier-deadlock guard.

race.py's race-condition workers construct threading.Barrier(count) and
call barrier.wait().  If fewer than `count` threads ever reach the barrier
(e.g. a thread.start() raises once the OS thread limit is hit, or a worker
raises before wait()), an unguarded wait() blocks forever and the non-daemon
threads joined without a deadline hang the whole process.

These tests assert the fix: wait() uses BARRIER_TIMEOUT and BrokenBarrierError
is caught, threads are daemon, and joins use JOIN_TIMEOUT — so a short-staffed
barrier resolves quickly instead of deadlocking.

All data here is SYNTHETIC (placeholder tokens, RFC-5737/localhost values).
No network is touched: the raw-request helpers are monkeypatched out.
"""

import threading
import time

import race


def test_constants_present_and_small():
    assert isinstance(race.BARRIER_TIMEOUT, (int, float))
    assert isinstance(race.JOIN_TIMEOUT, (int, float))
    assert 0 < race.BARRIER_TIMEOUT <= 60
    assert 0 < race.JOIN_TIMEOUT <= 120


def _shrink_timeouts(monkeypatch):
    # Keep the test fast: a short barrier timeout still exercises the
    # BrokenBarrierError path without waiting the production 15s.
    monkeypatch.setattr(race, "BARRIER_TIMEOUT", 0.5)
    monkeypatch.setattr(race, "JOIN_TIMEOUT", 2.0)


def test_2fa_does_not_hang_when_a_thread_fails_to_start(monkeypatch):
    _shrink_timeouts(monkeypatch)
    monkeypatch.setattr(race, "rest_raw", lambda *a, **k: (200, "ok"))

    # Force the LAST thread.start() to fail, simulating the OS thread limit.
    # The already-started threads must NOT deadlock on barrier.wait().
    real_thread = threading.Thread
    state = {"n": 0}

    class FlakyThread(real_thread):
        def start(self):
            state["n"] += 1
            if state["n"] == 5:  # the 5th (last, count=5) start() blows up
                raise RuntimeError("can't start new thread")
            super().start()

    monkeypatch.setattr(race.threading, "Thread", FlakyThread)

    start = time.monotonic()
    try:
        race.test_2fa_rate_limit("placeholder-token", count=5)
    except RuntimeError:
        # main may surface the start() failure; the point is it returns promptly.
        pass
    elapsed = time.monotonic() - start
    assert elapsed < 10, f"harness hung for {elapsed:.1f}s — barrier deadlock not fixed"


def test_workers_are_daemon_and_bail_on_broken_barrier(monkeypatch):
    _shrink_timeouts(monkeypatch)

    captured = {}
    real_thread = threading.Thread

    class RecordingThread(real_thread):
        def __init__(self, *a, **k):
            captured["daemon"] = k.get("daemon")
            super().__init__(*a, **k)

    monkeypatch.setattr(race.threading, "Thread", RecordingThread)
    monkeypatch.setattr(race, "gql_raw", lambda *a, **k: (200, {"data": {}}))

    start = time.monotonic()
    race.test_bounty_race("placeholder-token", "REPORT-1", count=3)
    elapsed = time.monotonic() - start

    assert captured.get("daemon") is True, "worker threads must be daemon=True"
    assert elapsed < 10, f"bounty race hung for {elapsed:.1f}s"
