"""Tests for the hard wall-clock deadline around web-app fingerprinting.

fingerprint_webapp fires ~20 sequential HTTP probes that each carry only a
per-request timeout. A trickle/tarpit endpoint resets requests' read timeout
indefinitely, so a single probe can wedge the whole tool — observed live on
mins.clienta.com, where fingerprinting froze for 9+ minutes with zero
progress. fingerprint_webapp_bounded caps total fingerprint time in a daemon
thread sharing the result dict, so partial (main-page) data survives and the
scan always proceeds.
"""
import time

import pytest

import vikramaditya


def test_bounded_returns_full_result_on_fast_path(monkeypatch):
    def fast(url, _result=None):
        _result["status"] = 200
        _result["server"] = "Kestrel"
        _result["tech"] = ["ASP.NET"]
        return _result

    monkeypatch.setattr(vikramaditya, "fingerprint_webapp", fast)
    r = vikramaditya.fingerprint_webapp_bounded("https://x.invalid", deadline=5)
    assert r["status"] == 200
    assert r["tech"] == ["ASP.NET"]
    assert not r.get("timed_out")
    assert r["error"] is None


def test_bounded_caps_tarpit_and_preserves_partial(monkeypatch):
    # Worker fills the main-page fields, then a later probe tarpits (sleeps past
    # the deadline). The wrapper must return promptly with the partial data and
    # error=None so the scan proceeds (NOT take the full sleep).
    def tarpit(url, _result=None):
        _result["status"] = 200          # main page gathered first
        _result["server"] = "nginx"
        time.sleep(3)                    # a probe hangs/trickles
        _result["tech"] = ["late"]       # never reached in time

    monkeypatch.setattr(vikramaditya, "fingerprint_webapp", tarpit)
    t0 = time.time()
    r = vikramaditya.fingerprint_webapp_bounded("https://x.invalid", deadline=0.5)
    elapsed = time.time() - t0

    assert elapsed < 2.0                  # returned at ~deadline, not after 3s
    assert r["timed_out"] is True
    assert r["status"] == 200             # partial main-page data preserved
    assert r["server"] == "nginx"
    assert r["error"] is None             # no error → scan still proceeds
    assert "late" not in r["tech"]        # the post-hang work did not land


def test_bounded_timeout_result_decoupled_from_late_daemon_writes(monkeypatch):
    # After the deadline the abandoned worker keeps running and mutates ITS dict;
    # the returned snapshot must not change under the caller. (Codex LOW fix.)
    live = []

    def slow(url, _result=None):
        _result["status"] = 200
        live.append(_result)              # the worker's live dict
        time.sleep(1.5)
        _result["login_detected"] = True  # late write, after we've returned
        _result["tech"].append("late")

    monkeypatch.setattr(vikramaditya, "fingerprint_webapp", slow)
    r = vikramaditya.fingerprint_webapp_bounded("https://x.invalid", deadline=0.3)
    assert r["timed_out"] is True
    assert r["login_detected"] is False

    time.sleep(1.8)                        # let the daemon do its late writes
    assert r["login_detected"] is False    # returned snapshot is decoupled
    assert "late" not in r["tech"]
    assert live and live[0]["login_detected"] is True  # the live dict DID mutate


def test_bounded_worker_exception_is_degraded_not_raised(monkeypatch):
    def boom(url, _result=None):
        raise RuntimeError("connection exploded")

    monkeypatch.setattr(vikramaditya, "fingerprint_webapp", boom)
    r = vikramaditya.fingerprint_webapp_bounded("https://x.invalid", deadline=5)
    assert "connection exploded" in (r["error"] or "")
    assert not r.get("timed_out")


def test_default_deadline_is_positive():
    assert isinstance(vikramaditya.FINGERPRINT_DEADLINE, int)
    assert vikramaditya.FINGERPRINT_DEADLINE > 0


def test_fingerprint_webapp_accepts_shared_result_dict(monkeypatch):
    # The worker must populate a caller-provided dict in place (so the wrapper
    # can read partial results). Stub out the network so this stays offline.
    shared = vikramaditya._new_fingerprint_result("https://x.invalid")

    class _Resp:
        status_code = 200
        headers = {"Server": "test"}
        text = "<html>no markers</html>"

    monkeypatch.setattr(vikramaditya, "fingerprint_webapp_bounded", lambda *a, **k: None)

    import requests
    monkeypatch.setattr(requests, "get", lambda *a, **k: _Resp())
    monkeypatch.setattr(requests, "post", lambda *a, **k: _Resp())

    out = vikramaditya.fingerprint_webapp("https://x.invalid", _result=shared)
    assert out is shared                       # same object mutated in place
    assert shared["status"] == 200
    assert shared["server"] == "test"
