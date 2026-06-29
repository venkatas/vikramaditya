"""Regression tests for auth_utils.FindingSaver and RateLimiter (group: auth_utils.py).

Covers two confirmed audit findings:

1. FindingSaver.save used a whole-second timestamp + a per-instance counter, so two
   same-category savers pointed at the same findings_dir, each saving their Nth finding
   within the same UTC second, would compute identical filenames and silently overwrite
   one another (open(path,"w") truncates). The fix adds microsecond+pid+uuid uniqueness
   and uses exclusive create ("x") so collisions fail loud instead of silently losing data.

2. RateLimiter.wait did a non-thread-safe check-then-set on self._last (TOCTOU): two
   threads sharing one limiter could read the same stale _last, both compute ~0 wait,
   and fire simultaneously, overshooting the per-second cap. The fix serializes the
   read-compute-write under a lock and reserves the slot before sleeping.

SYNTHETIC data only.
"""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from auth_utils import FindingSaver, RateLimiter  # noqa: E402


def test_finding_saver_no_overwrite_same_category(tmp_path):
    """Two same-category savers writing in the same wall-clock second must not clobber.

    Simulates the collision window by freezing both savers to the same whole-second
    timestamp string would-be; here we just write many findings rapidly from two
    instances and assert every finding produced its own file.
    """
    d = str(tmp_path / "findings")
    s1 = FindingSaver(d, "idor")
    s2 = FindingSaver(d, "idor")  # same category + same dir => the collision-prone case

    total = 0
    for i in range(25):
        s1.save({"id": f"a{i}", "severity": "low"})
        s2.save({"id": f"b{i}", "severity": "low"})
        total += 2

    files = [f for f in os.listdir(os.path.join(d, "idor")) if f.endswith(".json")]
    assert len(files) == total, (
        f"expected {total} distinct finding files, got {len(files)} "
        "(silent overwrite regression)"
    )


def test_finding_saver_uses_exclusive_create(monkeypatch, tmp_path):
    """A residual filename collision must raise, never silently truncate."""
    d = str(tmp_path / "findings")
    saver = FindingSaver(d, "auth_bypass")

    # Force uuid + timestamp to be deterministic so the first allocated path repeats.
    monkeypatch.setattr("auth_utils.uuid.uuid4", lambda: _FixedUUID())
    monkeypatch.setattr(
        "auth_utils.datetime",
        _FixedDatetime,
    )
    # Pre-create the file that the saver would otherwise pick, exhausting retries.
    # With a fixed uuid + timestamp + pid + idx, every retry computes the same name,
    # so save() must give up loudly rather than overwrite.
    saver._findings = []  # idx will be 1
    fixed_name = f"finding_19700101_000000_000000_{os.getpid()}_0001_aaaaaa.json"
    open(os.path.join(d, "auth_bypass", fixed_name), "x").close()

    raised = False
    try:
        saver.save({"id": "x", "severity": "high"})
    except FileExistsError:
        raised = True
    assert raised, "save() must raise FileExistsError on unresolvable collision"


def test_rate_limiter_has_lock():
    rl = RateLimiter(max_rps=100.0)
    assert isinstance(rl._lock, type(threading.Lock())) or hasattr(rl._lock, "acquire")


def test_rate_limiter_respects_cap_under_threads():
    """Shared limiter across threads must not let total throughput exceed the cap.

    With max_rps=20 (interval 50ms), 8 calls cannot complete in well under the
    serialized minimum if the slot reservation works. We assert the limiter
    serializes: the sum of returned wait_times reflects reserved spacing.
    """
    rl = RateLimiter(max_rps=20.0)  # 0.05s interval
    n = 8
    barrier = threading.Barrier(n)
    results = [0.0] * n

    def worker(i):
        barrier.wait()  # maximize contention
        results[i] = rl.wait()

    start = time.monotonic()
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - start

    # If the check-then-set were racy, many threads would compute ~0 wait and the
    # whole batch would finish near-instantly. With slot reservation, the (n-1)
    # later callers each reserve a 0.05s-spaced slot, so the batch takes at least
    # ~ (n-1)*interval minus scheduling slack.
    min_expected = (n - 1) * 0.05 * 0.6  # 60% slack for scheduler jitter
    assert elapsed >= min_expected, (
        f"batch finished in {elapsed:.3f}s, expected >= {min_expected:.3f}s; "
        "rate limiter slot reservation regressed"
    )


class _FixedUUID:
    hex = "aaaaaa" * 6


class _FixedDatetime:
    @staticmethod
    def now(tz=None):
        import datetime as _dt

        return _dt.datetime(1970, 1, 1, 0, 0, 0, tzinfo=tz)
