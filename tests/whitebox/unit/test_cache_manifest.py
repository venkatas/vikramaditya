import json
import time
from pathlib import Path
from whitebox.cache.manifest import PhaseCache


def test_fresh_phase_returns_valid(tmp_path):
    cache = PhaseCache(tmp_path, ttl_seconds=3600)
    cache.mark_complete("inventory", artifacts={"file": "inventory/ec2.json"})
    assert cache.is_fresh("inventory")
    meta = cache.get("inventory")
    assert meta["artifacts"]["file"] == "inventory/ec2.json"


def test_expired_phase_returns_stale(tmp_path):
    cache = PhaseCache(tmp_path, ttl_seconds=1)
    cache.mark_complete("inventory")
    time.sleep(1.5)
    assert not cache.is_fresh("inventory")


def test_refresh_invalidates_all(tmp_path):
    cache = PhaseCache(tmp_path, ttl_seconds=3600)
    cache.mark_complete("inventory")
    cache.mark_complete("prowler")
    cache.refresh()
    assert not cache.is_fresh("inventory")
    assert not cache.is_fresh("prowler")


def test_corrupt_manifest_invalidates_phase(tmp_path):
    cache = PhaseCache(tmp_path, ttl_seconds=3600)
    cache.mark_complete("inventory")
    # corrupt the file
    (tmp_path / "manifest.json").write_text("{not json")
    cache2 = PhaseCache(tmp_path, ttl_seconds=3600)
    assert not cache2.is_fresh("inventory")


def test_failed_phase_is_not_fresh(tmp_path):
    cache = PhaseCache(tmp_path, ttl_seconds=3600)
    cache.mark_failed("prowler", error="subprocess crashed")
    assert not cache.is_fresh("prowler")
    assert cache.get("prowler")["status"] == "failed"
