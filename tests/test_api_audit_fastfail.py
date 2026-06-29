"""OpenAPI discovery must fast-fail on a black-holing host.

GAP (audit 2026-06-14): discover_specs() probed every candidate host × all SPEC_PATHS serially
with a 6s-timeout fetch and no per-host fast-fail. On client-b.example one host silently dropped SYN,
so Phase 6.5 hung ~10 min (paths × 6s). Fix: abandon a host after 3 consecutive connect failures
(fetch status 0).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import api_audit  # noqa: E402


def test_discover_specs_fast_fails_on_black_hole(monkeypatch, tmp_path):
    monkeypatch.setattr(api_audit, "collect_candidate_hosts",
                        lambda *a, **k: (["https://deadhost.example"], 1))
    calls = {"n": 0}

    def _dead_fetch(url, timeout=6):
        calls["n"] += 1
        return {"status": 0, "content_type": "", "body": "", "final_url": url}

    monkeypatch.setattr(api_audit, "fetch", _dead_fetch)
    specs, ops, cands, raw, total = api_audit.discover_specs(tmp_path, max_hosts=5)
    assert specs == [] and ops == []
    assert calls["n"] <= 3, (
        f"a SYN-dropping host must fast-fail after 3 probes, got {calls['n']} "
        f"of {len(api_audit.SPEC_PATHS)} paths")


def test_discover_specs_probes_all_paths_when_host_responds(monkeypatch, tmp_path):
    monkeypatch.setattr(api_audit, "collect_candidate_hosts",
                        lambda *a, **k: (["https://live.example"], 1))
    calls = {"n": 0}

    def _live_fetch(url, timeout=6):
        calls["n"] += 1
        # responds (404) but no spec — must NOT be mistaken for a black-hole
        return {"status": 404, "content_type": "text/html", "body": "nope", "final_url": url}

    monkeypatch.setattr(api_audit, "fetch", _live_fetch)
    api_audit.discover_specs(tmp_path, max_hosts=5)
    assert calls["n"] == len(api_audit.SPEC_PATHS), (
        "a responding host must be probed across all spec paths (no premature fast-fail)")
