#!/usr/bin/env python3
"""Regression tests for legacy_crawler.py audit fixes (group legacy_crawler.py).

All data here is SYNTHETIC (example.invalid / placeholder creds). No network,
no Playwright, no scan is performed — these exercise the pure units only.

Covers:
  * dedup key includes the query string (query-distinct variants not collapsed)
  * max_pages=0 means UNLIMITED; positive cap exposes cap_reached/queue_remaining
  * per-path query-variant budget caps fan-out and sets a degradation marker
  * time-based SQLi differential gate (baseline + margin, multi-round) rejects a
    single transient slowdown (false-positive guard)
  * JS login body passes values as DATA, never f-string-interpolated source
"""
import inspect
import re
from urllib.parse import urlparse

import pytest

from legacy_crawler import LegacyCrawler

CREDS = "tester@example.invalid:placeholder-pw"
URL = "https://app.example.invalid"


def _mk(**kw):
    return LegacyCrawler(URL, CREDS, **kw)


# ── dedup keys on path + query (finding 1) ────────────────────────────────────

def test_norm_key_includes_query():
    c = _mk()
    k1 = c._norm_key(urlparse(f"{URL}/view.php?id=1"))
    k2 = c._norm_key(urlparse(f"{URL}/view.php?id=2"))
    k3 = c._norm_key(urlparse(f"{URL}/view.php?file=../../etc/passwd"))
    assert k1 != k2 != k3
    assert k1 == "/view.php?id=1"
    # bare path (no query) keeps the legacy plain-path key
    assert c._norm_key(urlparse(f"{URL}/view.php")) == "/view.php"


# ── query-variant budget + degradation marker (finding 1) ─────────────────────

def test_variant_budget_caps_and_marks_degraded():
    c = _mk()
    c.max_query_variants_per_path = 10
    allowed = [c._variant_budget_ok(urlparse(f"{URL}/p.php?id={i}")) for i in range(12)]
    assert allowed[:10] == [True] * 10
    assert allowed[10] is False and allowed[11] is False
    assert c.cap_reached is True  # degradation marker, not silent loss


def test_variant_budget_never_throttles_plain_paths():
    c = _mk()
    for _ in range(50):
        assert c._variant_budget_ok(urlparse(f"{URL}/static-page")) is True
    assert c.cap_reached is False


# ── unlimited vs capped page semantics (finding 2) ────────────────────────────

def test_max_pages_zero_is_unlimited_default_via_orchestrator():
    # vikramaditya.run_legacy_crawl passes max_pages=(max_urls or 0); the bare
    # full run must be UNLIMITED (0), not the legacy 200 default.
    c = _mk(max_pages=0)
    assert c.max_pages == 0
    # fresh crawler carries no false cap markers
    assert c.cap_reached is False
    assert c.queue_remaining == 0


def test_results_dict_exposes_cap_markers():
    # The persisted results must carry cap_reached + queue_remaining so a
    # consumer can tell a full crawl from a truncated one.
    src = inspect.getsource(LegacyCrawler._async_scan)
    assert "'cap_reached': self.cap_reached" in src
    assert "'queue_remaining': self.queue_remaining" in src


# ── time-based SQLi false-positive guard (finding 5) ──────────────────────────

def test_time_sqli_requires_baseline_margin_and_multi_round():
    src = inspect.getsource(LegacyCrawler._fuzz_forms)
    # baseline control request exists
    assert "vikram_baseline" in src
    # margin gate over baseline (not bare elapsed >= delay)
    assert "slow - baseline >= 3.5" in src
    assert "fast - baseline < 1.5" in src
    # multi-round confirmation, not a single retry
    assert "rounds" in src and "for _r in range(rounds)" in src


# ── JS login injection-safe (finding 3) ───────────────────────────────────────

def test_login_passes_values_as_data_not_interpolated():
    src = inspect.getsource(LegacyCrawler._login)
    # values are passed via Playwright's argument form (vals.user etc.)
    assert "setVal(\"login\", vals.user)" in src
    assert "vals.domain_part" in src and "vals.user_part" in src
    # no f-string that interpolates the raw username straight into JS source
    assert 'setVal("login", "{user}")' not in src
    # the evaluate call binds a data dict argument
    assert '{"user": user, "domain_part": domain_part, "user_part": user_part}' in src


def test_login_body_has_no_unescaped_credential_interpolation():
    # A credential containing a double quote must not be able to break out of
    # the JS evaluate body. Scope the check to the JS source that gets executed
    # (the setVal block), not Python log f-strings elsewhere in the method.
    src = inspect.getsource(LegacyCrawler._login)
    # The JS body must reference values only via the bound `vals.*` data arg.
    js_body = src[src.index("setVal = (n, v)"):src.index("FormName")]
    assert not re.search(r'\{user\}|\{pwd\}|\{user_part\}|\{domain_part\}', js_body)
    assert "vals.user" in js_body


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
