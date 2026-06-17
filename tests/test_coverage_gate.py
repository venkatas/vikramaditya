"""Proportional finish-gating for the agent (Feature #2, adapted from xalgorix
hookFinishGatekeeper). Replaces the crude `step_count < 6` with: adaptive floor by
surface size + a nudge when core vuln classes are still untested. Stops shallow
"ran recon + 1 tool, declared done" scans that silently miss findings.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import coverage_gate as cg  # noqa: E402


def test_surface_tier_floors_scale_with_size():
    assert cg.surface_tier(5)[0] == "small"
    assert cg.surface_tier(50)[0] == "medium"
    assert cg.surface_tier(5000)[0] == "large"
    # floors are non-decreasing with size
    assert cg.surface_tier(5)[1] <= cg.surface_tier(50)[1] <= cg.surface_tier(5000)[1]


def test_tested_classes_maps_tools():
    steps = ["run_recon", "run_sqlmap_targeted", "run_cors_check"]
    tc = cg.tested_classes(steps)
    assert "sqli" in tc and "cors" in tc


def test_untested_core_reports_gaps():
    # ran sqli + cors but not rce/jwt
    missing = cg.untested_core(["run_sqlmap_targeted", "run_cors_check"])
    assert "rce" in missing and "jwt" in missing
    assert "sqli" not in missing and "cors" not in missing


def test_can_finish_blocks_below_floor():
    ok, reason = cg.can_finish(["run_recon"], n_endpoints=50)
    assert ok is False
    assert "tool" in reason.lower() or "floor" in reason.lower() or "need" in reason.lower()


def test_can_finish_blocks_when_core_classes_untested():
    # floor met (9 scan tools on a medium surface) but core classes rce/jwt never tested
    steps = ["run_recon", "run_vuln_scan", "run_sqlmap_targeted", "run_cors_check",
             "run_param_discovery", "run_secret_hunt", "run_js_analysis", "run_api_fuzz",
             "run_cms_exploit", "read_recon_summary", "read_findings_summary"]
    ok, reason = cg.can_finish(steps, n_endpoints=50)
    assert ok is False
    assert "rce" in reason or "jwt" in reason


def test_can_finish_allows_when_floor_and_core_met():
    steps = ["run_recon", "run_vuln_scan", "run_sqlmap_targeted", "run_cors_check",
             "run_rce_scan", "run_jwt_audit", "run_param_discovery", "run_secret_hunt"]
    ok, reason = cg.can_finish(steps, n_endpoints=10)
    assert ok is True


def test_can_finish_small_surface_lenient():
    # a tiny surface (e.g. 1 static page) shouldn't demand the full battery — but still
    # blocks an immediate finish with nothing run
    ok, _ = cg.can_finish([], n_endpoints=1)
    assert ok is False
    ok2, _ = cg.can_finish(
        ["run_recon", "run_vuln_scan", "run_sqlmap_targeted", "run_cors_check",
         "run_rce_scan", "run_jwt_audit"], n_endpoints=1)
    assert ok2 is True
