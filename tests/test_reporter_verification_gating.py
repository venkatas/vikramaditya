"""reporter._apply_verification_gating must be CONSERVATIVE (Codex review).

It may only drop an EXPLICIT model-generated claim at medium+. Real scanner/tool findings —
even ones whose evidence text happens to contain the substring 'UNVERIFIED'/'PENDING' (e.g. a
leaked token 'AKIAUNVERIFIED...') — must NEVER be dropped. Hiding a real finding is worse than
reporting an unproven one.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import reporter  # noqa: E402

pytestmark = pytest.mark.skipif(not reporter._SCHEMA_OK, reason="finding_schema not importable")


def _f(**kw):
    kw.setdefault("severity", "high")
    kw.setdefault("raw", "")
    kw.setdefault("vtype", "misconfig")
    return kw


def test_real_finding_with_unverified_substring_is_kept():
    # the exact false-positive Codex flagged: 'UNVERIFIED' inside real evidence text
    f = _f(severity="critical", raw="leaked AWS key AKIAUNVERIFIEDKEY1234 in app.js")
    kept = reporter._apply_verification_gating([f])
    assert len(kept) == 1, "a real scanner finding must never be dropped for a substring"


def test_explicit_model_claim_medium_plus_is_dropped():
    f = _f(severity="high", raw="[MODEL CLAIM — verify PoC] possible SSRF on /fetch")
    kept = reporter._apply_verification_gating([f])
    assert kept == [], "an explicit unproven model claim at high must be dropped"


def test_model_claim_low_is_kept():
    f = _f(severity="low", raw="[MODEL CLAIM — verify PoC] minor info leak")
    kept = reporter._apply_verification_gating([f])
    assert len(kept) == 1, "low-severity claims are not gated out"


def test_explicit_verification_method_model_claim_dropped():
    f = _f(severity="critical", raw="RCE maybe", verification_method="model_claim")
    assert reporter._apply_verification_gating([f]) == []


def test_normal_scanner_findings_pass_through():
    fs = [_f(severity="medium", raw="nuclei: cors-misconfig on /api"),
          _f(severity="high", raw="dalfox: reflected XSS param q"),
          _f(severity="critical", raw="sqlmap: boolean-blind SQLi confirmed")]
    kept = reporter._apply_verification_gating(fs)
    assert len(kept) == 3, "real tool findings must all be kept"
