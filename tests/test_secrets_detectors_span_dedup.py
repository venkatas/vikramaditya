"""Regression tests for whitebox/secrets/detectors.scan_text span-based dedup.

Covers the offset-only dedup bug: two detector matches that share a START
offset but differ in span must both survive, and a named-detector token must
not be re-reported under the generic "high_entropy" label.

All inputs are SYNTHETIC placeholders (no real credentials).
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from whitebox.secrets.detectors import scan_text  # noqa: E402


def _dets(hits):
    return [h["detector"] for h in hits]


def test_high_entropy_not_double_reported_for_named_span():
    # A synthetic Google-API-key-shaped token (AIza + 35 chars) is long enough
    # (>= ENTROPY_MIN_LEN) that the entropy pass would also match it. With
    # span-coverage dedup it must be emitted ONCE under the named detector only.
    token = "AIza" + "B" * 35
    hits = scan_text("key=" + token, "synthetic")
    dets = _dets(hits)
    assert "google_api_key" in dets
    assert dets.count("high_entropy") == 0


def test_two_distinct_named_secrets_both_emitted():
    # Two different synthetic secrets at different offsets both survive.
    text = "password=hunter2placeholder secret_key: " + "A" * 40
    hits = scan_text(text, "synthetic")
    dets = _dets(hits)
    assert "generic_password_assignment" in dets
    assert "aws_secret_access_key" in dets


def test_standalone_high_entropy_still_emitted():
    # A high-entropy blob with no named-detector coverage is still reported.
    blob = "aZ9bQ3xK7mN2pL5wT8vR4cY6dH0gF1jS"
    hits = scan_text("blob " + blob, "synthetic")
    assert "high_entropy" in _dets(hits)


def test_exact_duplicate_span_collapsed_once():
    # The same span matched by the same detector must not be duplicated.
    text = "AKIAIOSFODNN7EXAMPLE"
    hits = scan_text(text, "synthetic")
    aws = [h for h in hits if h["detector"] == "aws_access_key_id"]
    assert len(aws) == 1


def test_overlapping_entropy_inside_named_span_suppressed():
    # An entropy substring that sits strictly inside a named-detector span
    # (different start offset) must be suppressed by span-coverage, not just by
    # a coincidentally-equal start offset.
    token = "AIza" + "C" * 35  # 39 chars, named span covers it fully
    hits = scan_text("api_key = " + token + " trailer", "synthetic")
    # Only one finding for the key, and it is the named one.
    key_hits = [h for h in hits if h["value"].startswith("AIza")]
    assert len(key_hits) == 1
    assert key_hits[0]["detector"] == "google_api_key"
