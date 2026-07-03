"""nomore403_audit — calibrated 401/403 bypass audit.

Covers the anti-false-positive calibration core, the [403-BYPASS-CANDIDATE]
output contract, and the reporter suppression that keeps a calibrated bypass a
LEAD rather than an auto-shipped CRITICAL (feedback_reporter_fabrication_verify).

JSON schema is the real nomore403 --json shape captured live:
    {"status_code": int, "content_length": int, "technique": str, "payload": str}
"""
import os

import nomore403_audit as nm


def _default(status=403, length=9):
    return {"status_code": status, "content_length": length,
            "technique": "default", "payload": "http://t/admin"}


def _row(technique, status, length):
    return {"status_code": status, "content_length": length,
            "technique": technique, "payload": f"http://t/admin::{technique}"}


# ── calibration core ─────────────────────────────────────────────────────────
def test_403_flipping_to_200_is_a_hit():
    results = [_default(403, 9), _row("hdr-ip", 200, 5123), _row("verbs", 403, 9)]
    hits = nm.calibrate_hits(results, 403)
    assert len(hits) == 1 and hits[0]["technique"] == "hdr-ip"


def test_all_forbidden_no_hits():
    results = [_default(403, 9), _row("hdr-ip", 403, 9), _row("verbs", 401, 12)]
    assert nm.calibrate_hits(results, 403) == []


def test_recon_status_not_forbidden_yields_nothing():
    # recon said 200 → not a gated resource → not a bypass no matter what
    results = [_default(200, 500), _row("hdr-ip", 200, 500)]
    assert nm.calibrate_hits(results, 200) == []


def test_tool_baseline_not_forbidden_yields_nothing():
    # recon mislabelled it / host is a catch-all 200 → tool's own baseline is 200
    results = [_default(200, 500), _row("hdr-ip", 200, 500)]
    assert nm.calibrate_hits(results, 403) == []


def test_catchall_guard_drops_uniform_signature():
    # many techniques all flip to the SAME (200, len) → catch-all noise, not real
    results = [_default(403, 9)] + [_row(f"t{i}", 200, 777) for i in range(6)]
    assert nm.calibrate_hits(results, 403) == []


def test_distinct_signatures_survive_catchall_guard():
    results = [_default(403, 9),
               _row("hdr-ip", 200, 100), _row("verbs", 200, 200),
               _row("unicode", 302, 0), _row("path-case", 200, 300),
               _row("double", 200, 400)]
    hits = nm.calibrate_hits(results, 403)
    assert len(hits) == 5


def test_dedup_identical_technique_status_length():
    results = [_default(403, 9), _row("hdr-ip", 200, 100), _row("hdr-ip", 200, 100)]
    assert len(nm.calibrate_hits(results, 403)) == 1


# ── output contract (anti-fabrication) ───────────────────────────────────────
def test_hit_line_has_candidate_prefix():
    line = nm.format_hit_line("http://t/admin", _row("hdr-ip", 200, 5123), 403, 9)
    assert line.startswith(nm.CANDIDATE_PREFIX)
    assert "403→200" in line and "technique=hdr-ip" in line


def test_reporter_suppresses_candidate_prefix():
    """The calibrated candidate must be a LEAD, not an auto-CRITICAL auth_bypass finding."""
    reporter_py = os.path.join(os.path.dirname(__file__), "..", "reporter.py")
    src = open(reporter_py).read()
    assert '"[403-BYPASS-CANDIDATE]"' in src, \
        "reporter.py NON_FINDING_PREFIXES must suppress [403-BYPASS-CANDIDATE]"


# ── url extraction ───────────────────────────────────────────────────────────
def test_extract_url_from_httpx_line():
    assert nm.extract_url("https://h.example [403] [9] [Forbidden] [1.2.3.4]") == "https://h.example"
    assert nm.extract_url("") == ""
    assert nm.extract_url("# comment") == ""


# ── audit orchestration (injected results_fn, no binary needed) ──────────────
def test_audit_writes_candidate_file(tmp_path):
    def fake_results(url):
        return [_default(403, 9), _row("hdr-ip", 200, 5123)]
    targets = [("https://h.example/admin", 403)]
    res = nm.audit(targets, str(tmp_path), results_fn=fake_results)
    assert res["ran"] and res["hits"] == 1
    out = tmp_path / "403_bypass_hits.txt"
    assert out.exists()
    body = out.read_text()
    assert body.startswith(nm.CANDIDATE_PREFIX) and "https://h.example/admin" in body


def test_audit_dedups_and_caps(tmp_path):
    calls = []

    def fake_results(url):
        calls.append(url)
        return [_default(403, 9)]  # no hits, just count invocations
    targets = [("https://a/x", 403), ("https://a/x", 403), ("https://b/y", 401)]
    res = nm.audit(targets, str(tmp_path), results_fn=fake_results, max_urls=1)
    assert res["urls_tested"] == 1 and calls == ["https://a/x"]


def test_audit_no_binary_reports_skip(tmp_path, monkeypatch):
    monkeypatch.setattr(nm, "find_binary", lambda explicit=None: None)
    res = nm.audit([("https://a/x", 403)], str(tmp_path))
    assert res["ran"] is False and "not installed" in res["reason"]


def test_audit_clean_target_writes_nothing(tmp_path):
    def fake_results(url):
        return [_default(403, 9), _row("verbs", 403, 9)]  # nothing bypassed
    res = nm.audit([("https://a/x", 403)], str(tmp_path), results_fn=fake_results)
    assert res["ran"] and res["hits"] == 0
    assert not (tmp_path / "403_bypass_hits.txt").exists()
