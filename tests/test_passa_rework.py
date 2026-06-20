"""Regression tests for the Pass-A fix REWORK.

These lock in the 4 items the independent friends-verifiers flagged after the
first automated fix pass (correct-but-incomplete or new-bug-introduced):

  1. finding_validator.parse_severity — must honor ONLY anchored severity
     tokens; a bare severity word inside a URL/prose ("info" in "info.php",
     "low" in "low false-positive") must NOT downgrade a confirmed finding.
  2. brain_scanner._grounded_read_unproven — generalized gate used at the
     PRIMARY enforcement path; keeps grounded non-passwd reads, rejects bare /
     noise-padded claims.
  3. scopeguard._hostish — bare hex words (dd/beef) no longer fire getaddrinfo,
     while encoded loopback (decimal/hex/short-form) is still caught.
  4. browser phase partial — producer flag consumed by the hunt.py rollup so a
     partial run renders degraded, not a clean success.

Synthetic data only.
"""
import os
import re

import brain_scanner as bs
import finding_validator as fv
import scopeguard as sg

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ── 1. finding_validator severity ───────────────────────────────────────────
def test_bare_severity_word_in_url_or_prose_does_not_downgrade():
    assert fv.parse_severity("sqli at http://acme.invalid/info.php?id=1", "sqli") == "critical"
    assert fv.parse_severity("time-based sqli, low false-positive rate", "sqli") == "critical"
    assert fv.parse_severity("rce via http://h/low/path", "rce") == "critical"


def test_explicit_severity_tokens_still_honored():
    assert fv.parse_severity("xss reflected [CRITICAL] at /q", "xss") == "critical"
    assert fv.parse_severity("[HIGH - SQLi] x", "xss") == "high"
    assert fv.parse_severity("note (low)", "misconfig") == "low"
    assert fv.parse_severity("severity: high", "xss") == "high"
    assert fv.parse_severity("info: banner on /", "exposure") == "info"   # leading label


# ── 2. brain_scanner generalized grounded gate ──────────────────────────────
def test_grounded_nonpasswd_read_is_kept():
    out = ("[CRITICAL] /etc/hosts readable\n"
           "127.0.0.1 localhost\n10.0.0.5 app.internal\n192.168.1.1 gateway")
    assert bs._grounded_read_unproven("[CRITICAL] /etc/hosts readable", out) is False


def test_bare_access_claim_is_unproven():
    assert bs._grounded_read_unproven("[CRITICAL] accessible", "[CRITICAL] accessible") is True


def test_progress_noise_does_not_count_as_file_content():
    noise = "[CRITICAL] accessible\n[*] scanning target\n[+] connecting...\nProgress: 50%"
    assert bs._grounded_read_unproven("[CRITICAL] accessible", noise) is True


def test_primary_enforcement_path_uses_generalized_gate():
    src = open(os.path.join(REPO, "brain_scanner.py"), encoding="utf-8").read()
    assert "_grounded_read_unproven(line," in src, "primary path still uses the strict gate"


# ── 3. scopeguard _hostish perf tightening ──────────────────────────────────
def test_hostish_skips_bare_hex_words():
    for w in ("dd", "beef", "cafe", "add", "face", "decade"):
        assert sg._hostish(w) is False, f"{w} wrongly host-ish (would fire getaddrinfo)"


def test_hostish_still_catches_encoded_loopback():
    for w in ("2130706433", "0x7f000001", "127.1", "127.0.0.1", "::1", "localhost"):
        assert sg._hostish(w) is True, f"{w} no longer host-ish — loopback detection regressed"


# ── 4. browser phase partial (producer + consumer wiring) ───────────────────
def test_browser_agent_partial_property():
    from browser_agent import BrowserAgent
    a = BrowserAgent.__new__(BrowserAgent)
    a._tasks_completed, a._tasks_errored, a._partial = 1, 2, True
    assert a.partial is True
    b = BrowserAgent.__new__(BrowserAgent)
    b._tasks_completed, b._tasks_errored, b._partial = 3, 0, False
    assert b.partial is False


def test_hunt_browser_consumer_marks_partial_degraded():
    src = open(os.path.join(REPO, "hunt.py"), encoding="utf-8").read()
    assert 'getattr(agent, "partial"' in src, "hunt browser consumer never reads agent.partial"
    assert re.search(r'partial[\s\S]{0,400}_mark_degraded\("browser"', src), \
        "partial branch does not mark the browser phase degraded"
