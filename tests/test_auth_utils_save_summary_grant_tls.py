"""Regression tests for auth_utils audit fixes (group: auth_utils.py).

Covers four confirmed audit findings:

1. FindingSaver.save_summary used "w" (truncate-then-dump), leaving summary.json
   empty/corrupt if interrupted mid-write. Fix: atomic temp-file + os.replace().

2. FindingSaver.save_txt wrote `detail` unescaped, so a newline or stray bracket
   in `detail` could split/mis-parse a finding line in reporter.py. Fix: normalise
   `detail` to a single line and neutralise `[`/`]`.

3. AuthSession._grant_is_dead text fallback false-positived on ordinary 401/403
   account-status prose containing "revoked"/"expired". Fix: broad terms now only
   match when a grant/token context word co-occurs.

4. AuthSession hardcoded session.verify=False, bypassing the VERIFY_TLS opt-in.
   Fix: session.verify is driven from VERIFY_TLS (strict by default).

SYNTHETIC data only.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from auth_utils import AuthSession, FindingSaver, VERIFY_TLS  # noqa: E402


# ── Finding [0]: atomic save_summary ──────────────────────────────────────────
def test_save_summary_writes_valid_json(tmp_path):
    d = str(tmp_path / "findings")
    s = FindingSaver(d, "idor")
    s.save({"id": "a1", "severity": "low", "detail": "synthetic"})
    s.save_summary()
    path = os.path.join(d, "idor", "summary.json")
    with open(path) as f:
        data = json.load(f)  # must parse — no truncation
    assert data["total"] == 1
    assert len(data["findings"]) == 1


def test_save_summary_atomic_no_partial_on_crash(tmp_path, monkeypatch):
    """If json.dump raises mid-write, the existing summary.json is untouched.

    The "w" truncate-then-dump bug would leave a zero-length / half-written
    file; the atomic temp+replace fix means the destination only ever holds the
    previous complete contents or the new complete contents, never a partial.
    """
    d = str(tmp_path / "findings")
    s = FindingSaver(d, "idor")
    s.save({"id": "good", "severity": "low"})
    s.save_summary()
    path = os.path.join(d, "idor", "summary.json")
    before = open(path).read()

    # Force the next dump to blow up partway. With atomic write the failure
    # lands on a temp file and os.replace is never reached, so `path` is intact.
    orig_dump = json.dump

    def boom(*a, **k):
        raise RuntimeError("simulated interruption (TCC lock / OOM)")

    # Append another finding BEFORE patching dump, so only save_summary's write
    # is interrupted (save() also uses json.dump).
    s._findings.append({"id": "more", "severity": "high"})
    monkeypatch.setattr("auth_utils.json.dump", boom)
    try:
        s.save_summary()
    except RuntimeError:
        pass

    after = open(path).read()
    assert after == before, "summary.json was clobbered by an interrupted write"
    # And it still parses as complete JSON.
    json.loads(after)
    # No leftover temp files in the directory.
    leftovers = [f for f in os.listdir(os.path.join(d, "idor")) if f.startswith(".summary.")]
    assert leftovers == [], f"temp file not cleaned up: {leftovers}"


# ── Finding [1]: save_txt one-line-per-finding ────────────────────────────────
def test_save_txt_newline_in_detail_stays_one_line(tmp_path):
    d = str(tmp_path / "findings")
    s = FindingSaver(d, "sqli")
    s.save_txt(
        {
            "severity": "high",
            "url": "https://example.invalid/x",
            "detail": "line one\nline two\r\nline three",
        }
    )
    txt = open(os.path.join(d, "sqli", "findings.txt")).read()
    assert txt.count("\n") == 1, "detail newlines split the finding across lines"
    assert "line one line two line three" in txt


def test_save_txt_brackets_in_detail_neutralised(tmp_path):
    d = str(tmp_path / "findings")
    s = FindingSaver(d, "sqli")
    s.save_txt(
        {
            "severity": "low",
            "url": "https://example.invalid/y",
            "detail": "payload [CRITICAL] reflected",
        }
    )
    line = open(os.path.join(d, "sqli", "findings.txt")).read().strip()
    # Exactly one leading [SEV] tag must survive; the detail bracket is rewritten.
    import re

    tags = re.findall(r"\[([^\]]+)\]", line)
    assert tags == ["LOW"], f"detail bracket leaked as a severity tag: {tags}"
    assert "(CRITICAL)" in line


# ── Finding [2]: _grant_is_dead false-positive guard ──────────────────────────
def test_grant_dead_account_revoked_prose_is_not_dead_grant():
    # Ordinary 401 with account-status prose must NOT trip a re-auth abort.
    assert AuthSession._grant_is_dead(401, "This account has been revoked") is False
    assert AuthSession._grant_is_dead(403, "Access revoked by administrator") is False
    assert AuthSession._grant_is_dead(401, "Your trial has expired") is False


def test_grant_dead_real_signals_still_detected():
    # Unambiguous grant phrases still fire.
    assert AuthSession._grant_is_dead(400, {"error": "invalid_grant"}) is True
    assert AuthSession._grant_is_dead(401, "the refresh token expired") is True
    # Broad term WITH grant/token context still fires.
    assert AuthSession._grant_is_dead(401, "your oauth token was revoked") is True
    assert AuthSession._grant_is_dead(400, "refresh token revoked") is True


def test_grant_dead_ignores_2xx():
    assert AuthSession._grant_is_dead(200, {"error": "invalid_grant"}) is False


# ── Finding [3]: session.verify honours VERIFY_TLS ────────────────────────────
def test_auth_session_verify_follows_toggle():
    sess = AuthSession("https://example.invalid")
    # By default (no VAPT_INSECURE_SSL) VERIFY_TLS is True => session is strict.
    assert sess._session.verify == VERIFY_TLS
    # It must not be unconditionally hardcoded False.
    if VERIFY_TLS:
        assert sess._session.verify is True
