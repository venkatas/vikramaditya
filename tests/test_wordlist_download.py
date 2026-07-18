"""P2 — corrupt wordlists + fail-open downloader.

`--setup-wordlists` requested two wrong SecLists URLs; raw.githubusercontent replied
`404: Not Found` and an earlier `curl -sL` (no -f) SAVED that body as the wordlist. The
14-byte '404: Not Found' blobs were committed and never repaired (the >100-byte skip guard
did not catch them; a corrupt list is not in check_tool_readiness), so payload coverage was
silently degraded. Now: validate to a temp file + atomic replace; a required list that is
missing/invalid is a visible coverage failure. No network — curl is mocked.
"""
import os
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import hunt  # noqa: E402


def _fake_curl(content):
    """Return a run_cmd stub that writes `content` to the `-o "<tmp>"` path (None => curl fails)."""
    def _rc(cmd, timeout=None, **kw):
        m = re.search(r'-o "([^"]+)"', cmd)
        if content is not None and m:
            with open(m.group(1), "w") as fh:
                fh.write(content)
            return True, ""
        return False, "curl failed"
    return _rc


VALID = "\n".join(f"payload-{i}" for i in range(12)) + "\n"


# ── the committed files are real content, not the '404' blob ─────────────────
@pytest.mark.parametrize("name", [
    "sqli-payloads.txt", "xss-payloads.txt", "ssrf-payloads.txt",
    "redirect-payloads.txt", "lfi-payloads.txt",
])
def test_committed_wordlists_are_valid(name):
    assert hunt._wordlist_content_valid(os.path.join(hunt.WORDLIST_DIR, name)), \
        f"{name} is not valid content (corrupt/HTML/too-small)"


# ── content validator rejects the exact defect + HTML + too-small ────────────
@pytest.mark.parametrize("body", [
    "404: Not Found\n",
    "<!DOCTYPE html>\n<html><head></head><body>Not here</body></html>\n" * 3,
    "a\nb\n",                                        # too few lines
    "",                                              # empty
])
def test_validator_rejects_bad_bodies(tmp_path, body):
    p = tmp_path / "w.txt"
    p.write_text(body)
    assert hunt._wordlist_content_valid(str(p)) is False


def test_validator_accepts_xss_starting_with_angle_bracket(tmp_path):
    # XSS payload lists legitimately start with '<script>' — must NOT be misread as HTML
    p = tmp_path / "xss.txt"
    p.write_text("\n".join(["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                            "<svg onload=alert(1)>", "<body onload=alert(1)>",
                            "javascript:alert(1)", "\"><script>alert(1)</script>"]) + "\n")
    assert hunt._wordlist_content_valid(str(p)) is True


# ── downloader: temp + validate + atomic replace, fail-closed on bad ─────────
def test_download_valid_atomically_replaces(tmp_path, monkeypatch):
    monkeypatch.setattr(hunt, "WORDLIST_DIR", str(tmp_path))
    monkeypatch.setattr(hunt, "run_cmd", _fake_curl(VALID))
    ok = hunt._download_validated_wordlist("x.txt", "http://x/y", required=True)
    assert ok is True
    assert (tmp_path / "x.txt").read_text() == VALID
    assert not (tmp_path / "x.txt.tmp").exists(), ".tmp not cleaned up after replace"


@pytest.mark.parametrize("bad", ["404: Not Found\n", "<!DOCTYPE html><html>x</html>\n" * 4, "one\ntwo\n"])
def test_download_bad_never_overwrites_existing(tmp_path, monkeypatch, bad):
    monkeypatch.setattr(hunt, "WORDLIST_DIR", str(tmp_path))
    good = tmp_path / "x.txt"
    good.write_text(VALID)                            # a good file already present
    monkeypatch.setattr(hunt, "run_cmd", _fake_curl(bad))
    ok = hunt._download_validated_wordlist("x.txt", "http://x/y", required=True)
    assert ok is False
    assert good.read_text() == VALID, "an invalid download overwrote a good wordlist"
    assert not (tmp_path / "x.txt.tmp").exists(), ".tmp left behind after a rejected download"


def test_download_curl_failure_is_fail_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(hunt, "WORDLIST_DIR", str(tmp_path))
    monkeypatch.setattr(hunt, "run_cmd", _fake_curl(None))    # curl -f exits non-zero
    assert hunt._download_validated_wordlist("x.txt", "http://x/y") is False
    assert not (tmp_path / "x.txt").exists()


# ── existing corrupt file gets re-validated and re-fetched by setup ──────────
def test_setup_refetches_committed_corrupt_file(tmp_path, monkeypatch):
    monkeypatch.setattr(hunt, "WORDLIST_DIR", str(tmp_path))
    # a committed corrupt '404' blob is present (and >100 bytes so the OLD size guard skipped it)
    (tmp_path / "sqli-payloads.txt").write_text("404: Not Found\n" + "x" * 200)
    monkeypatch.setattr(hunt, "run_cmd", _fake_curl(VALID))   # re-fetch returns good content
    still_bad = hunt.setup_wordlists()
    assert "sqli-payloads.txt" not in still_bad
    assert hunt._wordlist_content_valid(str(tmp_path / "sqli-payloads.txt"))


# ── required-list failure → non-empty return (drives caller sys.exit(1)) ─────
def test_setup_returns_failed_required(tmp_path, monkeypatch):
    monkeypatch.setattr(hunt, "WORDLIST_DIR", str(tmp_path))
    monkeypatch.setattr(hunt, "run_cmd", _fake_curl("404: Not Found\n"))   # every fetch 404s
    still_bad = hunt.setup_wordlists()
    assert set(hunt._REQUIRED_WORDLISTS) <= set(still_bad), \
        "required lists that failed to download must be reported for a fail-closed exit"


def test_setup_wordlists_caller_exits_on_required_failure():
    # the --setup-wordlists dispatcher must sys.exit(1) when setup returns failures
    h = (REPO / "hunt.py").read_text()
    assert "_bad = setup_wordlists()" in h and "sys.exit(1)" in h


# ── check_tool_readiness surfaces a corrupt payload list as a gap ────────────
def test_readiness_flags_corrupt_wordlist(tmp_path, monkeypatch):
    monkeypatch.setattr(hunt, "WORDLIST_DIR", str(tmp_path))
    (tmp_path / "sqli-payloads.txt").write_text("404: Not Found\n")   # corrupt
    for n in ("xss-payloads.txt", "ssrf-payloads.txt", "redirect-payloads.txt"):
        (tmp_path / n).write_text(VALID)                              # others fine
    monkeypatch.setattr(hunt, "_httpx_readiness_reason", lambda *a, **k: None)
    gaps = hunt.check_tool_readiness(installed=[])
    assert any(g["tool"] == "sqli-payloads.txt" for g in gaps), \
        "a corrupt payload wordlist is not surfaced as a readiness gap"
