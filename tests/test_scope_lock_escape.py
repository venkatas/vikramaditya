"""P0 — --scope-lock must never escape exact-host scope.

Canonical exact-host allowlist (S1): scope_checker.scope_lock_allows(host_or_url, exact_hosts)
returns True ONLY for a host that is EXACTLY one of the allowed hosts (or an explicitly-listed
host:port / IP). It must reject www., any subdomain, suffix-confusion, userinfo @-tricks, and
non-listed alternate ports — and FAIL CLOSED (False) on any parse ambiguity or empty allowlist.

Real engagement regression: under --scope-lock the tool still probed www., merged
hundreds of www + off-scope archive URLs, and vhost-fuzzed FUZZ.$TARGET.
"""
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import scope_checker  # noqa: E402


ALLOW = {"example.com"}


# ── exact host allowed ──────────────────────────────────────────────────────
@pytest.mark.parametrize("host", [
    "example.com", "EXAMPLE.com", "example.com.", "https://example.com/a?b=c",
    "http://example.com:80/", "https://example.com:443/x",   # default ports normalize
])
def test_exact_apex_allowed(host):
    assert scope_checker.scope_lock_allows(host, ALLOW) is True


# ── every escape vector rejected ────────────────────────────────────────────
@pytest.mark.parametrize("host", [
    "www.example.com",                       # the P0 www force-add
    "api.example.com", "old.example.com",    # subdomains
    "a.b.example.com",
    "example.com.evil.com",                  # suffix confusion (right-append)
    "notexample.com", "evil-example.com",    # prefix confusion
    "example.com.attacker.net",
    "https://example.com@evil.com/",         # userinfo trick → real host evil.com
    "https://evil.com/#example.com",         # fragment decoy
    "cdn.other.com", "other.com",            # unrelated
    "example.com:8443", "https://example.com:8443/",  # alt-port not listed
    "", "   ", "http://", "://example.com",   # malformed → fail closed
])
def test_escape_vectors_rejected(host):
    assert scope_checker.scope_lock_allows(host, ALLOW) is False


# ── alt-port allowed only when explicitly listed ────────────────────────────
def test_alt_port_allowed_when_listed():
    assert scope_checker.scope_lock_allows("example.com:8443", {"example.com:8443"}) is True
    assert scope_checker.scope_lock_allows("https://example.com:8443/x", {"example.com:8443"}) is True
    # a listed alt-port host must not also let the bare host's OTHER ports through
    assert scope_checker.scope_lock_allows("example.com:9000", {"example.com:8443"}) is False


# ── IP / CIDR targets: exact IP allowed, off-net rejected ───────────────────
def test_ip_target_exact_allowed():
    assert scope_checker.scope_lock_allows("203.0.113.5", {"203.0.113.5"}) is True
    assert scope_checker.scope_lock_allows("https://203.0.113.5/x", {"203.0.113.5"}) is True
    assert scope_checker.scope_lock_allows("203.0.113.6", {"203.0.113.5"}) is False


# ── fail closed: empty / missing allowlist scans nothing ────────────────────
def test_empty_allowlist_fails_closed():
    assert scope_checker.scope_lock_allows("example.com", set()) is False
    assert scope_checker.scope_lock_allows("example.com", None) is False


# ── multi-host (--targets-file) allowlist ───────────────────────────────────
def test_multi_host_allowlist():
    allow = {"example.com", "portal.example.com"}
    assert scope_checker.scope_lock_allows("portal.example.com", allow) is True
    assert scope_checker.scope_lock_allows("example.com", allow) is True
    assert scope_checker.scope_lock_allows("admin.example.com", allow) is False   # sibling not listed
    assert scope_checker.scope_lock_allows("www.portal.example.com", allow) is False


# ── URL-list filter (archive merge) drops off-scope, keeps in-scope ─────────
def test_filter_scope_lock_urls():
    urls = [
        "https://example.com/a",
        "https://www.example.com/b",          # off (www)
        "https://old.example.com/c",          # off (subdomain)
        "http://example.com/d?x=1",
        "https://cdn.other.com/e",            # off (unrelated)
        "https://example.com@evil.com/f",     # off (userinfo)
    ]
    kept = scope_checker.filter_scope_lock(urls, ALLOW)
    assert kept == ["https://example.com/a", "http://example.com/d?x=1"]


# ── CLI shim (recon.sh shells to this): exit 0 in-scope, nonzero off / fail-closed ──
def _cli(*args, allow_lines=None, tmp_path=None):
    allow_file = tmp_path / "allow.txt"
    allow_file.write_text("\n".join(allow_lines or []) + "\n")
    return subprocess.run(
        [sys.executable, str(REPO / "scope_checker.py"), "--scope-lock-check",
         "--allow-file", str(allow_file), *args],
        capture_output=True, text=True, timeout=30,
    )


def test_cli_check_in_scope(tmp_path):
    r = _cli("example.com", allow_lines=["example.com"], tmp_path=tmp_path)
    assert r.returncode == 0


def test_cli_check_off_scope_nonzero(tmp_path):
    r = _cli("www.example.com", allow_lines=["example.com"], tmp_path=tmp_path)
    assert r.returncode != 0


def test_cli_empty_allowlist_fails_closed(tmp_path):
    r = _cli("example.com", allow_lines=[], tmp_path=tmp_path)
    assert r.returncode != 0   # missing/empty allowlist under scope-lock → nothing in scope


def test_cli_filter_mode(tmp_path):
    allow_file = tmp_path / "allow.txt"; allow_file.write_text("example.com\n")
    inp = tmp_path / "urls.txt"
    inp.write_text("https://example.com/a\nhttps://www.example.com/b\nhttps://x.other.com/c\n")
    r = subprocess.run(
        [sys.executable, str(REPO / "scope_checker.py"), "--scope-lock-filter",
         "--allow-file", str(allow_file), "--in", str(inp), "--out", str(inp)],
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 0
    kept = inp.read_text().splitlines()
    assert kept == ["https://example.com/a"]
