"""Scope controls must be applied before crawler/fingerprint/SAN consumers run."""
from __future__ import annotations

import os
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys

import pytest

import scope_checker


REPO = Path(__file__).resolve().parent.parent
RECON = (REPO / "recon.sh").read_text()


@pytest.mark.parametrize("url", [
    "https://example.invalid/", "http://EXAMPLE.invalid/path?q=1",
    "https://example.invalid:443/", "http://example.invalid:80/",
    "https://example.invalid./", "https://api.example.invalid:8443/",
])
def test_crawl_scope_accepts_only_authorized_authorities(url):
    expression = scope_checker.scope_lock_crawl_regex({"example.invalid", "api.example.invalid:8443"})
    assert re.search(expression, url)
    assert scope_checker.scope_lock_allows(url, {"example.invalid", "api.example.invalid:8443"})


@pytest.mark.parametrize("url", [
    "https://www.example.invalid/", "https://example.invalid.evil.invalid/",
    "https://evil-example.invalid/", "https://example.invalid@evil.invalid/",
    "https://user@example.invalid/", "https://example.invalid:8443/",
    "https://api.example.invalid/", "https://api.example.invalid:9000/",
    "ftp://example.invalid/", "https://example.invalid%2eevil.invalid/",
])
def test_crawl_scope_rejects_escape_representations(url):
    expression = scope_checker.scope_lock_crawl_regex({"example.invalid", "api.example.invalid:8443"})
    assert re.search(expression, url) is None


@pytest.mark.parametrize("allowed", [set(), {"https://example.invalid"}, {"example.invalid@evil.invalid"}, {"bad host"}])
def test_invalid_crawl_allowlist_is_an_error(allowed):
    with pytest.raises(ValueError):
        scope_checker.scope_lock_crawl_regex(allowed)


def _shell(tmp_path, body, variables):
    setup = "\n".join(f"{key}={shlex.quote(str(value))}" for key, value in variables.items())
    helpers = r'''
set -uo pipefail
file_lines() { [ -f "$1" ] && wc -l < "$1" | tr -d ' ' || echo 0; }
log_info() { :; }; log_warn() { :; }; log_err() { :; }; log_ok() { :; }
log_step() { :; }; log_done() { :; }
timeout() { if [ "${1:-}" = -k ]; then shift 2; fi; shift; "$@"; }
_url_collection_gap() { RECON_URLS_FAILED=1; }
tool_ok() { return 0; }
phase_done() { return 1; }
VIK_KATANA_BIN=katana
'''
    if "RECON_DIR" in variables:
        diagnostics = Path(variables["RECON_DIR"]) / "urls" / "diagnostics"
        diagnostics.mkdir(parents=True, exist_ok=True)
        setup += "\nURL_DIAGNOSTICS=" + shlex.quote(str(diagnostics))
    env = {**os.environ, "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"]}
    # These phase fragments are followed by the next phase in recon.sh; a
    # final unchanged-filter predicate may legitimately return one under set -u.
    result = subprocess.run(["bash", "-c", helpers + setup + "\n" + body + "\n:"], env=env,
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    return result


@pytest.mark.parametrize("locked", [False, True])
def test_actual_katana_invocation_sets_pre_request_scope(tmp_path, locked):
    (tmp_path / "urls").mkdir()
    allow = tmp_path / "allow.txt"
    allow.write_text("example.invalid\n")
    calls = tmp_path / "calls"
    start = RECON.index("    KATANA_SCOPE_FLAGS=()")
    end = RECON.index("\n# Merge all URLs", start)
    block = RECON[start:end].rsplit("\nfi", 1)[0]
    body = 'katana() { printf "%s\\n" "$@" > "$CALLS"; }\n' + block
    _shell(tmp_path, body, {"RECON_DIR": tmp_path, "SCRIPT_DIR": REPO, "CALLS": calls,
                            "SCOPE_LOCK": int(locked), "SCOPE_ALLOW_FILE": allow,
                            "TARGET_TYPE": "domain"})
    argv = calls.read_text().splitlines()
    if locked:
        assert argv[argv.index("-fs") + 1] == "fqdn"
        assert "-dr" in argv
        expression = argv[argv.index("-cs") + 1]
        assert re.search(expression, "https://example.invalid/")
        assert not re.search(expression, "https://www.example.invalid/")
    else:
        assert "-fs" not in argv and "-cs" not in argv and "-dr" not in argv


def test_katana_missing_allowlist_never_starts(tmp_path):
    (tmp_path / "urls").mkdir()
    calls = tmp_path / "calls"
    start = RECON.index("    KATANA_SCOPE_FLAGS=()")
    end = RECON.index("\n# Merge all URLs", start)
    block = RECON[start:end].rsplit("\nfi", 1)[0]
    body = 'katana() { touch "$CALLS"; }\n' + block
    _shell(tmp_path, body, {"RECON_DIR": tmp_path, "SCRIPT_DIR": REPO, "CALLS": calls,
                            "SCOPE_LOCK": 1, "SCOPE_ALLOW_FILE": tmp_path / "missing",
                            "TARGET_TYPE": "domain"})
    assert not calls.exists()


@pytest.mark.parametrize("locked", [False, True])
def test_whatweb_actual_block_filters_initial_hosts_and_redirects(tmp_path, locked):
    priority = tmp_path / "priority"
    priority.mkdir()
    (priority / "critical_hosts.txt").write_text("https://example.invalid\nhttps://outside.invalid\n")
    calls = tmp_path / "calls"
    start = RECON.index('if tool_ok whatweb &&')
    end = RECON.index('\nASYNC_LOG_DIR=', start)
    body = r'''
_host_in_scope() { [ "$SCOPE_LOCK" != 1 ] || [ "$1" = https://example.invalid ]; }
whatweb() { printf '%s\n' "$@" >> "$CALLS"; }
''' + RECON[start:end]
    _shell(tmp_path, body, {"RECON_DIR": tmp_path, "CALLS": calls, "SCOPE_LOCK": int(locked)})
    argv = calls.read_text().splitlines()
    assert ("--follow-redirect=never" in argv) == locked
    assert ("https://outside.invalid" in argv) != locked


@pytest.mark.parametrize("locked", [False, True])
def test_san_feedback_preserves_candidates_without_widening_locked_scope(tmp_path, locked):
    for directory in ("certs", "live", "subdomains"):
        (tmp_path / directory).mkdir()
    (tmp_path / "live" / "ips.txt").write_text("203.0.113.5\n")
    (tmp_path / "subdomains" / "all.txt").write_text("example.invalid\n")
    allow = tmp_path / "allow.txt"
    allow.write_text("example.invalid\n")
    start = RECON.index('if phase_done "$RECON_DIR/certs/sans.txt"')
    end = RECON.index('\n# ── uncover shodan-idb', start)
    scope_helpers = RECON[RECON.index('_host_in_scope() {'):RECON.index('# In resume mode:')]
    body = r'''
tlsx() { cat >/dev/null; printf '%s\n' api.example.invalid outside.invalid; }
''' + scope_helpers + RECON[start:end]
    _shell(tmp_path, body, {"RECON_DIR": tmp_path, "SCRIPT_DIR": REPO, "TARGET": "example.invalid",
                            "SCOPE_LOCK": int(locked), "SCOPE_ALLOW_FILE": allow})
    merged = (tmp_path / "subdomains" / "all.txt").read_text()
    assert ("api.example.invalid" in merged) != locked
    assert "outside.invalid" not in merged
    assert "api.example.invalid" in (tmp_path / "certs" / "sans.txt").read_text()
    if locked:
        assert "api.example.invalid" in (tmp_path / "certs" / "san_candidates.txt").read_text()
        assert (tmp_path / "certs" / "in_scope_new.txt").read_text() == ""
        summary = json.loads((tmp_path / "certs" / "summary.json").read_text())
        assert summary["in_scope_new_count"] == 0
        assert "api.example.invalid" in summary["out_of_scope_sample"]
