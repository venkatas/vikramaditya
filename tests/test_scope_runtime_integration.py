"""Execution-level wiring for guarded screenshots and absolute tool pins."""
from pathlib import Path
import shlex
import subprocess
import sys

import pytest
import hunt
import tool_resolution


REPO = Path(__file__).resolve().parent.parent
RECON = (REPO / "recon.sh").read_text()


def _run(body, **variables):
    setup = "\n".join(f"{k}={shlex.quote(str(v))}" for k, v in variables.items())
    result = subprocess.run(["/bin/bash", "-c", "set -uo pipefail\n" + setup + "\n" + body],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    return result.stdout


@pytest.mark.parametrize("locked,skip,expected", [(1, "", False), (0, "1", False), (0, "", True)])
def test_priority_screenshots_do_not_launch_unguarded_renderer(tmp_path, locked, skip, expected):
    for directory in ("live", "priority", "screenshots"):
        (tmp_path / directory).mkdir()
    (tmp_path / "live/urls.txt").write_text("https://allowed.invalid\n")
    start = RECON.index('# ── Visual recon on priority web assets')
    end = RECON.index('# ── Deep fingerprint', start)
    calls = tmp_path / "calls"
    body = r'''
log_info() { :; }; log_warn() { :; }; log_step() { :; }; log_done() { :; }
tool_ok() { return 0; }; phase_done() { return 1; }
file_lines() { wc -l < "$1"; }
gowitness() { printf '%s\n' "$*" >> "$CALLS"; }
''' + RECON[start:end]
    _run(body, RECON_DIR=tmp_path, SCOPE_LOCK=locked, SKIP_SCREENSHOTS=skip, QUICK_MODE="", CALLS=calls)
    assert calls.exists() == expected


@pytest.mark.parametrize("success", [True, False])
def test_locked_visual_phase_uses_allowlist_and_only_marks_success(tmp_path, success):
    (tmp_path / "live").mkdir()
    (tmp_path / "live/urls.txt").write_text("https://allowed.invalid\n")
    calls = tmp_path / "calls"
    start = RECON.index('mkdir -p "$RECON_DIR/screenshots"', RECON.index('# Phase 4.5: Visual Recon'))
    end = RECON.index('# Phase 6: URL Collection', start)
    body = r'''
log_warn() { :; }; log_info() { :; }; log_step() { :; }; log_done() { :; }
phase_done() { return 1; }
_scope_filter_file() { printf 'FILTER %s\n' "$1" >> "$CALLS"; }
python3() { printf '%s\n' "$@" >> "$CALLS"; return "$RENDER_RC"; }
gowitness() { echo UNGUARDED >> "$CALLS"; return 99; }
''' + RECON[start:end]
    _run(body, RECON_DIR=tmp_path, SCRIPT_DIR=REPO, SCOPE_LOCK=1, SKIP_SCREENSHOTS="",
         SCOPE_ALLOW_FILE=tmp_path / "scope/allow.txt", SCREENSHOT_MAX=0, CALLS=calls,
         RENDER_RC=0 if success else 2, TARGET_TYPE="domain")
    argv = calls.read_text()
    assert "UNGUARDED" not in argv
    assert str(REPO / "scoped_browser.py") in argv
    assert "--allow-file\n" + str(tmp_path / "scope/allow.txt") in argv
    assert "--coverage-file\n" + str(tmp_path / "coverage_degraded.json") in argv
    assert argv.startswith("FILTER ")
    assert (tmp_path / "screenshots/.scoped.done").exists() == success
    assert not (tmp_path / "screenshots/.gowitness.done").exists()


@pytest.mark.parametrize("available", [True, False])
def test_shell_wrappers_execute_only_health_selected_absolute_pins(tmp_path, available):
    # Stub resolution output, then prepend a known-bad Go directory *after*
    # sourcing. Wrappers must not fall through to it, even in a child Bash.
    selected = tmp_path / "healthy"
    selected.mkdir()
    bad = tmp_path / "bad"
    bad.mkdir()
    for name in ("httpx", "dnsx", "nuclei", "katana"):
        path = selected / name
        path.write_text("#!/bin/sh\nprintf 'healthy %s\\n' \"$*\"\n")
        path.chmod(0o755)
        path = bad / name
        path.write_text("#!/bin/sh\necho BAD\n")
        path.chmod(0o755)
    body = r'''
python3() {
    for key in HTTPX DNSX NUCLEI KATANA; do
        name=$(printf '%s' "$key" | tr 'A-Z' 'a-z')
        if [ "$AVAILABLE" = 1 ]; then
            printf 'export VIK_%s_BIN=%q\n' "$key" "$SELECTED/$name"
        else
            printf 'export VIK_%s_BIN=\n' "$key"
        fi
    done
}
. "$SCRIPT_DIR/tool_runtime.sh"
PATH="$BAD:$PATH"
for name in httpx dnsx nuclei katana; do
    if _vik_tool_ok "$name"; then "$name" --sentinel; else printf 'missing\n'; fi
done
/bin/bash -c 'httpx --child || echo missing'
'''
    result = _run(body, SCRIPT_DIR=REPO, SELECTED=selected, BAD=bad, AVAILABLE=int(available))
    assert "BAD" not in result
    assert result.count("healthy") == (5 if available else 0)
    assert result.count("missing") == (0 if available else 5)


def test_both_shell_entrypoints_source_the_shared_runtime():
    for filename in ("recon.sh", "scanner.sh"):
        text = (REPO / filename).read_text()
        assert '. "$SCRIPT_DIR/tool_runtime.sh"' in text
        assert '_vik_tool_ok "$1"' in text


def test_exact_python_consumers_preserve_ports_and_reject_parser_tricks(tmp_path, monkeypatch):
    scope = tmp_path / "scope"
    scope.mkdir()
    (scope / "allow.txt").write_text("example.invalid\napi.example.invalid:8443\n")
    monkeypatch.delenv("SCOPE_ALLOW_FILE", raising=False)
    allowed = hunt._exact_allowed_hosts("example.invalid", str(tmp_path))
    assert allowed == {"example.invalid", "api.example.invalid:8443"}
    for url in ("https://example.invalid/", "https://api.example.invalid:8443/"):
        assert hunt._url_in_exact_allowed_hosts(url, allowed)
    for url in ("https://api.example.invalid/", "https://api.example.invalid:9000/",
                "https://example.invalid:8443/", "https://www.example.invalid/",
                "https://example.invalid\\@outside.invalid/", "https://example.invalid/\n"):
        assert not hunt._url_in_exact_allowed_hosts(url, allowed)


def test_missing_explicit_scope_never_falls_back_to_live_siblings(tmp_path, monkeypatch):
    (tmp_path / "live").mkdir()
    (tmp_path / "live/urls.txt").write_text("https://api.example.invalid/\n")
    monkeypatch.setenv("SCOPE_ALLOW_FILE", str(tmp_path / "missing"))
    assert hunt._exact_allowed_hosts("example.invalid", str(tmp_path)) == set()


@pytest.mark.parametrize("locked", [True, False])
def test_get_sqlmap_redirect_flag_preserves_other_options(locked):
    command = hunt._build_get_sqlmap_command("/tmp/a b", "/tmp/sql", "/tmp/out", "--cookie=test",
                                            scope_lock=locked)
    argv = shlex.split(command)
    assert ("--ignore-redirects" in argv) == locked
    assert "--cookie=test" in argv
    assert argv[argv.index("-m") + 1] == "/tmp/a b"


def test_runtime_keeps_invoking_python_before_tool_prefix(tmp_path, monkeypatch):
    python_dir = tmp_path / "venv/bin"
    python_dir.mkdir(parents=True)
    tool_dir = tmp_path / "generic/bin"
    tool_dir.mkdir(parents=True)
    monkeypatch.setattr(tool_resolution, "resolve", lambda name, **kw: (str(tool_dir / name), None))
    env = tool_resolution.runtime_env(env={"PATH": "/usr/bin:/bin"}, python_bin=str(python_dir))
    assert env["PATH"].split(":")[0] == str(python_dir)
    for filename in ("recon.sh", "scanner.sh"):
        for line in (REPO / filename).read_text().splitlines():
            if line.startswith("export PATH="):
                assert line.startswith('export PATH="$PATH:'), "entrypoint shadows active interpreter"


def test_timeout_consumers_use_absolute_tool_pins():
    import re
    assert re.search(r'timeout\s+-k\s+15\s+300\s+"\$VIK_KATANA_BIN"', RECON)
    assert len(re.findall(r'timeout -k 30 300 "\$VIK_DNSX_BIN"', RECON)) == 2
    assert not re.search(r'timeout[^\n]*\s(?:dnsx|katana)\s+-', RECON)


@pytest.mark.parametrize("selected_rc", [0, 7])
def test_actual_external_timeout_cannot_pick_shadow_katana(tmp_path, selected_rc):
    import shutil
    timeout = shutil.which("timeout") or shutil.which("gtimeout")
    assert timeout, "external timeout is required to validate binary pinning"
    (tmp_path / "urls").mkdir()
    diagnostics = tmp_path / "urls/diagnostics"
    diagnostics.mkdir()
    selected = tmp_path / "healthy/katana"
    selected.parent.mkdir()
    selected.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$CALLS"\n'
                        'printf "selected tool diagnostic\\n" >&2\nexit "$SELECTED_RC"\n')
    selected.chmod(0o755)
    shadow = tmp_path / "bad/katana"
    shadow.parent.mkdir()
    shadow.write_text('#!/bin/sh\necho BAD > "$CALLS"\nexit 139\n')
    shadow.chmod(0o755)
    allow = tmp_path / "allow.txt"
    allow.write_text("example.invalid\n")
    start = RECON.index("    KATANA_SCOPE_FLAGS=()")
    end = RECON.index("\n# Merge all URLs", start)
    block = RECON[start:end].rsplit("\nfi", 1)[0]
    body = r'''
PATH="$BAD:$PATH"
export CALLS SELECTED_RC
timeout() { "$EXTERNAL_TIMEOUT" "$@"; }
log_warn() { :; }; log_err() { :; }; log_done() { :; }
file_lines() { echo 0; }
_url_collection_gap() { printf '%s: %s\n' "$1" "$2" >> "$GAPS"; }
''' + block + "\n:"
    calls = tmp_path / "calls"
    gaps = tmp_path / "gaps"
    _run(body, RECON_DIR=tmp_path, SCRIPT_DIR=REPO, SCOPE_LOCK=1,
         SCOPE_ALLOW_FILE=allow, TARGET_TYPE="domain", VIK_KATANA_BIN=selected,
         BAD=shadow.parent, EXTERNAL_TIMEOUT=timeout, CALLS=calls,
         URL_DIAGNOSTICS=diagnostics, GAPS=gaps, SELECTED_RC=selected_rc)
    argv = calls.read_text().splitlines()
    assert "BAD" not in argv
    assert "-dr" in argv and "-cs" in argv
    assert (diagnostics / "katana.stderr.log").read_text() == "selected tool diagnostic\n"
    assert (diagnostics / "exit_codes.tsv").read_text() == f"katana\t{selected_rc}\n"
    assert gaps.exists() == (selected_rc != 0)
    if selected_rc:
        assert f"crawler exited rc={selected_rc}" in gaps.read_text()


def test_restricting_previous_unlocked_session_filters_execution_not_passive_evidence(tmp_path):
    for directory in ("live", "urls", "subdomains", "priority"):
        (tmp_path / directory).mkdir()
    canonical = "https://example.invalid\nhttps://www.example.invalid\nhttps://outside.invalid\n"
    (tmp_path / "live/urls.txt").write_text(canonical)
    (tmp_path / "urls/js_files.txt").write_text(canonical)
    (tmp_path / "urls/gau.txt").write_text(canonical)
    (tmp_path / "live/httpx_full.txt").write_text("https://example.invalid [200]\nhttps://www.example.invalid [200]\n")
    (tmp_path / "subdomains/all.txt").write_text("example.invalid\nwww.example.invalid\n")
    assert hunt._restrict_session_scope("example.invalid", str(tmp_path)) == {"example.invalid"}
    assert (tmp_path / "scope/allow.txt").read_text() == "example.invalid\n"
    assert (tmp_path / "live/urls.txt").read_text() == "https://example.invalid\n"
    assert (tmp_path / "urls/js_files.txt").read_text() == "https://example.invalid\n"
    assert (tmp_path / "urls/gau.txt").read_text() == canonical
    assert (tmp_path / "live/httpx_full.txt").read_text() == "https://example.invalid [200]\n"


@pytest.mark.parametrize("flag", ["--post-params", "--request-file"])
def test_direct_cli_threads_scope_flag(monkeypatch, tmp_path, flag):
    calls = []
    monkeypatch.setattr(hunt, "init_brain", lambda **kw: None)
    monkeypatch.setattr(hunt, "_brain", None)
    monkeypatch.setattr(hunt, "run_post_param_discovery", lambda *a, **kw: calls.append(kw) or True)
    monkeypatch.setattr(hunt, "run_sqlmap_request_file", lambda *a, **kw: calls.append(kw) or True)
    argv = ["hunt.py", "--target", "example.invalid", "--scope-lock", "--no-brain", flag]
    if flag == "--request-file":
        argv.append(str(tmp_path / "request.txt"))
    monkeypatch.setattr(sys, "argv", argv)
    try:
        hunt.main()
    except SystemExit as exc:
        assert exc.code == 0
    assert calls and calls[0]["scope_lock"] is True


@pytest.mark.parametrize("mode", ["resume", "scan_only"])
def test_scope_is_bound_before_dispatch_when_recon_is_bypassed(tmp_path, monkeypatch, mode):
    (tmp_path / "live").mkdir()
    (tmp_path / "live/urls.txt").write_text("https://example.invalid\nhttps://outside.invalid\n")
    monkeypatch.setattr(hunt, "_brain", None)
    monkeypatch.setattr(hunt, "check_tool_readiness", lambda: [])
    monkeypatch.setattr(hunt, "_activate_recon_session", lambda *a, **kw: ("s1", str(tmp_path)))
    monkeypatch.setattr(hunt, "_resolve_recon_dir", lambda *a, **kw: str(tmp_path))
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda *a, **kw: str(tmp_path / "findings"))
    monkeypatch.setattr(hunt, "_resolve_reports_dir", lambda *a, **kw: str(tmp_path / "reports"))
    monkeypatch.setattr(hunt, "_enrich_targets_with_whitebox_asset_feed", lambda *a, **kw: [])
    monkeypatch.setattr(hunt, "run_recon", lambda *a, **kw: pytest.fail("recon should be bypassed"))

    class ObservedDispatch(Exception):
        pass

    def dispatch(*args):
        assert (tmp_path / "scope/allow.txt").read_text() == "example.invalid\n"
        assert (tmp_path / "live/urls.txt").read_text() == "https://example.invalid\n"
        raise ObservedDispatch

    monkeypatch.setattr(hunt, "run_param_discovery", dispatch)
    with pytest.raises(ObservedDispatch):
        hunt.hunt_target("example.invalid", scope_lock=True, param_discover=True,
                         **{mode: True})


@pytest.mark.parametrize("target_type", ["ip", "cidr"])
def test_locked_ip_screenshot_phase_uses_expanded_exact_ip_list(tmp_path, target_type):
    (tmp_path / "live").mkdir()
    (tmp_path / "subdomains").mkdir()
    (tmp_path / "live/urls.txt").write_text("http://192.0.2.1\n")
    (tmp_path / "subdomains/all.txt").write_text("192.0.2.1\n")
    start = RECON.index('mkdir -p "$RECON_DIR/screenshots"', RECON.index('# Phase 4.5: Visual Recon'))
    end = RECON.index('# Phase 6: URL Collection', start)
    body = r'''
log_warn() { :; }; log_info() { :; }; log_step() { :; }; log_done() { :; }
phase_done() { return 1; }; _scope_filter_file() { :; }
python3() { printf '%s\n' "$@" > "$CALLS"; }
''' + RECON[start:end]
    calls = tmp_path / "calls"
    _run(body, RECON_DIR=tmp_path, SCRIPT_DIR=REPO, TARGET_TYPE=target_type,
         SCOPE_LOCK=1, SCOPE_ALLOW_FILE="", SKIP_SCREENSHOTS="", SCREENSHOT_MAX=0, CALLS=calls)
    assert "--allow-file\n" + str(tmp_path / "subdomains/all.txt") in calls.read_text()


def test_reachability_scoped_redirect_never_contacts_denied_server():
    import http.server
    import threading
    hits = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", denied)
            else:
                self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        origin = f"http://127.0.0.1:{server.server_port}"
        denied = origin.replace("127.0.0.1", "localhost") + "/denied"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            allowed = {f"127.0.0.1:{server.server_port}"}
            assert hunt._url_reachable(origin + "/ok", allowed_hosts=allowed)
            assert hunt._url_reachable(origin + "/redirect", allowed_hosts=allowed)
            assert not hunt._url_reachable(denied, allowed_hosts=allowed)
            assert hits == ["/ok", "/redirect"]
        finally:
            server.shutdown()
            thread.join()


@pytest.mark.parametrize("locked", [True, False])
def test_arjun_generic_filters_locked_input_and_disables_redirects(tmp_path, monkeypatch, locked):
    for directory in ("live", "urls"):
        (tmp_path / directory).mkdir()
    (tmp_path / "live/urls.txt").write_text("https://example.invalid/\nhttps://outside.invalid/\n")
    if locked:
        (tmp_path / "scope").mkdir()
        (tmp_path / "scope/allow.txt").write_text("example.invalid\n")
    monkeypatch.delenv("SCOPE_ALLOW_FILE", raising=False)
    monkeypatch.setattr(hunt, "_resolve_recon_dir", lambda *a, **kw: str(tmp_path))
    monkeypatch.setattr(hunt, "_which", lambda name: name == "arjun")
    monkeypatch.setattr(hunt, "_brain", None)
    commands = []
    monkeypatch.setattr(hunt, "run_cmd", lambda command, **kw: (commands.append(command) or True, ""))
    assert hunt.run_param_discovery("example.invalid")
    assert len(commands) == 1
    assert ("--disable-redirects" in shlex.split(commands[0])) == locked
    targets = (tmp_path / "params/top_urls.txt").read_text()
    assert ("outside.invalid" in targets) != locked
