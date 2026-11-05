"""Execute the actual Phase-3 block against fake httpx/curl; no target traffic.

Nonzero core/batch/retry exits must invalidate completion even if they printed
live hosts, a neighboring batch succeeded, or an old .probe.done exists.
"""
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
RECON = (REPO / "recon.sh").read_text()
PHASE3 = RECON.split('# Phase 3: HTTP Probing in Batches of BATCH_SIZE', 1)[1]
PHASE3 = PHASE3.split('fi  # end Phase 3 resume skip', 1)[0] + 'fi\n'


def _run_phase(tmp_path, scenario, *, target="203.0.113.5", resume=False, exact_scope=False):
    for directory in ("live", "subdomains", "priority"):
        (tmp_path / directory).mkdir(exist_ok=True)
    targets = tmp_path / "targets.txt"
    targets.write_text("203.0.113.5\n203.0.113.6\n")
    fake = tmp_path / "httpx"
    fake.write_text(f"#!{sys.executable}\n" + '''
import os, sys
from pathlib import Path
args = sys.argv[1:]
name = Path(args[args.index('-l') + 1]).name
with open(Path(os.environ['PROBE_TEST_DIR']) / 'requested-hosts.txt', 'a') as log:
    log.write(Path(args[args.index('-l') + 1]).read_text())
scenario = os.environ['SCENARIO']
if name == '.core_hosts.txt':
    if scenario == 'core_failure':
        print('core probe crashed', file=sys.stderr)
        sys.exit(139)
    sys.exit(0)
if name == '.scheme_retry.txt':
    if scenario == 'retry_failure':
        print('retry timed out', file=sys.stderr)
        sys.exit(124)
    sys.exit(0)
if scenario == 'partial_failure':
    print('https://203.0.113.5 [200]')
    print('crash after output', file=sys.stderr)
    sys.exit(139)
if scenario == 'mixed_failure':
    if name.endswith('aa'):
        print('https://203.0.113.5 [200]')
        sys.exit(0)
    print('second batch crashed', file=sys.stderr)
    sys.exit(139)
if scenario == 'core_failure':
    print('https://example.invalid [200]')
sys.exit(0)
''')
    fake.chmod(0o700)
    script = r'''
set -u
file_lines() { [ -f "$1" ] && wc -l < "$1" | tr -d ' ' || echo 0; }
log_info() { :; }
log_warn() { :; }
log_err() { :; }
log_ok() { :; }
log_step() { :; }
log_done() { :; }
tool_ok() { return 1; }
_host_in_scope() { return 1; }
_scope_filter_file() { :; }
phase_done() { [ "$RESUME_MODE" = 1 ] && [ -s "$1" ]; }
timeout() { shift; "$@"; }
curl() { printf '%s' 000; }
'''
    values = {
        "RECON_DIR": str(tmp_path), "HTTPX_BIN": str(fake),
        "HTTPX_HEALTHY": "1", "HTTPX_TARGET_FILE": str(targets),
        "TARGET": target, "BATCH_SIZE": "1", "PROBED_COUNT": "2",
        "RESOLVED_COUNT": "2", "HTTP_PROBE_TIMEOUT": "1",
        "RATE_LIMIT": "1", "THREADS": "1", "SCOPE_LOCK": "1",
        "RESUME_MODE": "1" if resume else "0",
        "SCRIPT_DIR": str(REPO),
    }
    if exact_scope:
        allow = tmp_path / "allow.txt"
        allow.write_text("203.0.113.5\n203.0.113.6\n")
        values["SCOPE_ALLOW_FILE"] = str(allow)
    script += "\n".join(f"{key}={shlex.quote(value)}" for key, value in values.items()) + "\n"
    if exact_scope:
        script += RECON[RECON.index('_host_in_scope() {'):RECON.index('# In resume mode:')]
    script += PHASE3
    script += '\nprintf "PROBE_FAILED=%s\\n" "${RECON_PROBE_FAILED:-0}"\n'
    result = subprocess.run(
        ["bash", "-c", script], env={**os.environ, "SCENARIO": scenario,
            "PROBE_TEST_DIR": str(tmp_path),
            "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"]},
        text=True, capture_output=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr
    return result


@pytest.mark.parametrize("scenario,target", [
    ("partial_failure", "203.0.113.5"),
    ("mixed_failure", "203.0.113.5"),
    ("retry_failure", "203.0.113.5"),
    ("core_failure", "example.invalid"),
])
def test_any_failed_invocation_prevents_completion(tmp_path, scenario, target):
    live = tmp_path / "live"
    live.mkdir()
    (live / ".probe.done").write_text("stale success\n")
    result = _run_phase(tmp_path, scenario, target=target)
    assert "PROBE_FAILED=1" in result.stdout
    assert (live / ".probe.failed").is_file()
    assert not (live / ".probe.done").exists()
    diagnostics = (live / "httpx_exit_codes.tsv").read_text()
    assert "\t139" in diagnostics or "\t124" in diagnostics
    assert (live / "httpx_stderr.log").stat().st_size > 0
    if scenario in {"partial_failure", "mixed_failure", "core_failure"}:
        assert "[200]" in (live / "httpx_full.txt").read_text()


def test_healthy_empty_probe_is_complete(tmp_path):
    result = _run_phase(tmp_path, "healthy_empty")
    assert "PROBE_FAILED=0" in result.stdout
    assert (tmp_path / "live" / ".probe.done").is_file()
    assert not (tmp_path / "live" / ".probe.failed").exists()
    assert (tmp_path / "live" / "httpx_full.txt").read_text() == ""


def test_resume_failed_attempt_reprobes_and_clears_failure_only_on_success(tmp_path):
    live = tmp_path / "live"
    _run_phase(tmp_path, "partial_failure")
    # A stale success marker must never mask a failed attempt during resume.
    (live / ".probe.done").write_text("stale\n")
    _run_phase(tmp_path, "partial_failure", resume=True)
    assert not (live / ".probe.done").exists()
    assert (live / ".probe.failed").is_file()
    _run_phase(tmp_path, "healthy_empty", resume=True)
    assert (live / ".probe.done").is_file()
    assert not (live / ".probe.failed").exists()
    exits = (live / "httpx_exit_codes.tsv").read_text()
    assert exits.count("# probe attempt") == 3


def test_stale_wider_scope_batch_is_filtered_before_httpx(tmp_path):
    subs = tmp_path / "subdomains"
    subs.mkdir()
    (subs / "batch_zz").write_text("outside.invalid\n")
    _run_phase(tmp_path, "healthy_empty", exact_scope=True)
    assert "outside.invalid" not in (tmp_path / "requested-hosts.txt").read_text()
    assert (tmp_path / "live" / ".probe.done").exists()
