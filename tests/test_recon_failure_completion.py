"""Execute recon's archive/crawler/port blocks with local fake tools only."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "recon.sh").read_text()
HELPERS = SOURCE[SOURCE.index("_record_recon_gap() {"):SOURCE.index("refresh_priority() {")]
PORTS = SOURCE[SOURCE.index("run_phase5_port_scanning() {"):SOURCE.index("run_phase11_takeover_check() {")]
ARCHIVES = SOURCE[SOURCE.index("# gau — historical URLs"):SOURCE.index("# waymore — richer archive")]
KATANA = SOURCE[SOURCE.index("# katana — active crawl"):SOURCE.index("# Merge all URLs")]
URL_GATE = "\n".join(SOURCE[SOURCE.index(
    'if [ ! -e "$RECON_DIR/urls/.urls.failed"'):].splitlines()[:3]) + "\n"


def _preamble(tmp_path, *, resume=False):
    for name in ("urls", "ports", "subdomains", "priority", "live"):
        (tmp_path / name).mkdir(exist_ok=True)
    (tmp_path / "subdomains/resolved.txt").write_text("example.invalid\n")
    (tmp_path / "urls/archive_targets.txt").write_text("example.invalid\n")
    (tmp_path / "live/urls.txt").write_text("https://example.invalid\n")
    (tmp_path / "urls/diagnostics").mkdir(exist_ok=True)
    values = {
        "RECON_DIR": str(tmp_path), "SCRIPT_DIR": str(ROOT),
        "TARGET": "example.invalid", "RESUME_MODE": "1" if resume else "",
        "GAU_TIMEOUT": "1", "WAYBACK_TIMEOUT": "1", "SCOPE_LOCK": "0",
        "THREADS": "1", "FULL_RECON": "1", "TARGET_TYPE": "domain",
        "ARCHIVE_TARGETS": str(tmp_path / "urls/archive_targets.txt"),
        "URL_DIAGNOSTICS": str(tmp_path / "urls/diagnostics"),
        "RECON_URLS_FAILED": "0", "VIK_KATANA_BIN": "fake_katana",
    }
    script = "set -uo pipefail\n" + "\n".join(
        f"{key}={shlex.quote(value)}" for key, value in values.items()) + "\n"
    script += r'''
file_lines() { [ -f "$1" ] && wc -l < "$1" | tr -d ' ' || echo 0; }
log_info() { printf 'INFO %s\n' "$1"; }
log_warn() { printf 'WARN %s\n' "$1"; }
log_err() { printf 'ERR %s\n' "$1"; }
log_step() { printf 'STEP %s\n' "$1"; }
log_done() { printf 'DONE %s\n' "$1"; }
phase_done() { [ -n "$RESUME_MODE" ] && [ -s "$1" ]; }
_scope_filter_file() { :; }
timeout() { [ "$1" != -k ] || shift 2; shift; "$@"; }
'''
    return script + HELPERS


def _run(tmp_path, script, **values):
    result = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, timeout=15,
        env={**os.environ, **{key: str(value) for key, value in values.items()},
             "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"]})
    assert result.returncode == 0, result.stderr
    return result


def _archives(tmp_path, *, primary=0, fallback=0, wayback=0, use_gau=True, empty=False,
              resume=False):
    script = _preamble(tmp_path, resume=resume)
    script += r'''
tool_ok() { [ "$1" != gau ] || [ "$USE_GAU" = 1 ]; }
gau() {
    printf 'gau call\n' >> "$RECON_DIR/gau.calls"
    cat >/dev/null
    if [ "${1:-}" = --threads ]; then
        while [ "$1" != --o ]; do shift; done
        if [ "$EMPTY_ARCHIVES" = 1 ]; then : > "$2"; else printf 'https://example.invalid/primary\n' > "$2"; fi
        printf 'primary diagnostic\n' >&2
        return "$PRIMARY_RC"
    fi
    [ "$EMPTY_ARCHIVES" = 1 ] || printf 'https://example.invalid/fallback\n'
    printf 'fallback diagnostic\n' >&2
    return "$FALLBACK_RC"
}
waybackurls() {
    cat >/dev/null
    [ "$EMPTY_ARCHIVES" = 1 ] || printf 'https://example.invalid/wayback\n'
    printf 'wayback diagnostic\n' >&2
    return "$WAYBACK_RC"
}
curl() {
    [ "$EMPTY_ARCHIVES" = 1 ] || printf 'https://example.invalid/cdx\n'
    printf 'CDX diagnostic\n' >&2
    return "$WAYBACK_RC"
}
'''
    script += URL_GATE + ARCHIVES + '\n_finish_url_collection || true\nfi\n'
    return _run(tmp_path, script, PRIMARY_RC=primary, FALLBACK_RC=fallback,
                WAYBACK_RC=wayback, USE_GAU=int(use_gau), EMPTY_ARCHIVES=int(empty))


@pytest.mark.parametrize("kwargs,tool", [
    ({"primary": 124, "fallback": 124}, "gau"),
    ({"wayback": 7}, "waybackurls"),
    ({"wayback": 22, "use_gau": False}, "wayback"),
])
def test_archive_failure_keeps_partial_evidence_and_invalidates_completion(tmp_path, kwargs, tool):
    urls = tmp_path / "urls"
    urls.mkdir()
    (urls / ".urls.done").write_text("stale success\n")
    result = _archives(tmp_path, **kwargs)
    assert not (urls / ".urls.done").exists()
    assert (urls / ".urls.failed").is_file()
    rows = json.loads((tmp_path / "coverage_degraded.json").read_text())
    assert any(row["tool"] == tool for row in rows)
    assert any(row["source"] == "recon.sh" for row in rows)
    assert f"[COVERAGE-GAP] {tool}:" in (tmp_path / "manual_review/coverage_gaps.txt").read_text()
    assert "URL collection incomplete" in result.stdout
    assert (urls / "diagnostics/exit_codes.tsv").is_file()
    assert any(path.read_text() for path in (urls / "diagnostics").glob("*.stderr.log"))
    if tool == "gau":
        assert "primary" in (urls / "gau.txt").read_text()
        assert "fallback" in (urls / "gau.txt").read_text()
        assert "DONE gau:" not in result.stdout


def test_archive_retry_success_removes_failed_marker_and_marks_completion(tmp_path):
    _archives(tmp_path, primary=124, fallback=124)
    _archives(tmp_path, resume=True)
    assert (tmp_path / "urls/.urls.done").is_file()
    assert not (tmp_path / "urls/.urls.failed").exists()


def test_failed_archive_marker_overrides_stale_success_then_clean_resume_skips(tmp_path):
    _archives(tmp_path, primary=124, fallback=124)
    (tmp_path / "urls/.urls.done").write_text("stale completion\n")
    _archives(tmp_path, resume=True)
    assert (tmp_path / "gau.calls").read_text().count("gau call") == 3
    _archives(tmp_path, resume=True)
    assert (tmp_path / "gau.calls").read_text().count("gau call") == 3


def test_legacy_date_only_url_completion_is_retried_once(tmp_path):
    urls = tmp_path / "urls"
    urls.mkdir()
    (urls / ".urls.done").write_text("2026-11-04 10:20:30\n")
    result = _archives(tmp_path, resume=True, empty=True)
    assert "DONE gau: 0 URLs" in result.stdout
    assert (tmp_path / "gau.calls").read_text().count("gau call") == 1
    assert (urls / ".urls.done").read_text().splitlines()[0] == "url_collection_v2"
    assert not (urls / ".urls.failed").exists()
    _archives(tmp_path, resume=True, empty=True)
    assert (tmp_path / "gau.calls").read_text().count("gau call") == 1


def test_gau_fallback_can_recover_primary_failure(tmp_path):
    result = _archives(tmp_path, primary=2, fallback=0)
    assert (tmp_path / "urls/.urls.done").is_file()
    assert not (tmp_path / "coverage_degraded.json").exists()
    assert "DONE gau:" in result.stdout


def test_successful_empty_archives_are_not_a_failure(tmp_path):
    result = _archives(tmp_path, empty=True)
    assert "DONE gau: 0 URLs" in result.stdout
    assert "DONE waybackurls: 0 URLs" in result.stdout
    assert (tmp_path / "urls/.urls.done").is_file()
    assert not (tmp_path / "coverage_degraded.json").exists()


def test_malformed_prior_coverage_is_preserved_with_durable_gap_fallback(tmp_path):
    malformed = '{"partial":\n'
    (tmp_path / "coverage_degraded.json").write_text(malformed)
    _archives(tmp_path, primary=124, fallback=124)
    assert (tmp_path / "coverage_degraded.json").read_text() == malformed
    assert "[COVERAGE-GAP] gau:" in (tmp_path / "manual_review/coverage_gaps.txt").read_text()
    assert not (tmp_path / "urls/.urls.done").exists()


@pytest.mark.parametrize("rc", [0, 7, 124])
def test_katana_failure_is_not_a_clean_zero_result(tmp_path, rc):
    script = _preamble(tmp_path) + r'''
tool_ok() { return 0; }
fake_katana() {
    printf 'crawler diagnostic\n' >&2
    return "$KATANA_RC"
}
'''
    script += KATANA + '\n_finish_url_collection || true\n'
    result = _run(tmp_path, script, KATANA_RC=rc)
    assert (tmp_path / "urls/.urls.done").exists() == (rc == 0)
    assert (tmp_path / "urls/.urls.failed").exists() == (rc != 0)
    if rc:
        assert "DONE katana:" not in result.stdout
        assert any(row["tool"] == "katana" for row in json.loads(
            (tmp_path / "coverage_degraded.json").read_text()))


def _ports(tmp_path, *, nmap_rc=0, naabu_rc=0, naabu=False, resume=False, empty=False):
    script = _preamble(tmp_path, resume=resume) + r'''
tool_ok() {
    case "$1" in
        nmap) return 0 ;;
        naabu) [ "$USE_NAABU" = 1 ] ;;
        *) return 1 ;;
    esac
}
nmap() {
    printf 'nmap call\n' >> "$RECON_DIR/nmap.calls"
    printf '%s\n' "$*" >> "$RECON_DIR/nmap.argv"
    local normal='' grepable=''
    while [ "$#" -gt 0 ]; do
        case "$1" in -oN) normal="$2"; shift 2 ;; -oG) grepable="$2"; shift 2 ;; *) shift ;; esac
    done
    printf '# Nmap partial or complete header\n' > "$normal"
    if [ "$EMPTY_PORTS" = 0 ]; then printf 'Host: example.invalid () Ports: 443/open/tcp//https///\n' > "$grepable"; fi
    printf 'nmap diagnostic\n' >&2
    return "$NMAP_RC"
}
naabu() {
    while [ "$1" != -o ]; do shift; done
    printf 'example.invalid:443\n' > "$2"
    printf 'naabu diagnostic\n' >&2
    return "$NAABU_RC"
}
'''
    script += PORTS + '\nrun_phase5_port_scanning; rc=$?\nprintf "PORT_RC=%s\\n" "$rc"\n'
    return _run(tmp_path, script, NMAP_RC=nmap_rc, NAABU_RC=naabu_rc,
                USE_NAABU=int(naabu), EMPTY_PORTS=int(empty))


def test_failed_nmap_partial_header_is_not_resume_completion(tmp_path):
    first = _ports(tmp_path, nmap_rc=7)
    assert "PORT_RC=1" in first.stdout
    assert not (tmp_path / "ports/.nmap.done").exists()
    assert (tmp_path / "ports/.nmap.failed").is_file()
    assert "partial" in (tmp_path / "ports/nmap_results.txt").read_text()
    second = _ports(tmp_path, resume=True, empty=True)
    assert "PORT_RC=0" in second.stdout
    assert (tmp_path / "nmap.calls").read_text().count("nmap call") == 2
    assert (tmp_path / "ports/.nmap.done").is_file()
    assert not (tmp_path / "ports/.nmap.failed").exists()
    assert list((tmp_path / "ports/diagnostics").glob("nmap_results.txt.previous.*"))
    _ports(tmp_path, resume=True)
    assert (tmp_path / "nmap.calls").read_text().count("nmap call") == 2


def test_legacy_nonempty_nmap_file_is_retried_on_resume(tmp_path):
    ports = tmp_path / "ports"
    ports.mkdir()
    (ports / "nmap_results.txt").write_text("# stale partial header\n")
    _ports(tmp_path, resume=True)
    assert (tmp_path / "nmap.calls").read_text().count("nmap call") == 1


def test_failed_naabu_forces_full_nmap_fallback_and_degrades(tmp_path):
    result = _ports(tmp_path, naabu=True, naabu_rc=7)
    assert "PORT_RC=1" in result.stdout
    assert "--top-ports 1000" in (tmp_path / "nmap.argv").read_text()
    assert "-p 443" not in (tmp_path / "nmap.argv").read_text()
    assert not (tmp_path / "ports/.nmap.done").exists()
    assert any(row["tool"] == "naabu" for row in json.loads(
        (tmp_path / "coverage_degraded.json").read_text()))


def test_successful_zero_port_scan_has_explicit_completion(tmp_path):
    result = _ports(tmp_path, empty=True)
    assert "PORT_RC=0" in result.stdout
    assert "DONE Open ports: 0" in result.stdout
    assert (tmp_path / "ports/.nmap.done").is_file()
    assert not (tmp_path / "coverage_degraded.json").exists()
