"""Wrong gf binaries and failed patterns must never manufacture URL matches."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

import pytest

import tool_resolution as tr


REPO = Path(__file__).resolve().parent.parent
GF_HELP = "Usage of gf:\n  -dump\n    print pattern command\n  -list\n    list patterns\n  -save\n    save pattern\n"


def _binary(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(0o700)
    return str(path)


def _gf(path, *, patterns=("sqli",), body="/bin/cat", list_rc=0, list_stderr=""):
    listed = "".join(name + "\n" for name in patterns)
    return _binary(path, f"""case "$1" in
    -h) printf '%s' {shlex.quote(GF_HELP)} >&2; exit 0 ;;
    -list) printf '%s' {shlex.quote(listed)}; printf '%s' {shlex.quote(list_stderr)} >&2; exit {list_rc} ;;
    *) {body} ;;
esac""")


@pytest.fixture(autouse=True)
def _reset_cache():
    tr._cached_check.cache_clear()
    yield
    tr._cached_check.cache_clear()


def _match(tmp_path, binary, *, urls=None, patterns=("sqli",), allow=None):
    source = tmp_path / "input URLs.txt"
    source.write_text("".join(url + "\n" for url in (urls or ["https://target.test/?id=1"])))
    output = tmp_path / "results"
    coverage = tmp_path / "coverage_degraded.json"
    summary = tr.match_gf(source, output, coverage_file=coverage, allow_file=allow,
                          patterns=patterns, candidates=[binary] if binary else [])
    return summary, output, coverage


def test_goframe_is_not_tomnomnom_gf_even_with_exit_zero(tmp_path):
    wrong = _binary(tmp_path / "gf", 'echo "USAGE gf COMMAND; GoFrame CLI Tool v2.10.3"; exit 0')
    selected, reason = tr.resolve("gf", candidates=[wrong])
    assert selected is None
    assert "not tomnomnom gf" in reason and "GoFrame" in reason


def test_goframe_does_not_shadow_later_gf_and_help_on_stderr_accepted(tmp_path, monkeypatch):
    wrong_dir = tmp_path / "wrong"
    right_dir = tmp_path / "right"
    _binary(wrong_dir / "gf", 'echo "GoFrame CLI"')
    right = _gf(right_dir / "gf")
    monkeypatch.setattr(tr, "BREW_PREFIXES", ())
    assert tr.resolve("gf", env={"PATH": os.pathsep.join((str(wrong_dir), str(right_dir)))},
                      gobin=str(tmp_path / "absent")) == (right, None)


def test_explicit_gf_pin_is_used_before_other_candidates(tmp_path, monkeypatch):
    chosen = _gf(tmp_path / "my gf")
    monkeypatch.setattr(tr, "BREW_PREFIXES", ())
    assert tr.resolve("gf", env={"PATH": "", "VIK_GF_BIN": chosen},
                      gobin=str(tmp_path / "absent"))[0] == chosen


def test_success_only_counts_validated_input_urls_once(tmp_path):
    url = "https://target.test/?id=1"
    binary = _gf(tmp_path / "tools with spaces/gf", body=f"/bin/cat; printf '%s\\n' {shlex.quote(url)}")
    summary, output, coverage = _match(tmp_path, binary, urls=[url, url])
    assert summary["counts"] == {"sqli": 1}
    assert summary["coverage_gaps"] == [] and not coverage.exists()
    assert (output / "sqli.txt").read_text() == url + "\n"
    assert (output / "diagnostics/sqli.json").exists()


def test_known_pattern_rc_one_empty_is_normal_no_match(tmp_path):
    binary = _gf(tmp_path / "gf", body="exit 1")
    summary, output, coverage = _match(tmp_path, binary)
    assert summary["counts"] == {"sqli": 0}
    assert not summary["coverage_gaps"] and not coverage.exists()
    assert (output / "sqli.txt").read_text() == ""


@pytest.mark.parametrize("body", [
    'echo \'command "sqli" not found in GoFrame\'; echo "stack trace"; exit 0',
    '/bin/cat; echo "grep: invalid regular expression" >&2; exit 0',
    '/bin/cat; exit 139',
    '/bin/cat; exit 1',
    'echo "https://external.test/?id=1"; exit 0',
    'echo "1:https://target.test/?id=1"; exit 0',
    'echo "id=1"; exit 0',
])
def test_errors_partial_failures_and_non_url_output_are_not_hits(tmp_path, body):
    binary = _gf(tmp_path / "gf", body=body)
    summary, output, coverage = _match(tmp_path, binary)
    assert summary["counts"] == {"sqli": 0}
    assert (output / "sqli.txt").read_text() == ""
    assert summary["coverage_gaps"] and json.loads(coverage.read_text())[0]["tool"] == "gf"
    raw = json.loads((output / "diagnostics/sqli.json").read_text())
    assert raw["stdout"] or raw["stderr"]


def test_missing_tool_is_coverage_gap_not_silent_skip(tmp_path):
    summary, output, coverage = _match(tmp_path, None)
    assert summary["counts"] == {"sqli": 0}
    assert "not installed" in summary["coverage_gaps"][0]
    assert (output / "sqli.txt").read_text() == ""
    assert coverage.exists()


def test_wrong_tool_cannot_run_pattern_and_is_coverage_gap(tmp_path):
    marker = tmp_path / "pattern executed"
    wrong = _binary(tmp_path / "gf", f'echo "GoFrame CLI"; [ "$1" = "sqli" ] && /usr/bin/touch {shlex.quote(str(marker))}; exit 0')
    summary, output, _ = _match(tmp_path, wrong)
    assert not marker.exists()
    assert summary["counts"]["sqli"] == 0 and summary["coverage_gaps"]
    assert (output / "sqli.txt").read_text() == ""


def test_missing_patterns_are_gaps_but_unrelated_custom_names_are_allowed(tmp_path):
    binary = _gf(tmp_path / "gf", patterns=("sqli", "custom pattern", "日本語"))
    summary, output, coverage = _match(tmp_path, binary, patterns=("sqli", "xss"))
    assert summary["counts"] == {"sqli": 1, "xss": 0}
    assert summary["coverage_gaps"] == ["gf[xss] pattern is not installed"]
    assert (output / "xss.txt").read_text() == ""
    assert len(json.loads(coverage.read_text())) == 1


def test_empty_list_is_missing_patterns_not_wrong_identity(tmp_path):
    binary = _gf(tmp_path / "gf", patterns=())
    assert tr.resolve("gf", candidates=[binary])[0] == binary
    summary, _, _ = _match(tmp_path, binary)
    assert summary["coverage_gaps"] == ["gf[sqli] pattern is not installed"]


@pytest.mark.parametrize("list_rc,list_stderr", [(2, ""), (0, "cannot read patterns")])
def test_pattern_listing_failure_is_coverage_gap(tmp_path, list_rc, list_stderr):
    binary = _gf(tmp_path / "gf", list_rc=list_rc, list_stderr=list_stderr)
    summary, output, _ = _match(tmp_path, binary)
    assert summary["counts"] == {"sqli": 0}
    assert "pattern list failed" in summary["coverage_gaps"][0]
    assert not (output / "diagnostics/sqli.json").exists()


def test_input_scope_and_url_validation_precedes_pattern_stdin(tmp_path):
    binary = _gf(tmp_path / "gf")
    allow = tmp_path / "allow.txt"
    allow.write_text("target.test\n")
    good = "https://target.test/?id=1"
    summary, output, _ = _match(tmp_path, binary, allow=str(allow), urls=[
        good, "https://external.test/?id=1", "not a URL", "file:///tmp/id=1",
        "https://user:pass@target.test/?id=1", "https://target.test:99999/", "https://target.test\\@external.test/",
    ])
    assert summary["counts"] == {"sqli": 1}
    assert len(summary["coverage_gaps"]) == 1
    assert (output / "diagnostics/input_urls.txt").read_text() == good + "\n"
    assert (output / "sqli.txt").read_text() == good + "\n"


@pytest.mark.parametrize("allow_content", [None, ""])
def test_missing_or_empty_scope_fails_closed(tmp_path, allow_content):
    binary = _gf(tmp_path / "gf")
    allow = tmp_path / "allow.txt"
    if allow_content is not None:
        allow.write_text(allow_content)
    summary, output, _ = _match(tmp_path, binary, allow=str(allow))
    assert summary["counts"] == {"sqli": 0}
    assert "scope allowlist" in summary["coverage_gaps"][0]
    assert not (output / "diagnostics/sqli.json").exists()


def test_timed_out_pattern_cannot_leave_partial_matches(tmp_path, monkeypatch):
    binary = _gf(tmp_path / "gf")
    original = tr._gf_capture

    def capture(argv, **kwargs):
        if argv[-1] == "sqli":
            return {"stdout": "https://target.test/?id=1\n", "stderr": "", "returncode": -9, "timed_out": True}
        return original(argv, **kwargs)

    monkeypatch.setattr(tr, "_gf_capture", capture)
    summary, output, _ = _match(tmp_path, binary)
    assert summary["counts"]["sqli"] == 0
    assert (output / "sqli.txt").read_text() == "" and summary["coverage_gaps"]


def test_coverage_preserves_unrelated_markers_and_deduplicates(tmp_path):
    coverage = tmp_path / "coverage.json"
    previous = {"tool": "browser", "reason": "blocked redirect"}
    coverage.write_text(json.dumps([previous]))
    tr._gf_coverage(coverage, ["missing pattern", "missing pattern"])
    tr._gf_coverage(coverage, ["missing pattern"])
    entries = json.loads(coverage.read_text())
    assert entries == [previous, {"tool": "gf", "phase": "recon", "reason": "missing pattern"}]


@pytest.mark.parametrize("scope_lock", ["0", "1"])
def test_cli_and_real_recon_block_execute_pinned_gf_locally(tmp_path, scope_lock):
    # Execute only the extracted GF block, not recon's active networking phases.
    binary = _gf(tmp_path / "custom tools/gf", patterns=tr.GF_PATTERNS)
    recon_dir = tmp_path / "session"
    (recon_dir / "urls").mkdir(parents=True)
    (recon_dir / "urls/all.txt").write_text("https://target.test/?id=1\n")
    allow = tmp_path / "allow.txt"
    allow.write_text("target.test\n")
    source = (REPO / "recon.sh").read_text()
    block = source.split("# gf — pattern-match", 1)[1].split("# Gxss —", 1)[0]
    block = block[block.index("\n"):]
    # Use the same interpreter as the tests, independent of host PATH aliases.
    prelude = f"""set -u
python3() {{ {shlex.quote(sys.executable)} "$@"; }}
log_step() {{ :; }}
log_warn() {{ printf '%s\\n' "$*"; }}
RECON_DIR={shlex.quote(str(recon_dir))}
SCRIPT_DIR={shlex.quote(str(REPO))}
SCOPE_LOCK={scope_lock}
SCOPE_ALLOW_FILE={shlex.quote(str(allow))}
"""
    result = subprocess.run(["/bin/bash", "-c", prelude + block], capture_output=True, text=True,
                            env={**os.environ, "VIK_GF_BIN": binary}, timeout=30)
    assert result.returncode == 0, result.stderr
    assert "gf[sqli]: 1 validated input URLs" in result.stdout
    assert "Coverage gap:" not in result.stderr
    assert (recon_dir / "urls/gf/sqli.txt").read_text() == "https://target.test/?id=1\n"
    assert not (recon_dir / "coverage_degraded.json").exists()
