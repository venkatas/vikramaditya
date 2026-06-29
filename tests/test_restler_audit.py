#!/usr/bin/env python3
"""Regression tests for restler_audit.py target resolution & token quoting.

Synthetic data only — no real targets/credentials.
"""
import shlex
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import restler_audit as ra  # noqa: E402


# --- _resolve_target: scheme-less must NOT silently no-op (fail closed) ----

def test_resolve_target_schemeless_defaults_https():
    host, port, use_ssl = ra._resolve_target("api.example.invalid/v1")
    assert host == "api.example.invalid"
    assert port == 443
    assert use_ssl is True


def test_resolve_target_explicit_http_no_ssl():
    host, port, use_ssl = ra._resolve_target("http://api.example.invalid:8080/v1")
    assert host == "api.example.invalid"
    assert port == 8080
    assert use_ssl is False


def test_resolve_target_explicit_port_preserved():
    host, port, use_ssl = ra._resolve_target("https://api.example.invalid:9443")
    assert host == "api.example.invalid"
    assert port == 9443
    assert use_ssl is True


@pytest.mark.parametrize("bad", ["", "   ", "https://", "://nohost"])
def test_resolve_target_fails_closed_on_no_host(bad):
    # Must raise rather than yield an empty target_ip (the silent no-op bug).
    with pytest.raises(SystemExit):
        ra._resolve_target(bad)


# --- token interpolation must be shell-safe (shlex.quote) -----------------

def _capture_args(stage):
    """Invoke a stage with _run_restler patched; return the stage_args list."""
    captured = {}

    def fake_run(stage_args, spec_dir, work_dir, timeout):
        captured["args"] = stage_args
        return 0

    with mock.patch.object(ra, "_run_restler", side_effect=fake_run):
        stage(captured)
    return captured["args"]


def test_test_stage_quotes_token_with_single_quote():
    work = Path("/tmp/restler_synth")
    evil = "a'b; touch /tmp/pwned"
    args = _capture_args(
        lambda _c: ra.test_stage(work, "https://api.example.invalid", evil)
    )
    idx = args.index("--token_refresh_cmd")
    cmd = args[idx + 1]
    # The quoted form must round-trip to exactly `echo <token>` with the token
    # preserved as a single argument — no breakout.
    parts = shlex.split(cmd)
    assert parts[0] == "echo"
    assert parts[1] == evil
    assert cmd == f"echo {shlex.quote(evil)}"


def test_fuzz_stage_quotes_token_with_single_quote():
    work = Path("/tmp/restler_synth")
    evil = "x'y$(id)"
    args = _capture_args(
        lambda _c: ra.fuzz_stage(work, "https://api.example.invalid", evil, 0.01)
    )
    idx = args.index("--token_refresh_cmd")
    cmd = args[idx + 1]
    parts = shlex.split(cmd)
    assert parts == ["echo", evil]


def test_no_token_means_no_refresh_cmd():
    work = Path("/tmp/restler_synth")
    args = _capture_args(
        lambda _c: ra.test_stage(work, "https://api.example.invalid", None)
    )
    assert "--token_refresh_cmd" not in args


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
