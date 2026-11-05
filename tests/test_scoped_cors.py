"""The generated CORS checker must not follow out-of-scope redirects."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import shlex
import subprocess
import threading

import pytest

import hunt


@contextmanager
def _server(respond):
    hits = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            origin = self.headers.get("Origin", "")
            hits.append((self.path, origin))
            status, headers = respond(self.path, origin)
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", hits
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


@pytest.fixture
def cors_case(tmp_path, monkeypatch):
    recon = tmp_path / "session's files"
    (recon / "live").mkdir(parents=True)
    (recon / "scope").mkdir()
    live_file = recon / "live" / "urls.txt"
    allow_file = recon / "scope" / "allow.txt"
    monkeypatch.delenv("SCOPE_ALLOW_FILE", raising=False)
    monkeypatch.delenv("SCOPE_LOCK", raising=False)
    monkeypatch.setattr(hunt, "_brain", None)
    monkeypatch.setattr(hunt, "_resolve_recon_dir", lambda *a, **k: str(recon))
    monkeypatch.setattr(hunt, "CORS_MAX_URLS", 0)
    logs, gaps, phases = [], [], []
    monkeypatch.setattr(hunt, "log", lambda *a: logs.append(a))
    monkeypatch.setattr(hunt, "_mark_degraded", lambda *a: gaps.append(a))
    monkeypatch.setattr(hunt, "_brain_phase_complete", lambda *a, **k: phases.append((a, k)))
    def run_generated(command, **kwargs):
        env = dict(os.environ, PYTHONPATH="", PYTHONDONTWRITEBYTECODE="1")
        # Deliberately run outside the repo. The session script must insert
        # the absolute repository path before importing the shared guard.
        result = subprocess.run(shlex.split(command), cwd=tmp_path, env=env,
                                capture_output=True, text=True, timeout=15)
        return result.returncode == 0, result.stdout + result.stderr
    monkeypatch.setattr(hunt, "run_cmd", run_generated)
    return recon, live_file, allow_file, logs, gaps, phases


def test_real_locked_cors_blocks_initial_and_redirect_destinations_but_keeps_headers(cors_case):
    recon, live_file, allow_file, logs, gaps, phases = cors_case
    with _server(lambda path, origin: (200, {"Access-Control-Allow-Origin": origin})) as (outside, outside_hits):
        def respond(path, origin):
            if path == "/escape":
                return 302, {"Location": outside + "/escaped"}
            if path == "/redirect":
                return 302, {"Location": "/reflect"}
            if path == "/wild-public":
                return 200, {"Access-Control-Allow-Origin": "*"}
            if path == "/wild-creds":
                return 200, {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}
            if path == "/no-reflect":
                return 200, {"Access-Control-Allow-Origin": "https://trusted.invalid"}
            return 200, {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "TrUe"}
        with _server(respond) as (inside, inside_hits):
            allow_file.write_text(inside.removeprefix("http://") + "\n")
            live_file.write_text("\n".join(inside + path for path in (
                "/reflect", "/wild-public", "/wild-creds", "/no-reflect", "/redirect", "/escape",
            )) + "\n" + outside + "/poisoned-seed\n")

            assert hunt.run_cors_check("engagement.invalid") is False

            assert outside_hits == []
            assert len(inside_hits) == 28  # 7 allowed requests per Origin, including redirect.
            findings = (recon / "cors" / "cors_findings.txt").read_text().splitlines()
            assert len(findings) == 16
            assert sum("sev=HIGH" in line for line in findings) == 8
            assert sum("sev=MEDIUM" in line for line in findings) == 4
            assert sum(line.startswith("CORS-INFO") for line in findings) == 4
            assert not any("escape" in line or "poisoned" in line for line in findings)
            coverage = json.loads((recon / "cors" / "scope_coverage.json").read_text())
            assert coverage["tested"] == 20
            assert len(coverage["blocked"]) == 8
            assert coverage["errors"] == []
            assert gaps and phases[-1][0] == ("CORS CHECK", False)
            assert not any("No misconfigurations found" in str(entry) for entry in logs)


def test_locked_cors_allowed_control_completes(cors_case):
    recon, live_file, allow_file, _, gaps, phases = cors_case
    with _server(lambda path, origin: (200, {
        "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true",
    })) as (inside, hits):
        allow_file.write_text(inside.removeprefix("http://") + "\n")
        live_file.write_text(inside + "/reflect\n")
        assert hunt.run_cors_check("engagement.invalid") is True
        assert len(hits) == 4
        assert len((recon / "cors" / "cors_findings.txt").read_text().splitlines()) == 4
        assert gaps == []
        assert phases[-1][0] == ("CORS CHECK", True)


def test_authoritative_allowlist_is_reloaded_before_each_origin(cors_case):
    recon, live_file, allow_file, _, gaps, _ = cors_case
    def respond(path, origin):
        allow_file.write_text("")
        return 200, {"Access-Control-Allow-Origin": origin}
    with _server(respond) as (inside, hits):
        allow_file.write_text(inside.removeprefix("http://") + "\n")
        live_file.write_text(inside + "/reflect\n")
        assert hunt.run_cors_check("engagement.invalid") is False
        assert len(hits) == 1
        coverage = json.loads((recon / "cors" / "scope_coverage.json").read_text())
        assert coverage["tested"] == 1
        assert len(coverage["blocked"]) == 3
        assert gaps


@pytest.mark.parametrize("missing", [False, True])
def test_missing_or_empty_authoritative_scope_stops_before_launch(cors_case, monkeypatch, missing):
    _, live_file, allow_file, _, gaps, _ = cors_case
    live_file.write_text("https://engagement.invalid/\n")
    if missing:
        monkeypatch.setenv("SCOPE_ALLOW_FILE", str(allow_file))
    else:
        allow_file.write_text("")
    def forbidden(*a, **k):
        raise AssertionError("CORS script launched without a usable exact allowlist")
    monkeypatch.setattr(hunt, "run_cmd", forbidden)
    assert hunt.run_cors_check("engagement.invalid") is False
    assert any("missing or empty" in reason for _, reason in gaps)


def test_nonlocked_cors_retains_legacy_redirect_behavior(cors_case):
    recon, live_file, _, _, gaps, _ = cors_case
    with _server(lambda path, origin: (200, {
        "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true",
    })) as (destination, destination_hits):
        with _server(lambda path, origin: (302, {"Location": destination + "/allowed-by-legacy"})) as (source, source_hits):
            live_file.write_text(source + "/redirect\n")
            assert hunt.run_cors_check("engagement.invalid") is True
            assert len(source_hits) == len(destination_hits) == 4
            assert len((recon / "cors" / "cors_findings.txt").read_text().splitlines()) == 4
            assert gaps == []
            assert not (recon / "cors" / "scope_coverage.json").exists()
