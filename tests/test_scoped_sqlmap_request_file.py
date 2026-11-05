"""Request-file SQLmap and WebForms refresh share the exact-scope boundary."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import re
import shlex
import threading

import pytest

import hunt


TOKENS = ("__VIEWSTATE", "__EVENTVALIDATION", "__VIEWSTATEGENERATOR")
FAILED_DUMP = "unable to retrieve the number of entries\n500 (Internal Server Error)"


@pytest.fixture
def case(tmp_path, monkeypatch):
    recon = tmp_path / "recon" / "target" / "sessions" / "test"
    findings = tmp_path / "findings" / "target" / "sessions" / "test"
    (recon / "scope").mkdir(parents=True)
    findings.mkdir(parents=True)
    req = tmp_path / "request.txt"
    req.write_text("GET /?id=1 HTTP/1.1\nHost: target.example.invalid\n\n")
    allow_file = recon / "scope" / "allow.txt"
    monkeypatch.delenv("SCOPE_ALLOW_FILE", raising=False)
    monkeypatch.delenv("SCOPE_LOCK", raising=False)
    monkeypatch.setattr(hunt, "_brain", None)
    monkeypatch.setattr(hunt, "_resolve_recon_dir", lambda *a, **k: str(recon))
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda *a, **k: str(findings))
    monkeypatch.setattr(hunt, "_which", lambda name: name == "sqlmap")
    logs, gaps = [], []
    monkeypatch.setattr(hunt, "log", lambda *a: logs.append(a))
    monkeypatch.setattr(hunt, "_mark_degraded", lambda *a: gaps.append(a))
    monkeypatch.setattr(hunt, "_brain_phase_complete", lambda *a, **k: None)
    return req, allow_file, findings, logs, gaps


@pytest.mark.parametrize("authority", ["explicit", "persisted", "environment"])
def test_every_request_file_retry_and_column_extract_disables_redirects(case, monkeypatch, authority):
    req, allow_file, _, _, _ = case
    if authority == "persisted":
        allow_file.write_text("target.example.invalid\n")
    elif authority == "environment":
        monkeypatch.setenv("SCOPE_LOCK", "1")
    calls = []
    def fake_run(cmd, **kwargs):
        argv = shlex.split(cmd)
        calls.append(argv)
        return (False, FAILED_DUMP) if "--sql-query" not in argv else (True, "[*] value")
    monkeypatch.setattr(hunt, "run_cmd", fake_run)
    hunt.run_sqlmap_request_file(str(req), domain="target.example.invalid",
        scope_lock=authority == "explicit", extra_flags="--dump -T tbl -C one,two")
    assert len(calls) == 4
    assert all("--ignore-redirects" in argv for argv in calls)
    assert "--fresh-queries" in calls[1]


def test_targeted_extract_infers_authoritative_scope(case, monkeypatch):
    req, allow_file, findings, _, _ = case
    allow_file.write_text("target.example.invalid\n")
    calls = []
    monkeypatch.setattr(hunt, "run_cmd", lambda cmd, **k: calls.append(shlex.split(cmd)) or (True, "[*] value"))
    assert hunt._sqlmap_targeted_extract(str(req), str(findings / "sqlmap_reqfile"), "public", "tbl", ["col"], 1) == {"col": ["value"]}
    assert "--ignore-redirects" in calls[0]


@pytest.mark.parametrize("contents", ["", "outside.invalid\n"])
def test_authoritative_scope_rejects_request_before_tools(case, monkeypatch, contents):
    req, allow_file, findings, _, gaps = case
    allow_file.write_text(contents)
    def forbidden(*a, **k):
        raise AssertionError("sqlmap must not run outside authoritative scope")
    monkeypatch.setattr(hunt, "run_cmd", forbidden)
    assert hunt.run_sqlmap_request_file(str(req), domain="target.example.invalid") is False
    assert hunt._sqlmap_targeted_extract(str(req), str(findings / "sqlmap_reqfile"), "public", "tbl", ["col"], 1) == {}
    assert gaps


@contextmanager
def _server(respond):
    hits = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append((self.path, self.headers.get("Cookie", "")))
            status, headers, body = respond(self.path, len(hits))
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body.encode())
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


def _tokens(value):
    return "".join(f'<input name="{name}" value="{value}">' for name in TOKENS)


def _webforms_request(req, allow_file, url):
    authority = url.removeprefix("http://")
    allow_file.write_text(authority + "\n")
    req.write_text(f"POST {url}/form HTTP/1.1\nHost: {authority}\nCookie: sid=secret\n\n" + "&".join(name + "=stale" for name in TOKENS))
    return authority


def _eval_from_command(command):
    return next(arg.split("=", 1)[1] for arg in shlex.split(command) if arg.startswith("--eval="))


def test_real_webforms_preflight_redirect_is_blocked_before_scan(case, monkeypatch):
    req, allow_file, _, _, gaps = case
    calls = []
    monkeypatch.setattr(hunt, "run_cmd", lambda *a, **k: calls.append(a) or (True, ""))
    with _server(lambda path, n: (200, {}, _tokens("outside"))) as (outside, outside_hits):
        with _server(lambda path, n: (302, {"Location": outside + "/escaped"}, "")) as (inside, inside_hits):
            domain = _webforms_request(req, allow_file, inside)
            assert hunt.run_sqlmap_request_file(str(req), domain=domain) is False
            assert outside_hits == [] and len(inside_hits) == 1
            assert calls == []
            assert any("no stale-token" in reason and "redirect" in reason for _, reason in gaps)


def test_real_stdlib_eval_refreshes_allowed_tokens_and_preserves_cookie(case, monkeypatch):
    req, allow_file, _, _, gaps = case
    refreshed = []
    def run_eval(command, **kwargs):
        code = _eval_from_command(command)
        assert "--ignore-redirects" in shlex.split(command)
        assert "_NoRedirect" in code
        assert "requests" not in code
        values = dict.fromkeys(TOKENS, "stale")
        # sqlmap normalizes semicolon-separated statements before evaluation.
        exec(re.sub(r"\s*;\s*", "\n", code), values)
        refreshed.append([values[name] for name in TOKENS])
        return True, "all tested parameters do not appear to be injectable"
    monkeypatch.setattr(hunt, "run_cmd", run_eval)
    with _server(lambda path, n: (200, {}, _tokens(f"fresh{n}"))) as (inside, hits):
        domain = _webforms_request(req, allow_file, inside)
        assert hunt.run_sqlmap_request_file(str(req), domain=domain) is False
        assert refreshed == [["fresh2"] * 3]
        assert len(hits) == 2 and all(cookie == "sid=secret" for _, cookie in hits)
        assert gaps == []


@pytest.mark.parametrize("refresh_failure", ["redirect", "missing_tokens"])
def test_real_eval_does_not_follow_redirect_or_reuse_stale_tokens(case, monkeypatch, refresh_failure):
    req, allow_file, _, logs, gaps = case
    def run_eval(command, **kwargs):
        try:
            exec(re.sub(r"\s*;\s*", "\n", _eval_from_command(command)), dict.fromkeys(TOKENS, "stale"))
        except Exception as exc:
            return False, f"an error occurred while evaluating provided code ('{exc}')"
        raise AssertionError("refresh must fail rather than scanning stale tokens")
    monkeypatch.setattr(hunt, "run_cmd", run_eval)
    with _server(lambda path, n: (200, {}, _tokens("outside"))) as (outside, outside_hits):
        def respond(path, count):
            if count == 1:
                return 200, {}, _tokens("preflight")
            return (302, {"Location": outside + "/escaped"}, "") if refresh_failure == "redirect" else (200, {}, "no tokens")
        with _server(respond) as (inside, hits):
            domain = _webforms_request(req, allow_file, inside)
            assert hunt.run_sqlmap_request_file(str(req), domain=domain) is False
            assert outside_hits == [] and len(hits) == 2
            assert any("INCONCLUSIVE" in reason for _, reason in gaps)
            assert not any("complete — no injection" in str(entry) for entry in logs)


def test_unsupported_eval_is_inconclusive_not_clean(case, monkeypatch):
    req, allow_file, _, logs, gaps = case
    monkeypatch.setattr(hunt, "run_cmd", lambda *a, **k: (False, "the '--eval' option requires SQLMAP_UNSAFE_EVAL=1"))
    with _server(lambda path, n: (200, {}, _tokens("preflight"))) as (inside, _):
        domain = _webforms_request(req, allow_file, inside)
        assert hunt.run_sqlmap_request_file(str(req), domain=domain) is False
        assert any("INCONCLUSIVE" in reason for _, reason in gaps)
        assert not any("complete — no injection" in str(entry) for entry in logs)


@pytest.mark.parametrize("failed_step", ["retry", "targeted"])
def test_retry_and_targeted_refresh_failures_are_not_hidden_by_first_output(case, monkeypatch, failed_step):
    req, allow_file, _, logs, gaps = case
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        assert "--ignore-redirects" in shlex.split(command)
        assert "_NoRedirect" in _eval_from_command(command)
        if len(calls) == 1:
            return True, FAILED_DUMP
        return False, "an error occurred while evaluating provided code ('HTTP Error 302: Found')"
    monkeypatch.setattr(hunt, "run_cmd", run)
    with _server(lambda path, n: (200, {}, _tokens("preflight"))) as (inside, _):
        domain = _webforms_request(req, allow_file, inside)
        assert hunt.run_sqlmap_request_file(str(req), domain=domain,
            tamper="space2comment" if failed_step == "retry" else "",
            extra_flags="--dump -T tbl -C first,second") is False
        assert len(calls) == 2
        assert any("INCONCLUSIVE" in reason for _, reason in gaps)
        assert not any("complete — no injection" in str(entry) for entry in logs)


def test_exact_scope_refuses_model_escalation_even_when_requested(case, monkeypatch):
    req, allow_file, _, _, gaps = case
    allow_file.write_text("target.example.invalid\n")
    class Brain:
        enabled = True
        def exploit_finding(self, *a, **k):
            raise AssertionError("model-generated network commands bypass exact scope")
    monkeypatch.setattr(hunt, "_brain", Brain())
    monkeypatch.setattr(hunt, "run_cmd", lambda *a, **k: (True, "Parameter: id (GET)\nType: error-based\n"))
    assert hunt.run_sqlmap_request_file(str(req), domain="target.example.invalid", escalate=True) is True
    assert any("model-driven SQLi escalation disabled" in reason for _, reason in gaps)
