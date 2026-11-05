"""Scope-locked Nuclei must not delegate redirect authority to templates."""
import ast
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

import cve
import nuclei_dast
import nuclei_scope


REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def clean_scope_environment(monkeypatch):
    monkeypatch.delenv("SCOPE_LOCK", raising=False)
    monkeypatch.delenv("SCOPE_ALLOW_FILE", raising=False)


def persisted_scope(tmp_path):
    scope = tmp_path / "scope" / "allow.txt"
    scope.parent.mkdir(parents=True)
    scope.write_text("")  # even an empty policy must retain redirect locking
    return scope


@pytest.mark.parametrize("mode", ["unlocked", "explicit", "env-lock", "env-file", "persisted"])
def test_shared_guard_detects_all_scope_forms(tmp_path, monkeypatch, mode):
    if mode == "env-lock":
        monkeypatch.setenv("SCOPE_LOCK", "1")
    elif mode == "env-file":
        monkeypatch.setenv("SCOPE_ALLOW_FILE", str(tmp_path / "missing.txt"))
    elif mode == "persisted":
        persisted_scope(tmp_path)
    flags = nuclei_scope.nuclei_scope_flags(tmp_path / "findings" / "nested" / "out.txt",
                                           locked=mode == "explicit")
    assert flags == ([] if mode == "unlocked" else ["-dr"])


@pytest.mark.parametrize("mode", ["unlocked", "shell-local", "env-file", "persisted"])
def test_actual_shell_wrapper_keeps_absolute_pin_and_guard(tmp_path, mode):
    runtime = (REPO / "tool_runtime.sh").read_text()
    wrapper = runtime[runtime.index("nuclei() {"):runtime.index("katana()")]
    binary = tmp_path / "selected-nuclei"
    binary.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
    binary.chmod(0o700)
    recon = tmp_path / "session"
    if mode == "persisted":
        persisted_scope(recon)
    env = dict(os.environ)
    if mode == "env-file":
        env["SCOPE_ALLOW_FILE"] = str(tmp_path / "missing")
    setup = "\n".join(f"{key}={shlex.quote(str(value))}" for key, value in {
        "VIK_NUCLEI_BIN": binary, "VIK_NUCLEI_SCOPE_HELPER": REPO / "nuclei_scope.py",
        "RECON_DIR": recon, "SCOPE_LOCK": "1" if mode == "shell-local" else "0",
    }.items())
    result = subprocess.run(["/bin/bash", "-c", "set -eu\n" + setup + "\n" + wrapper +
                             '\nnuclei -u http://127.0.0.1 -fr -dr=false\n'],
                            env=env, text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    argv = result.stdout.splitlines()
    assert argv[:4] == ["-u", "http://127.0.0.1", "-fr", "-dr=false"]
    assert argv[4:] == ([] if mode == "unlocked" else ["-dr"])


@pytest.mark.parametrize("tree", ["findings", "reports"])
def test_persisted_scope_resolves_split_session_siblings(tmp_path, tree):
    persisted_scope(tmp_path / "recon" / "allowed.invalid" / "sessions" / "id")
    output = tmp_path / tree / "allowed.invalid" / "sessions" / "id" / "dast" / "out.txt"
    assert nuclei_scope.nuclei_scope_flags(output)[-1] == "-dr"


def test_scope_coverage_is_canonical_partial_and_failure_not_findings(tmp_path):
    session = tmp_path / "recon" / "allowed.invalid" / "sessions" / "id"
    persisted_scope(session)
    output = tmp_path / "findings" / "allowed.invalid" / "sessions" / "id" / "nested" / "out.txt"
    nuclei_scope.record_nuclei_coverage(output, exit_code=0)
    nuclei_scope.record_nuclei_coverage(output, exit_code=1)
    nuclei_scope.record_nuclei_coverage(output, exit_code=1)
    marker = output.parent.parent / "coverage_degraded.json"
    entries = json.loads(marker.read_text())
    assert len(entries) == 2
    assert "partial coverage" in entries[0]["reason"]
    assert "exited rc=1" in entries[1]["reason"]
    assert entries[1]["tool"] == "nuclei"
    assert not (output.parent / "coverage_degraded.json").exists()


@pytest.mark.parametrize("original", [b"{malformed evidence\n", b'{"existing":"wrong-shape"}\n',
                                       b'["wrong entry shape"]\n'])
def test_recorder_preserves_invalid_evidence_and_uses_reporter_fallback(tmp_path, original):
    from phase_manifest import collect_coverage
    persisted_scope(tmp_path)
    marker = tmp_path / "coverage_degraded.json"
    marker.write_bytes(original)
    nuclei_scope.record_nuclei_coverage(tmp_path, exit_code=1)
    assert marker.read_bytes() == original
    gap = (tmp_path / "manual_review" / "coverage_gaps.txt").read_text()
    assert "[COVERAGE-GAP] nuclei:" in gap and "exited rc=1" in gap
    assert any(item["tool_or_phase"] == "nuclei" and "exited rc=1" in item["reason"]
               for item in collect_coverage(str(tmp_path)))


def test_recorder_preserves_read_failed_evidence(tmp_path, monkeypatch):
    persisted_scope(tmp_path)
    marker = tmp_path / "coverage_degraded.json"
    original = b'[{"tool":"original","reason":"prior evidence"}]\n'
    marker.write_bytes(original)
    real_read = Path.read_text

    def denied(path, *args, **kwargs):
        if path == marker:
            raise PermissionError("fixture denies metadata read")
        return real_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", denied)
    nuclei_scope.record_nuclei_coverage(tmp_path, exit_code=1)
    assert marker.read_bytes() == original
    assert "exited rc=1" in (tmp_path / "manual_review" / "coverage_gaps.txt").read_text()


def test_concurrent_normal_and_failed_recorders_preserve_all_gaps(tmp_path):
    persisted_scope(tmp_path)
    marker = tmp_path / "coverage_degraded.json"
    original = {"tool": "original", "reason": "prior evidence"}
    marker.write_text(json.dumps([original]))
    codes = [0, *range(1, 25)] * 2
    with ThreadPoolExecutor(max_workers=12) as pool:
        list(pool.map(lambda code: nuclei_scope.record_nuclei_coverage(tmp_path, exit_code=code), codes))
    entries = json.loads(marker.read_text())
    assert original in entries and len(entries) == 26
    assert sum("partial coverage" in item["reason"] for item in entries) == 1
    for code in range(1, 25):
        assert any(f"exited rc={code};" in item["reason"] for item in entries)
    assert not list(tmp_path.glob(".coverage_degraded.*"))


def test_actual_shell_wrapper_preserves_failure_and_records_gap(tmp_path):
    runtime = (REPO / "tool_runtime.sh").read_text()
    wrapper = runtime[runtime.index("nuclei() {"):runtime.index("katana()")]
    binary = tmp_path / "failing-nuclei"
    binary.write_text("#!/bin/sh\nexit 1\n")
    binary.chmod(0o700)
    session = tmp_path / "recon" / "allowed.invalid" / "sessions" / "id"
    persisted_scope(session)
    setup = "\n".join(f"{key}={shlex.quote(str(value))}" for key, value in {
        "VIK_NUCLEI_BIN": binary, "VIK_NUCLEI_SCOPE_HELPER": REPO / "nuclei_scope.py",
        "RECON_DIR": session, "SCOPE_LOCK": "1",
    }.items())
    result = subprocess.run(["/bin/bash", "-c", "set -u\n" + setup + "\n" + wrapper +
                             '\nnuclei -u http://127.0.0.1\n'],
                            text=True, capture_output=True, timeout=10)
    assert result.returncode == 1 and "coverage is incomplete" in result.stderr
    marker = tmp_path / "findings" / "allowed.invalid" / "sessions" / "id" / "coverage_degraded.json"
    assert "exited rc=1" in json.loads(marker.read_text())[0]["reason"]


@pytest.mark.parametrize("locked", [False, True])
def test_cve_actual_command_propagates_persisted_scope(tmp_path, monkeypatch, locked):
    if locked:
        persisted_scope(tmp_path)
    captured = []
    monkeypatch.setattr(cve, "run_cmd", lambda command, **kwargs: (captured.append(command) or (True, "")))
    cve.run_nuclei_cve_scan("allowed.invalid", str(tmp_path), str(tmp_path / "findings" / "nuclei.txt"))
    scan = next(command for command in captured if "nuclei -tags" in command)
    assert ("-dr" in shlex.split(scan)) == locked


@pytest.mark.parametrize("locked", [False, True])
def test_dast_retains_scope_after_temp_input_copy(tmp_path, monkeypatch, locked):
    original = tmp_path / "session" / "urls" / "with_params.txt"
    original.parent.mkdir(parents=True)
    original.write_text("https://allowed.invalid/?a=1\n")
    if locked:
        persisted_scope(tmp_path / "session")
    monkeypatch.setattr(nuclei_dast, "find_binary", lambda explicit=None: "/selected/nuclei")
    commands = []

    def runner(argv, timeout):
        commands.append(argv)
        return {"stdout": "Nuclei Engine Version: v3.8.0", "returncode": 0}

    result = nuclei_dast.run(str(original), str(tmp_path / "separate-output"),
                             "allowed.invalid", runner=runner)
    assert result["ran"]
    scan = next(argv for argv in commands if "-dast" in argv)
    assert ("-dr" in scan) == locked
    assert scan[0] == "/selected/nuclei"


@pytest.mark.parametrize("locked", [False, True])
def test_hunt_absolute_nuclei_call_expressions_all_include_guard(tmp_path, locked):
    tree = ast.parse((REPO / "hunt.py").read_text())
    seen = 0
    for function in tree.body:
        if not isinstance(function, ast.FunctionDef) or function.name not in ("run_cms_exploit", "run_rce_scan"):
            continue
        assert "nuclei_scope_flags(recon_dir)" in ast.unparse(function)
        for call in ast.walk(function):
            if not isinstance(call, ast.Call) or not call.args or not isinstance(call.args[0], ast.JoinedStr):
                continue
            expression = call.args[0]
            if not any(isinstance(n, ast.Name) and n.id == "nuclei_bin" for n in ast.walk(expression)):
                continue
            names = {n.id: "local-test" for n in ast.walk(expression) if isinstance(n, ast.Name)}
            names.update(nuclei_bin="/selected/nuclei", nuclei_guard=" -dr" if locked else "")
            command = eval(compile(ast.Expression(expression), "<actual-nuclei-call>", "eval"), names)
            assert ("-dr" in shlex.split(command)) == locked
            assert command.startswith("/selected/nuclei ")
            seen += 1
    assert seen == 4


@pytest.mark.parametrize("filename", ["autopilot_api_hunt.py", "vikramaditya.py"])
@pytest.mark.parametrize("locked", [False, True])
def test_direct_python_argv_expressions_propagate_scope_flags(filename, locked):
    tree = ast.parse((REPO / filename).read_text())
    expressions = [node.args[0] for node in ast.walk(tree) if isinstance(node, ast.Call)
                   and node.args and isinstance(node.args[0], ast.BinOp)
                   and any(isinstance(part, ast.Name) and part.id == "_nuclei_scope_flags"
                           for part in ast.walk(node.args[0]))]
    assert len(expressions) == 1
    expression = expressions[0]
    names = {node.id: "local-test" for node in ast.walk(expression) if isinstance(node, ast.Name)}
    names.update(os=os, urls_file=SimpleNamespace(name="input.txt"),
                 _nuclei_bin="/selected/nuclei", _nuclei_scope_flags=["-dr"] if locked else [])
    argv = eval(compile(ast.Expression(expression), "<actual-nuclei-argv>", "eval"), names)
    assert ("-dr" in argv) == locked


def test_standalone_shell_nuclei_commands_both_include_guard():
    source = (REPO / "scripts/full_hunt.sh").read_text()
    assert '"$TOOLS_DIR/nuclei_scope.py" --shell-flags "$OUT"' in source
    invocations = source.split('nuclei -u "$TARGETURL"')[1:]
    assert len(invocations) == 2
    assert all("$NUCLEI_SCOPE_FLAGS" in invocation.split("2>/dev/null", 1)[0]
               for invocation in invocations)


def test_standalone_shell_helper_failure_never_launches_nuclei(tmp_path):
    source = (REPO / "scripts/full_hunt.sh").read_text()
    block = source[source.index('if [ "$(check_tool nuclei)"'):source.index('# ── XSS scan')]
    calls = tmp_path / "called"
    setup = "\n".join(f"{key}={shlex.quote(str(value))}" for key, value in {
        "TOKEN": "", "TOOLS_DIR": tmp_path / "missing-helper", "OUT": tmp_path,
        "TARGETURL": "http://127.0.0.1", "CALLS": calls, "QUICK": "false",
    }.items())
    body = ('set -e\n' + setup + '\ncheck_tool() { echo true; }; log() { :; }; ok() { :; }; warn() { :; }\n'
            + 'nuclei() { echo UNGUARDED >> "$CALLS"; }\n' + block)
    result = subprocess.run(["/bin/bash", "-c", body], text=True, capture_output=True, timeout=10)
    assert result.returncode != 0 and not calls.exists()


def test_native_nuclei_dr_overrides_template_and_follow_configuration(tmp_path):
    """No remote targets, update checks, HTTP probing, or OAST are permitted."""
    binary = shutil.which("nuclei")
    if not binary:
        pytest.skip("installed Nuclei required for native redirect precedence check")
    running = []

    def start(routes):
        hits = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                self.send_response(302 if self.path in routes else 200)
                if self.path in routes:
                    self.send_header("Location", routes[self.path])
                self.end_headers()
                self.wfile.write(b"local-control-ok")

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        thread.start()
        running.append((server, thread))
        return server, hits

    sink, sink_hits = start({})
    routes = {}
    origin, origin_hits = start(routes)
    origin_url = f"http://127.0.0.1:{origin.server_port}"
    routes.update({"/port": f"http://127.0.0.1:{sink.server_port}/denied-port",
                   "/alias": f"http://localhost:{origin.server_port}/denied-alias",
                   "/userinfo": f"http://user:pass@127.0.0.1:{origin.server_port}/userinfo-final",
                   "/same": "/same-authority-final"})
    template = tmp_path / "redirect.yaml"
    template.write_text("""id: local-scope-redirect-test
info:
  name: Local redirect precedence control
  author: local
  severity: info
http:
  - method: GET
    path:
      - '{{BaseURL}}'
    redirects: true
    matchers:
      - type: word
        words:
          - local-control-ok
""")
    config = tmp_path / "nuclei-config.yaml"
    config.write_text("follow-redirects: true\n")
    inputs = tmp_path / "targets.txt"
    inputs.write_text("\n".join(origin_url + path for path in ("/port", "/alias", "/userinfo", "/same", "/direct")) + "\n")
    base = [binary, "-t", str(template), "-l", str(inputs), "-config", str(config),
            "-duc", "-ni", "-nh", "-no-stdin", "-retries", "0", "-timeout", "2",
            "-c", "1", "-bs", "1", "-rl", "10", "-dc", "-silent", "-nc"]
    try:
        guard = nuclei_scope.nuclei_scope_flags(locked=True)
        conflict = subprocess.run(base + guard, text=True,
                                  capture_output=True, timeout=30)
        assert conflict.returncode != 0
        assert "both follow redirects and disable redirects" in conflict.stderr
        assert origin_hits == [] and sink_hits == []
        config.write_text("{}\n")
        cli_conflict = subprocess.run(base + ["-fr"] + guard, text=True,
                                      capture_output=True, timeout=30)
        assert cli_conflict.returncode != 0 and origin_hits == [] and sink_hits == []
        locked = subprocess.run(base + ["-dr=false"] + guard, text=True,
                                capture_output=True, timeout=30)
        assert locked.returncode == 0, locked.stderr
        assert sink_hits == []
        assert "/denied-alias" not in origin_hits and "/same-authority-final" not in origin_hits
        assert "/userinfo-final" not in origin_hits
        assert "/direct" in origin_hits and "local-scope-redirect-test" in locked.stdout
        origin_hits.clear()
        # This control proves the template really exercises redirects when the
        # guard is absent, rather than merely loading a no-redirect request.
        unlocked = subprocess.run(base, text=True, capture_output=True, timeout=30)
        assert unlocked.returncode == 0, unlocked.stderr
        assert "/denied-port" in sink_hits and "/denied-alias" in origin_hits
        assert "/same-authority-final" in origin_hits
        sink_hits.clear()
        origin_hits.clear()
        same_host = subprocess.run(base + ["-fhr"], text=True, capture_output=True, timeout=30)
        assert same_host.returncode == 0, same_host.stderr
        # Retain the observed comparison in pytest output under -rP without
        # assuming same-host is an exact-authority scope control.
        print("native -fhr destinations:", json.dumps({"sink": sink_hits, "origin": origin_hits}))
    finally:
        for server, thread in running:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
