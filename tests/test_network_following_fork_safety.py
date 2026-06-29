"""Regression guard for the macOS Network.framework fork()+exec SIGSEGV (rc=-11).

These modules call external tools (curl/sqlmap/dalfox/nuclei/trufflehog/prowler/
pmapper/frida/objection/drozer) on code paths that run AFTER in-process network I/O
(`requests`, `urllib`, boto3) has loaded Apple's Network.framework. That framework
registers a NON-fork-safe ``pthread_atfork`` child handler that SIGSEGVs any
``fork()+exec`` child *before* exec on macOS, silently zeroing the phase. The fix is
to launch through ``procutil.run_capture`` (``os.posix_spawn``, which skips atfork
handlers).

This is a grep-style source guard: on the affected paths, a raw ``subprocess.run`` /
``subprocess.Popen`` must NOT reappear, and the module must launch via ``procutil``.
A behavioural fork-safety guard for the launch mechanism itself lives in
tests/test_posix_spawn_fork_safety.py.
"""
import ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

# Modules whose network-following external-tool launches were converted to procutil.
# Each must (a) reference procutil and (b) not regress to raw subprocess on the
# fixed functions.
FIXED_MODULES = [
    REPO / "autopilot_api_hunt.py",
    REPO / "mobile_hunt.py",
    REPO / "whitebox" / "audit" / "prowler_runner.py",
    REPO / "whitebox" / "iam" / "pmapper_runner.py",
]

# (module, function-name) pairs that were converted. The curl/sqlmap/dalfox/nuclei/
# trufflehog/prowler/pmapper/frida/objection/drozer launches all live in these.
# mobile_hunt._post is intentionally EXCLUDED: its lone subprocess.run is the MobSF
# multipart upload, the FIRST network op (before any in-process urlopen), not a
# network-following path.
FIXED_FUNCTIONS = {
    "autopilot_api_hunt.py": {
        "run",                      # AuthBypassScanner.run (curl) + Phase-7 (sqlmap/dalfox/nuclei)
        "_report_js_credentials",   # trufflehog
    },
    "mobile_hunt.py": {
        "frida_pinning_bypass",
        "objection_keychain",
        "drozer_ipc",
    },
    "prowler_runner.py": {"run"},
    "pmapper_runner.py": {"build_graph"},
}


@pytest.mark.parametrize("path", FIXED_MODULES, ids=lambda p: p.name)
def test_module_uses_procutil(path):
    txt = path.read_text(encoding="utf-8")
    assert "procutil" in txt, f"{path.name} no longer references procutil (fork-safe launch lost)"


def _raw_subprocess_calls_in_function(tree: ast.AST, fname: str) -> list[int]:
    """Return line numbers of any subprocess.run / subprocess.Popen (under any alias)
    call inside the named function (recursively across nested defs)."""
    hits = []

    class _V(ast.NodeVisitor):
        def visit_Call(self, node):
            f = node.func
            # match <something>.run(...) / <something>.Popen(...) where the receiver is
            # a bare name (subprocess, _sp, _req_mod's not relevant — we only flag the
            # subprocess attribute access by method name + Name receiver).
            if isinstance(f, ast.Attribute) and f.attr in ("run", "Popen"):
                if isinstance(f.value, ast.Name) and f.value.id in (
                    "subprocess", "_sp", "sp",
                ):
                    hits.append(node.lineno)
            self.generic_visit(node)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == fname:
            _V().visit(node)
    return hits


@pytest.mark.parametrize("path", FIXED_MODULES, ids=lambda p: p.name)
def test_no_raw_subprocess_on_fixed_paths(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    wanted = FIXED_FUNCTIONS[path.name]
    offenders = {}
    for fname in wanted:
        lines = _raw_subprocess_calls_in_function(tree, fname)
        if lines:
            offenders[fname] = lines
    assert not offenders, (
        f"{path.name}: raw subprocess.run/Popen reintroduced on network-following "
        f"path(s) {offenders} — must route through procutil.run_capture (posix_spawn) "
        "to avoid the macOS Network.framework fork()+exec SIGSEGV (rc=-11)."
    )


def test_autopilot_auth_bypass_logs_crashed_child():
    """The auth-bypass curl path must log when the launched child crashes, so a future
    rc=-11 regression is not silent again."""
    txt = (REPO / "autopilot_api_hunt.py").read_text(encoding="utf-8")
    # crude but stable: a warn-log referencing the curl returncode exists.
    assert re.search(r"curl exited rc=", txt), \
        "auth-bypass curl path no longer logs a crashed-child returncode"
