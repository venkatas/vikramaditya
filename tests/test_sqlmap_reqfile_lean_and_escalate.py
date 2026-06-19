"""run_sqlmap_request_file gates two behaviours surfaced on a live engagement:

1. --sqlmap-lean SKIPS the heavy `--dbs --tables` enumeration so a targeted `--sql-query`/`--dump`
   makes only the few requests it needs — heavy re-enumeration every call is what tripped a
   target's edge rate-limiting (421 Misdirected Request storms) and broke blind extraction.
2. The autonomous SQLi→RCE brain loop (model-generated `--os-shell` / `--file-write` webshell at
   the LIVE target) is OPT-IN only (escalate=True) — never auto-run on a confirmation pass.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import hunt  # noqa: E402


def _req(tmp_path):
    f = tmp_path / "req.txt"
    f.write_text("GET /api/x?id=1 HTTP/1.1\nHost: t.example.invalid\n\n")
    return str(f)


def _patch_common(monkeypatch, tmp_path, cmds):
    monkeypatch.setattr(hunt, "_which", lambda *a, **k: "/usr/bin/sqlmap")
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda *a, **k: str(tmp_path))
    monkeypatch.setattr(hunt, "_brain", None)            # no brain -> no escalation/narration
    monkeypatch.setattr(hunt, "run_cmd",
                        lambda cmd, *a, **k: (cmds.append(cmd), (False, "no injection"))[1])


def test_lean_skips_dbs_tables_enumeration(monkeypatch, tmp_path):
    cmds = []
    _patch_common(monkeypatch, tmp_path, cmds)
    hunt.run_sqlmap_request_file(_req(tmp_path), domain="t.example.invalid",
                                 extra_flags='--sql-query "SELECT 1"', lean=True)
    assert cmds, "sqlmap was not invoked"
    assert "--dbs --tables" not in cmds[0]               # lean: no heavy enumeration
    assert "--sql-query" in cmds[0]


def test_non_lean_keeps_dbs_tables(monkeypatch, tmp_path):
    cmds = []
    _patch_common(monkeypatch, tmp_path, cmds)
    hunt.run_sqlmap_request_file(_req(tmp_path), domain="t.example.invalid", lean=False)
    assert "--dbs --tables" in cmds[0]


class _Brain:
    enabled = True

    def __init__(self):
        self.calls = []

    def exploit_finding(self, *a, **k):
        self.calls.append((a, k))


def _patch_confirmed(monkeypatch, tmp_path, brain):
    monkeypatch.setattr(hunt, "_which", lambda *a, **k: "/usr/bin/sqlmap")
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda *a, **k: str(tmp_path))
    monkeypatch.setattr(hunt, "run_cmd", lambda cmd, *a, **k: (True, "injectable"))
    monkeypatch.setattr(hunt, "_parse_sqlmap_confirmation",
                        lambda out: {"confirmed": True, "dbms": "MySQL", "types": ["error-based"],
                                     "params": ["id"], "tables": [], "payloads": []})
    monkeypatch.setattr(hunt, "_sqlmap_dump_failed", lambda out: False)
    monkeypatch.setattr(hunt, "_brain_phase_complete", lambda *a, **k: None)
    monkeypatch.setattr(hunt, "_sqlmap_evidence_block", lambda conf: "evidence")
    monkeypatch.setattr(hunt, "_sqli_rce_hints", lambda *a, **k: "hints")
    monkeypatch.setattr(hunt, "_brain", brain)


def test_rce_escalation_off_by_default(monkeypatch, tmp_path):
    brain = _Brain()
    _patch_confirmed(monkeypatch, tmp_path, brain)
    hunt.run_sqlmap_request_file(_req(tmp_path), domain="t.example.invalid", escalate=False)
    assert brain.calls == []                             # os-shell/file-write loop NOT run


def test_rce_escalation_runs_when_opted_in(monkeypatch, tmp_path):
    brain = _Brain()
    _patch_confirmed(monkeypatch, tmp_path, brain)
    hunt.run_sqlmap_request_file(_req(tmp_path), domain="t.example.invalid", escalate=True)
    assert len(brain.calls) == 1                         # escalation ran exactly once
