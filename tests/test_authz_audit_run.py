"""authz_audit_run — live runner writes findings/<target>/authz/findings.json."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import authz_audit_run


def test_run_writes_reporter_findings_json(tmp_path):
    admin = {"/AdminQueue": (200, "<h1>Queue</h1><table>x</table>")}
    low = lambda p: admin.get(p, (404, "", ""))
    unauth = lambda p: (302, "", "/login")
    path, fs = authz_audit_run.run(
        "https://app.invalid", low, unauth_get=unauth,
        admin_paths=["/AdminQueue"], out_root=str(tmp_path))
    assert os.path.exists(path)
    assert os.path.join("app.invalid", "authz", "findings.json") in path
    rows = json.load(open(path))
    assert rows and rows[0]["source"] == "authz_audit" and rows[0]["type"] == "auth_bypass"


def test_run_empty_writes_empty_list(tmp_path):
    path, fs = authz_audit_run.run(
        "host.invalid", lambda p: (403, "", ""), unauth_get=lambda p: (302, "", "/login"),
        admin_paths=["/Admin"], out_root=str(tmp_path))
    assert json.load(open(path)) == []
