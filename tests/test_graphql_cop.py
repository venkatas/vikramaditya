"""graphql-cop wiring in graphql_audit.py — GraphQL DoS/CSRF/info-leak checks.

Output format + severities captured live from graphql-cop against a real
graphql-core server: a JSON list of {result, title, description, impact,
severity(HIGH|MEDIUM|LOW|INFO), color, curl_verify}; only result==True are findings.
"""
import json

import graphql_audit as G

REAL_JSON = json.dumps([
    {"result": True, "title": "Introspection", "description": "Introspection Query Enabled",
     "impact": "Information Leakage", "severity": "HIGH", "color": "red", "curl_verify": "curl -X POST ..."},
    {"result": True, "title": "Field Suggestions", "description": "Field Suggestions are Enabled",
     "impact": "Information Leakage - /graphql", "severity": "LOW", "color": "blue", "curl_verify": "curl ..."},
    {"result": False, "title": "Trace Mode", "description": "x", "impact": "y",
     "severity": "INFO", "color": "blue", "curl_verify": ""},
])


def test_parse_keeps_only_fired_checks():
    f = G.parse_graphql_cop_output(REAL_JSON)
    assert len(f) == 2                                   # Trace Mode (result False) dropped
    sev = {x["title"]: x["severity"] for x in f}
    assert sev["Introspection"] == "high" and sev["Field Suggestions"] == "low"
    assert f[0]["curl_verify"].startswith("curl")


def test_parse_ignores_non_json_noise_line():
    # graphql-cop prints a plain 'does not seem to be running GraphQL' line before the JSON
    noisy = "http://x does not seem to be running GraphQL.\n" + REAL_JSON + "\n"
    assert len(G.parse_graphql_cop_output(noisy)) == 2


def test_parse_empty_and_malformed():
    assert G.parse_graphql_cop_output("") == []
    assert G.parse_graphql_cop_output("not json at all") == []
    assert G.parse_graphql_cop_output("[]") == []        # detected as GraphQL, 0 checks fired


def test_headers_to_gcop_json():
    assert json.loads(G._headers_to_gcop_json(["Authorization: Bearer x", "X-Api: y"])) == {
        "Authorization": "Bearer x", "X-Api": "y"}
    assert G._headers_to_gcop_json([]) is None
    assert G._headers_to_gcop_json(["nocolon"]) is None


def test_run_gates_dos_by_default(tmp_path):
    cap = {}

    def runner(cmd, log_path):
        cap["cmd"] = list(cmd)
        return REAL_JSON
    r = G.run_graphql_cop("http://t/graphql", ["Authorization: Bearer TOK"], tmp_path, runner=runner)
    cmd = cap["cmd"]
    assert "-t" in cmd and "http://t/graphql" in cmd and "json" in cmd
    assert "-H" in cmd and "Bearer TOK" in cmd[cmd.index("-H") + 1]
    assert "-e" in cmd and "alias_overloading" in cmd[cmd.index("-e") + 1]   # DoS gated off
    assert len(r["findings"]) == 2
    assert json.loads((tmp_path / "graphql_cop" / "findings.json").read_text())


def test_run_aggressive_runs_dos(tmp_path):
    cap = {}

    def runner(cmd, log_path):
        cap["cmd"] = list(cmd)
        return "[]"
    G.run_graphql_cop("http://t/graphql", [], tmp_path, aggressive=True, runner=runner)
    assert "-e" not in cap["cmd"]                          # DoS probes NOT excluded
