"""garak REST wiring in llm_hunt.py — the fix for the non-functional LLM engine.

The old run_garak passed a GARAK_REST_AUTH env garak ignores + no generator config,
so it could not authenticate or match a real chat schema. These tests lock the fix:
a real RestGenerator options file (auth via REST_API_KEY, NEVER on the CLI/in the
file) + a report parser keyed on garak v0.15.x's real eval format (captured live).
"""
import json

import llm_hunt as L


def test_split_auth_header():
    assert L._split_auth_header("Authorization: Bearer tok") == ("Authorization", "$KEY", "Bearer tok")
    assert L._split_auth_header("X-Api-Key: abc") == ("X-Api-Key", "$KEY", "abc")
    assert L._split_auth_header("") == (None, None, None)
    assert L._split_auth_header("nocolon") == (None, None, None)


def test_garak_rest_options_no_secret_in_file():
    opts, key = L.garak_rest_options(
        "https://api.x/chat", "Authorization: Bearer SECRET",
        req_field="message", resp_field="$.choices[0].message.content", method="post")
    rg = opts["rest"]["RestGenerator"]
    assert rg["uri"] == "https://api.x/chat" and rg["method"] == "post"
    assert rg["headers"]["Authorization"] == "$KEY"        # placeholder, not the token
    assert "SECRET" not in json.dumps(opts)                # NO secret in the options file
    assert key == "Bearer SECRET"                          # token supplied via REST_API_KEY env
    assert rg["req_template_json_object"] == {"message": "$INPUT"}
    assert rg["response_json_field"] == "$.choices[0].message.content"


def test_garak_rest_options_no_auth():
    opts, key = L.garak_rest_options("https://api.x/chat", "")
    assert key is None
    assert "Authorization" not in opts["rest"]["RestGenerator"]["headers"]


def test_parse_garak_report_real_eval_format(tmp_path):
    # eval entry shape captured live from garak v0.15.1 (total_evaluated + fails, NOT "total")
    rpt = tmp_path / "r.report.jsonl"
    rpt.write_text(
        '{"entry_type":"init"}\n'
        '{"entry_type":"eval","probe":"latentinjection.LatentJailbreak","detector":"x.Y",'
        '"passed":3,"fails":2,"nones":0,"total_evaluated":5,"total_processed":5}\n'
        '{"entry_type":"eval","probe":"safe.Probe","detector":"x.Z",'
        '"passed":5,"fails":0,"total_evaluated":5,"total_processed":5}\n'
        'not json\n'
    )
    f = L.parse_garak_report(str(rpt))
    assert len(f) == 1                                     # only the eval with fails>0
    assert f[0]["probe"] == "latentinjection.LatentJailbreak"
    assert f[0]["failed"] == 2 and f[0]["total"] == 5
    assert f[0]["severity"] == "medium"                    # 2/5 = 0.4 -> medium


def test_parse_garak_report_severity_scale(tmp_path):
    rpt = tmp_path / "r.report.jsonl"
    rpt.write_text(
        '{"entry_type":"eval","probe":"p.hi","detector":"d","passed":0,"fails":5,"total_evaluated":5}\n'
        '{"entry_type":"eval","probe":"p.lo","detector":"d","passed":19,"fails":1,"total_evaluated":20}\n'
    )
    sev = {x["probe"]: x["severity"] for x in L.parse_garak_report(str(rpt))}
    assert sev["p.hi"] == "high" and sev["p.lo"] == "low"  # 100% -> high, 5% -> low


def test_run_garak_no_secret_on_cli(tmp_path):
    captured = {}

    def fake_runner(cmd, log_path, env=None, timeout=1800):
        captured["cmd"] = list(cmd)
        captured["env"] = env or {}
        return 0
    L.run_garak("https://api.x/chat", "Authorization: Bearer TOPSECRET", "test.Blank",
                tmp_path, runner=fake_runner)
    cmd = captured["cmd"]
    assert "TOPSECRET" not in " ".join(cmd)                # token NEVER on the command line
    assert "-G" in cmd and cmd[cmd.index("-G") + 1].endswith("rest_options.json")
    assert "--model_type" in cmd and cmd[cmd.index("--model_type") + 1] == "rest"
    assert captured["env"].get("REST_API_KEY") == "Bearer TOPSECRET"
    assert "TOPSECRET" not in (tmp_path / "garak" / "rest_options.json").read_text()
