"""nuclei_dast — the DAST fuzzing pass + its version guard, scope lock, and the
reporter ingestion of its output.
"""
import os

import nuclei_dast as nd


# ── version parsing / guards ─────────────────────────────────────────────────
def test_parse_version():
    assert nd.parse_version("[INF] Nuclei Engine Version: v3.7.1") == (3, 7, 1)
    assert nd.parse_version("v3.10.0") == (3, 10, 0)
    assert nd.parse_version("garbage") is None


def test_dast_support_and_cve_guard():
    assert nd.supports_dast((3, 7, 1)) is True
    assert nd.supports_dast((3, 0, 0)) is False
    assert nd.supports_dast(None) is False
    # 3.7.1 supports -dast but is BELOW the CVE-safe 3.8.0 line
    assert nd.cve_safe((3, 7, 1)) is False
    assert nd.cve_safe((3, 8, 0)) is True
    assert nd.cve_safe((3, 10, 0)) is True
    assert nd.cve_safe(None) is False


# ── scope lock ───────────────────────────────────────────────────────────────
def test_scope_regex_in_and_out_of_scope():
    import re
    rx = re.compile(nd.scope_regex("example.com"))
    assert rx.search("https://example.com/a")
    assert rx.search("http://api.example.com/b?x=1")
    assert not rx.search("https://evil.com/c")
    assert not rx.search("https://notexample.com/d")   # suffix-attack guard
    assert not rx.search("https://example.com.evil.net/e")


# ── command construction ─────────────────────────────────────────────────────
def test_build_cmd_defaults_no_oast():
    argv = nd.build_cmd("/b/nuclei", "in.txt", "out.txt", "example.com")
    assert "-dast" in argv and "-ni" in argv           # OAST off by default (no exfil)
    assert argv[argv.index("-fa") + 1] == "low"
    assert "-cs" in argv and "-iserver" not in argv
    assert argv[argv.index("-o") + 1] == "out.txt"


def test_build_cmd_with_self_hosted_oast():
    argv = nd.build_cmd("/b/nuclei", "in.txt", "out.txt", "example.com",
                        oob_server="https://oob.mine", oob_token="t")
    assert "-iserver" in argv and "https://oob.mine" in argv
    assert "-itoken" in argv and "-ni" not in argv     # OAST enabled → no -ni


def test_build_cmd_openapi_input_mode():
    argv = nd.build_cmd("/b/nuclei", "spec.json", "out.txt", "example.com",
                        input_mode="openapi")
    assert argv[argv.index("-im") + 1] == "openapi"


def test_build_cmd_retries_default_one():
    # -retries 1 (not 0) so nuclei re-confirms — reduces timing/network FPs
    argv = nd.build_cmd("/b/nuclei", "in.txt", "out.txt", "example.com")
    assert argv[argv.index("-retries") + 1] == "1"


def test_find_binary_prefers_path(monkeypatch, tmp_path):
    path_bin = tmp_path / "path_nuclei"
    path_bin.write_text("#!/bin/sh\n"); path_bin.chmod(0o755)
    monkeypatch.setattr(nd.shutil, "which", lambda n: str(path_bin))
    assert nd.find_binary() == str(path_bin)   # PATH wins over ~/go/bin


# ── run orchestration (injected runner, no real binary) ──────────────────────
def test_run_skips_without_binary(tmp_path, monkeypatch):
    monkeypatch.setattr(nd, "find_binary", lambda explicit=None: None)
    inp = tmp_path / "with_params.txt"; inp.write_text("https://example.com/?a=1\n")
    res = nd.run(str(inp), str(tmp_path / "dast"), "example.com")
    assert res["ran"] is False and "not installed" in res["reason"]


def test_run_skips_empty_input(tmp_path, monkeypatch):
    monkeypatch.setattr(nd, "find_binary", lambda explicit=None: "/bin/true")
    inp = tmp_path / "with_params.txt"; inp.write_text("")
    res = nd.run(str(inp), str(tmp_path / "dast"), "example.com")
    assert res["ran"] is False and "no param URLs" in res["reason"]


def test_run_skips_when_version_too_old(tmp_path, monkeypatch):
    monkeypatch.setattr(nd, "find_binary", lambda explicit=None: "/bin/true")
    inp = tmp_path / "with_params.txt"; inp.write_text("https://example.com/?a=1\n")

    def old_runner(argv, timeout):
        return {"stdout": "Nuclei Engine Version: v3.0.0", "stderr": "", "returncode": 0}
    res = nd.run(str(inp), str(tmp_path / "dast"), "example.com", runner=old_runner)
    assert res["ran"] is False and "lacks -dast" in res["reason"]


def test_host_in_scope():
    assert nd.host_in_scope("https://example.com/a", "example.com")
    assert nd.host_in_scope("https://api.example.com/b?x=1", "example.com")
    assert not nd.host_in_scope("https://evil.com/c", "example.com")
    assert not nd.host_in_scope("https://notexample.com/d", "example.com")
    assert not nd.host_in_scope("https://example.com.evil.net/e", "example.com")


def test_run_drops_off_scope_urls(tmp_path, monkeypatch):
    monkeypatch.setattr(nd, "find_binary", lambda explicit=None: "/bin/true")
    inp = tmp_path / "with_params.txt"
    inp.write_text("https://example.com/?a=1\nhttps://evil.com/?b=2\nhttps://api.example.com/?c=3\n")
    seen = {}

    def runner(argv, timeout):
        if "-version" in argv:
            return {"stdout": "v3.10.0", "stderr": "", "returncode": 0}
        seen["urls"] = [x.strip() for x in open(argv[argv.index("-l") + 1]) if x.strip()]
        return {"stdout": "", "stderr": "", "returncode": 0}
    res = nd.run(str(inp), str(tmp_path / "dast"), "example.com", runner=runner)
    assert res["urls_total"] == 2                              # evil.com dropped in Python
    assert not any("evil.com" in u for u in seen["urls"])       # nuclei never sees it
    assert all("example.com" in u for u in seen["urls"])


def test_run_skips_cidr(tmp_path):
    res = nd.run("x", str(tmp_path / "dast"), "192.168.1.0/24")
    assert res["ran"] is False and "CIDR" in res["reason"]


def test_run_caps_large_input(tmp_path, monkeypatch):
    monkeypatch.setattr(nd, "find_binary", lambda explicit=None: "/bin/true")
    inp = tmp_path / "with_params.txt"
    inp.write_text("\n".join(f"https://example.com/?a={i}" for i in range(20)) + "\n")
    seen = {}

    def runner(argv, timeout):
        if "-version" in argv:
            return {"stdout": "v3.10.0", "stderr": "", "returncode": 0}
        li = argv[argv.index("-l") + 1]
        seen["lines"] = sum(1 for _ in open(li))
        return {"stdout": "", "stderr": "", "returncode": 0}
    res = nd.run(str(inp), str(tmp_path / "dast"), "example.com", max_urls=5, runner=runner)
    assert res["capped"] is True and res["urls_scanned"] == 5 and res["urls_total"] == 20
    assert seen["lines"] == 5   # nuclei got the capped file


def test_run_surfaces_timeout(tmp_path, monkeypatch):
    monkeypatch.setattr(nd, "find_binary", lambda explicit=None: "/bin/true")
    inp = tmp_path / "with_params.txt"; inp.write_text("https://example.com/?a=1\n")

    def runner(argv, timeout):
        if "-version" in argv:
            return {"stdout": "v3.10.0", "stderr": "", "returncode": 0}
        return {"stdout": "", "stderr": "", "returncode": -9, "timed_out": True}
    res = nd.run(str(inp), str(tmp_path / "dast"), "example.com", runner=runner)
    assert res["ran"] is True and res["timed_out"] is True and res["returncode"] == -9


def test_run_counts_findings_and_flags_cve(tmp_path, monkeypatch):
    monkeypatch.setattr(nd, "find_binary", lambda explicit=None: "/bin/true")
    inp = tmp_path / "with_params.txt"; inp.write_text("https://example.com/?a=1\n")
    out_dir = tmp_path / "dast"

    def runner(argv, timeout):
        if "-version" in argv:
            return {"stdout": "Nuclei Engine Version: v3.7.1", "stderr": "", "returncode": 0}
        # emulate nuclei writing 2 findings to the -o path
        out = argv[argv.index("-o") + 1]
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w") as f:
            f.write("[reflected-xss] [http] [medium] https://example.com/?a=1\n")
            f.write("[open-redirect] [http] [low] https://example.com/?next=1\n")
        return {"stdout": "", "stderr": "", "returncode": 0}
    res = nd.run(str(inp), str(out_dir), "example.com", runner=runner)
    assert res["ran"] and res["findings"] == 2
    assert res["cve_warn"] is True            # 3.7.1 < 3.8.0
    assert os.path.isfile(res["out_file"])


# ── reporter ingestion of dast/ ──────────────────────────────────────────────
def test_reporter_ingests_dast_findings(tmp_path):
    import reporter
    fdir = tmp_path / "findings"
    (fdir / "dast").mkdir(parents=True)
    (fdir / "dast" / "nuclei_dast.txt").write_text(
        "[reflected-xss] [http] [high] https://example.com/?q=1\n"
        "[crlf-injection] [http] [medium] https://example.com/?redir=2\n"
    )
    findings = reporter.load_findings(str(fdir))
    dast = [f for f in findings if "DAST fuzzing match" in f.get("title", "")]
    assert len(dast) == 2
    sev = {f["title"].split(": ", 1)[1]: f["severity"] for f in dast}
    d = {f["title"].split(": ", 1)[1]: f["detail"] for f in dast}
    # single-request DAST matches are capped to <=medium + a verify caveat (anti-fab)
    assert sev["reflected-xss"] == "medium" and sev["crlf-injection"] == "medium"
    assert "verify with dalfox/sqlmap" in d["reflected-xss"]


def test_reporter_dast_sets_cvss_by_severity(tmp_path):
    import reporter
    fdir = tmp_path / "findings"
    (fdir / "dast").mkdir(parents=True)
    (fdir / "dast" / "nuclei_dast.txt").write_text(
        "[open-redirect] [http] [low] https://example.com/?next=1\n")
    findings = reporter.load_findings(str(fdir))
    f = next(x for x in findings if "open-redirect" in x.get("title", ""))
    # low DAST finding must NOT inherit the nuclei_finding CVSS-7.5 default
    assert f["severity"] == "low" and f["cvss"] == "2.5"


def test_reporter_dast_timing_capped_to_candidate(tmp_path):
    import reporter
    fdir = tmp_path / "findings"
    (fdir / "dast").mkdir(parents=True)
    (fdir / "dast" / "nuclei_dast.txt").write_text(
        "[time-based-sqli] [http] [critical] https://example.com/?id=1\n")
    findings = reporter.load_findings(str(fdir))
    f = next(x for x in findings if "time-based-sqli" in x.get("title", ""))
    assert f["severity"] == "medium"                 # capped down from critical
    assert "UNCONFIRMED timing" in f["detail"]
