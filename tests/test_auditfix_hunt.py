"""Regression tests for hunt.py audit fixes (v9.24).

Covers the pure-Python helpers introduced/changed by the clientd.com
end-to-end audit:

  1. GitHound config/auth error detection (masked-failure fix)
  3. sqlmap candidate hygiene — FUZZ→1 substitution, .axd denylist,
     reachability preflight, db-named host seeding
  4. tri-state phase status mapping
  5. tool readiness layer
  6. structured finding count (vs raw file count)
  + coverage.json integration contract with the reporter
"""

import json
import os

import hunt


# ── Issue 1: GitHound config/auth error detection ─────────────────────────────
def test_githound_error_detected_for_missing_config():
    assert hunt._githound_output_is_error("[!] config.yml was not found.")
    assert hunt._githound_output_is_error("ERROR: no GitHub tokens configured")
    assert hunt._githound_output_is_error("rate limit exceeded")


def test_githound_real_results_not_flagged_as_error():
    real = "https://github.com/acme/repo/blob/main/.env\nAWS_SECRET=AKIA...\n"
    assert not hunt._githound_output_is_error(real)
    assert not hunt._githound_output_is_error("")  # empty != error


# ── Issue 3a: FUZZ placeholder substitution ───────────────────────────────────
def test_substitute_fuzz_placeholders_basic():
    assert (hunt._substitute_fuzz_placeholders("https://x/a?d=FUZZ&t=FUZZ")
            == "https://x/a?d=1&t=1")


def test_substitute_fuzz_placeholders_case_insensitive():
    assert hunt._substitute_fuzz_placeholders("https://x/a?p=fuzz") == "https://x/a?p=1"


def test_substitute_fuzz_placeholders_noop_when_clean():
    url = "https://x/a?id=42&name=bob"
    assert hunt._substitute_fuzz_placeholders(url) == url


# ── Issue 3c: .axd resource-handler denylist ──────────────────────────────────
def test_denylist_drops_webresource_and_scriptresource():
    assert hunt._is_denylisted_sqlmap_candidate(
        "https://x/WebResource.axd?d=abc&t=123")
    assert hunt._is_denylisted_sqlmap_candidate(
        "https://x/ScriptResource.axd?d=abc")
    assert not hunt._is_denylisted_sqlmap_candidate("https://x/api/users?id=1")


def test_sanitize_candidates_combines_filters():
    raw = [
        "https://x/WebResource.axd?d=FUZZ&t=FUZZ",   # denylisted -> dropped
        "https://x/ScriptResource.axd?d=abc",        # denylisted -> dropped
        "https://x/api?d=FUZZ&t=FUZZ",               # FUZZ -> 1
        "https://x/api?id=5",                        # kept verbatim
        "https://x/api?id=5",                        # dedup
    ]
    out = hunt._sanitize_sqlmap_candidates(raw)
    assert out == ["https://x/api?d=1&t=1", "https://x/api?id=5"]


def test_sanitize_drops_unresolvable_placeholder():
    # A token that survives substitution attempts (none of our tokens map) — the
    # ``{{`` placeholder substitutes to 1 so this is kept; verify a residual
    # placeholder URL with an unhandled token shape is dropped.
    raw = ["https://x/api?q={{secret}}"]
    out = hunt._sanitize_sqlmap_candidates(raw)
    # {{ and }} both substitute to 1 -> ?q=1secret1, no residual placeholder.
    assert out == ["https://x/api?q=1secret1"]


# ── Issue 3a: reachability preflight (mocked) ─────────────────────────────────
def test_filter_reachable_candidates(monkeypatch):
    alive = {"https://up/a", "https://up/b"}
    monkeypatch.setattr(hunt, "_url_reachable", lambda u, timeout=8: u in alive)
    cands = ["https://up/a", "https://dead/x", "https://up/b", "https://dead/y"]
    reachable, dead = hunt._filter_reachable_candidates(cands)
    assert reachable == ["https://up/a", "https://up/b"]
    assert dead == 2


def test_filter_reachable_all_dead(monkeypatch):
    monkeypatch.setattr(hunt, "_url_reachable", lambda u, timeout=8: False)
    reachable, dead = hunt._filter_reachable_candidates(["https://x/a", "https://x/b"])
    assert reachable == []
    assert dead == 2


# ── Issue 8: db-named host seeding ────────────────────────────────────────────
def test_is_db_named_host_matches_db_labels():
    assert hunt._is_db_named_host("https://mysql-prod.example.com/")
    assert hunt._is_db_named_host("https://db.example.com")
    assert hunt._is_db_named_host("postgres.internal.example.com")
    assert hunt._is_db_named_host("https://mssql01.corp:1433/")


def test_is_db_named_host_no_false_positive_on_substring():
    # "feedback" contains "db" as a substring but not as a label — must not match.
    assert not hunt._is_db_named_host("https://feedback.example.com/")
    assert not hunt._is_db_named_host("https://www.example.com/")


def test_collect_db_named_candidates(tmp_path):
    live_dir = tmp_path / "live"
    live_dir.mkdir()
    (live_dir / "urls.txt").write_text(
        "https://www.example.com/\n"
        "https://db.example.com/\n"
        "https://mysql-prod.example.com/login\n"
        "https://feedback.example.com/\n"
    )
    out = hunt._collect_db_named_candidates(str(tmp_path))
    # Exact-equality membership (out is a list of full URLs) — avoids the
    # imprecise URL-substring check CodeQL flags (py/incomplete-url-substring-sanitization).
    assert any(u == "https://db.example.com/" for u in out)
    assert any(u == "https://mysql-prod.example.com/login" for u in out)
    assert all(u != "https://www.example.com/" for u in out)
    assert all(u != "https://feedback.example.com/" for u in out)


# ── Issue 4: tri-state phase status mapping ───────────────────────────────────
def test_derive_phase_status_not_requested():
    assert (hunt.derive_phase_status(requested=False, ran_truthy=True)
            == hunt.PHASE_STATUS_SKIPPED)


def test_derive_phase_status_ran():
    assert (hunt.derive_phase_status(requested=True, ran_truthy=True, degraded=False)
            == hunt.PHASE_STATUS_RAN)


def test_derive_phase_status_skipped_when_falsy():
    assert (hunt.derive_phase_status(requested=True, ran_truthy=False)
            == hunt.PHASE_STATUS_SKIPPED)


def test_derive_phase_status_error_when_degraded():
    # Degraded wins even if the run_* helper returned truthy on a skip path.
    assert (hunt.derive_phase_status(requested=True, ran_truthy=True, degraded=True)
            == hunt.PHASE_STATUS_ERROR)


def test_phase_status_glyphs():
    assert hunt.phase_status_glyph(hunt.PHASE_STATUS_RAN) == "✓"
    assert hunt.phase_status_glyph(hunt.PHASE_STATUS_SKIPPED) == "∅"
    assert hunt.phase_status_glyph(hunt.PHASE_STATUS_ERROR) == "✗"


# ── Issue 5: tool readiness layer ─────────────────────────────────────────────
def test_check_tool_readiness_flags_unconfigured_githound(tmp_path, monkeypatch):
    # No config.yml anywhere, no wordlists -> all three present tools flagged.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(hunt, "HOME", str(tmp_path))
    monkeypatch.setattr(hunt, "WORDLIST_DIR", str(tmp_path / "wordlists"))
    gaps = hunt.check_tool_readiness(["git-hound", "kiterunner", "jwt_tool"])
    tools = {g["tool"] for g in gaps}
    assert "git-hound" in tools
    assert "kiterunner" in tools
    assert "jwt_tool" in tools


def test_check_tool_readiness_satisfied_when_config_present(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(hunt, "HOME", str(tmp_path))
    wl = tmp_path / "wordlists"
    wl.mkdir()
    (tmp_path / "config.yml").write_text("github_access_tokens: [abc]\n")
    (wl / "api-endpoints.txt").write_text("/api\n")
    (wl / "jwt-secrets.txt").write_text("secret\n")
    monkeypatch.setattr(hunt, "WORDLIST_DIR", str(wl))
    gaps = hunt.check_tool_readiness(["git-hound", "kiterunner", "jwt_tool"])
    assert gaps == []


def test_check_tool_readiness_ignores_absent_tools(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(hunt, "HOME", str(tmp_path))
    monkeypatch.setattr(hunt, "WORDLIST_DIR", str(tmp_path / "wordlists"))
    # git-hound NOT in the installed list -> not flagged.
    gaps = hunt.check_tool_readiness(["nmap", "sqlmap"])
    assert gaps == []


# ── Degraded accumulator + coverage.json contract ─────────────────────────────
def test_mark_degraded_dedupes_and_coverage_json(tmp_path):
    hunt._reset_degraded()
    hunt._mark_degraded("git-hound", "no config.yml")
    hunt._mark_degraded("git-hound", "no config.yml")  # dup -> ignored
    hunt._mark_degraded("sqlmap", "all candidates unreachable")
    out = hunt.write_coverage_json(str(tmp_path))
    assert out is not None and os.path.isfile(out)
    data = json.load(open(out))
    assert data == [
        {"tool": "git-hound", "reason": "no config.yml"},
        {"tool": "sqlmap", "reason": "all candidates unreachable"},
    ]
    hunt._reset_degraded()


def test_coverage_json_written_empty(tmp_path):
    hunt._reset_degraded()
    out = hunt.write_coverage_json(str(tmp_path))
    assert out is not None and os.path.isfile(out)
    assert json.load(open(out)) == []


# ── Issue 6: structured finding count vs raw file count ───────────────────────
def test_structured_finding_count_excludes_noise(tmp_path):
    fdir = tmp_path / "findings"
    fdir.mkdir()
    # Empty file -> 0
    (fdir / "candidates.txt").write_text("")
    # Banner/comment lines only -> 0
    (fdir / "log.txt").write_text("# header\n=========\n-- separator --\n")
    # 3 real text findings
    (fdir / "sqli.txt").write_text("INJ https://x?id=1\nINJ https://x?id=2\nINJ https://x?id=3\n")
    # JSON list of 2
    (fdir / "xss.json").write_text(json.dumps([{"a": 1}, {"b": 2}]))
    # JSON dict with findings key (count = 4)
    (fdir / "wrap.json").write_text(json.dumps({"findings": [1, 2, 3, 4]}))

    structured = hunt._structured_finding_count(str(fdir))
    raw = hunt._dir_file_count(str(fdir))
    assert raw == 5            # five files on disk
    assert structured == 9     # 0 + 0 + 3 + 2 + 4 real findings
    assert structured != raw   # the whole point: structured != raw file count
