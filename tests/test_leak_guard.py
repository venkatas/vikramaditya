"""The automated leak-guard: block client names everywhere + real secrets in non-test files,
without false-positiving on fake secret-shaped fixtures (this codebase IS a secret scanner, so
its docs/tests legitimately contain example secrets).

NOTE: this test uses SYNTHETIC names only — a test for the guard must not embed real client data.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import leak_guard  # noqa: E402

TERMS = ["acmebank", "foowidget", "zorpmail"]   # synthetic stand-ins for the real blocklist


def test_fake_akia_fixture_in_test_file_is_allowed():
    changes = [("tests/test_cred.py", 'assert c.access_key_id == "AKIAEXAMPLE000000001"')]
    assert leak_guard._scan(changes, TERMS) == []


def test_real_shaped_akia_in_source_file_is_blocked():
    changes = [("hunt.py", 'key = "AKIA1234567890QRSTUV"')]   # 16 chars, no fixture marker
    assert any(w == "AWS access key" for w, _ in leak_guard._scan(changes, TERMS))


def test_client_name_blocked_even_in_test_file():
    changes = [("tests/test_x.py", 'url = "https://acmebank.example/login"')]
    assert any(w == "acmebank" for w, _ in leak_guard._scan(changes, TERMS))


def test_aws_example_key_is_allowlisted():
    changes = [("docs/payloads.md", "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")]
    assert leak_guard._scan(changes, TERMS) == []


def test_real_private_key_in_source_is_blocked():
    changes = [("config.py", "-----BEGIN RSA PRIVATE KEY-----")]
    assert any(w == "private key" for w, _ in leak_guard._scan(changes, TERMS))


def test_placeholder_private_key_fixture_is_allowed():
    # a one-line string-literal fixture with escaped \n + ABCD body is not a real key
    changes = [("docs/plan.md", 'txt = "-----BEGIN RSA PRIVATE KEY-----\\nABCD\\n-----END RSA PRIVATE KEY-----"')]
    assert leak_guard._scan(changes, TERMS) == []


def test_is_test_path():
    assert leak_guard._is_test_path("tests/test_foo.py")
    assert leak_guard._is_test_path("a/b/test_bar.py")
    assert not leak_guard._is_test_path("hunt.py")
    assert not leak_guard._is_test_path("scripts/leak_guard.py")


# ── DO-NOW hardening: filename matching + fail-closed ────────────────────────

def test_client_name_in_filename_blocked():
    # content is clean, but the client identifier is in the FILE NAME (the real-client *.sql dump vector)
    changes = [("engagements/acmebank_dump.sql", "id,name")]
    hits = leak_guard._scan(changes, TERMS)
    assert any(w == "acmebank" and "filename" in line for w, line in hits)


def test_filename_match_via_extra_paths():
    # a binary/renamed file with no added text lines still caught via extra_paths
    hits = leak_guard._scan([], TERMS, extra_paths=["data/zorpmail_backup.bak"])
    assert any(w == "zorpmail" for w, _ in hits)


def test_clean_filename_and_content_not_flagged():
    assert leak_guard._scan([("hunt.py", "x = 1")], TERMS) == []


def test_fail_closed_on_empty_blocklist(monkeypatch):
    monkeypatch.setattr(leak_guard, "_load_blocklist", lambda: [])
    monkeypatch.delenv("LEAK_GUARD_ALLOW_NO_BLOCKLIST", raising=False)
    monkeypatch.setattr(sys, "argv", ["leak_guard.py", "--staged"])
    assert leak_guard.main() == 2          # blocks, does NOT silently pass


def test_empty_blocklist_override_allows(monkeypatch):
    monkeypatch.setattr(leak_guard, "_load_blocklist", lambda: [])
    monkeypatch.setenv("LEAK_GUARD_ALLOW_NO_BLOCKLIST", "1")
    monkeypatch.setattr(leak_guard, "_added_changes", lambda a: [])
    monkeypatch.setattr(leak_guard, "_changed_paths", lambda a: [])
    monkeypatch.setattr(sys, "argv", ["leak_guard.py", "--staged"])
    assert leak_guard.main() == 0


def test_fails_closed_on_internal_error(monkeypatch):
    monkeypatch.setattr(leak_guard, "_load_blocklist", lambda: ["acmebank"])
    def boom(*a, **k):
        raise RuntimeError("git exploded")
    monkeypatch.setattr(leak_guard, "_added_changes", boom)
    monkeypatch.setattr(sys, "argv", ["leak_guard.py", "--staged"])
    assert leak_guard.main() == 2          # internal error -> fail closed, not exit 0


# ── Red-team gap fixes (HARD secrets split as "AKIA"+... so THIS test file never trips the guard
#    it tests — the guard now blocks marker-less HARD secrets even on a test path) ──────────────

_AK = "AKIA"          # split prefix: keeps a contiguous real-shaped key out of the source bytes


def test_marker_adjacent_aws_key_is_blocked():
    # GAP 1: a real-shaped key on a line that ALSO contains a fixture WORD must still block
    changes = [("config.py", 'KEY = "' + _AK + '1234567890QRSTUV"  # example default')]
    assert any(w == "AWS access key" for w, _ in leak_guard._scan(changes, TERMS))


def test_marker_inside_token_still_allowed():
    # suppression is now scoped to the token: AKIAEXAMPLE… stays a fixture
    changes = [("config.py", 'KEY = "' + _AK + 'EXAMPLE000000001"  # default')]
    assert leak_guard._scan(changes, TERMS) == []


def test_real_akia_in_test_file_now_blocked():
    # GAP 4: HARD secrets are no longer skipped on a test path (a real key in a fixture leaks)
    changes = [("tests/test_x.py", 'k = "' + _AK + '1234567890QRSTUV"')]
    assert any(w == "AWS access key" for w, _ in leak_guard._scan(changes, TERMS))


def test_github_token_blocked():
    assert any(w == "GitHub token"
               for w, _ in leak_guard._scan([("app.py", 'gh = "ghp_' + "a" * 36 + '"')], TERMS))


def test_slack_token_blocked():
    line = 'sl = "xoxb-' + "1" * 12 + '-zzzz"'
    assert any(w == "Slack token" for w, _ in leak_guard._scan([("app.py", line)], TERMS))


def test_google_api_key_blocked():
    assert any(w == "Google API key"
               for w, _ in leak_guard._scan([("app.py", 'g = "AIza' + "b" * 35 + '"')], TERMS))


def test_jwt_in_source_is_blocked():
    jwt = "eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 10
    assert any("JWT" in w for w, _ in leak_guard._scan([("svc.py", f'auth = "{jwt}"')], TERMS))


def test_jwt_in_test_file_is_allowed():
    # SOFT patterns stay lenient on test paths (fixture JWTs are common there)
    jwt = "eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 10
    assert leak_guard._scan([("tests/test_auth.py", f'auth = "{jwt}"')], TERMS) == []


def test_hardcoded_password_blocked():
    assert any(w == "hardcoded password"
               for w, _ in leak_guard._scan([("svc.py", 'password = "S3cr3tP@ssword"')], TERMS))


def test_password_with_marker_allowed():
    assert leak_guard._scan([("svc.py", 'password = "your_password_here"')], TERMS) == []


def test_basic_auth_url_blocked():
    line = 'u = "https://admin:Hunter2Password@10.0.0.5/api"'
    assert any(w == "basic-auth URL" for w, _ in leak_guard._scan([("svc.py", line)], TERMS))


def test_separator_variant_client_name_blocked():
    # GAP 5: 'acme-bank' / spaced variants of the >=5-char term 'acmebank' caught via normalization
    assert any(w == "acmebank"
               for w, _ in leak_guard._scan([("app.py", 'host = "acme-bank.internal"')], TERMS))


def test_dotted_client_filename_blocked():
    hits = leak_guard._scan([], TERMS, extra_paths=["data/acme.bank.export.csv"])
    assert any(w == "acmebank" for w, _ in hits)


def test_short_term_not_fuzzy_matched():
    # a <5-char term is NOT normalized (bounds false positives): a spaced form is not matched
    assert leak_guard._scan([("app.py", "a c m e widget here")], ["acme"]) == []


def test_dump_artifact_blocked_by_extension():
    # GAP 5b: a renamed dump with NO client token in the name is still blocked by extension
    hits = leak_guard._scan([("retrieved_dump.sql", "INSERT INTO t VALUES (1)")], TERMS)
    assert any(w == "dump artifact" for w, _ in hits)


def test_dump_artifact_allowlist_env(monkeypatch):
    monkeypatch.setenv("LEAK_GUARD_ALLOW_DUMPS", "schema_fixture.sql")
    assert leak_guard._scan([("schema_fixture.sql", "create table t (id int)")], TERMS) == []


def test_private_key_fixture_still_allowed_after_hardening():
    # the existing one-line placeholder PEM literal must still pass (regression guard)
    changes = [("docs/plan.md", 'txt = "-----BEGIN RSA PRIVATE KEY-----\\nABCD\\n-----END RSA PRIVATE KEY-----"')]
    assert leak_guard._scan(changes, TERMS) == []


# ── GAP 3: commit-message leaks (no diff carries them) ────────────────────────

def test_commit_message_client_name_blocked(monkeypatch, tmp_path):
    monkeypatch.setattr(leak_guard, "_load_blocklist", lambda: ["acmebank"])
    f = tmp_path / "MSG"
    f.write_text("fix: patch acmebank login flow\n")
    monkeypatch.setattr(sys, "argv", ["leak_guard.py", "--msg-file", str(f)])
    assert leak_guard.main() == 1


def test_commit_message_secret_blocked(monkeypatch, tmp_path):
    monkeypatch.setattr(leak_guard, "_load_blocklist", lambda: ["acmebank"])
    f = tmp_path / "MSG"
    f.write_text("debug: leaked key " + _AK + "1234567890QRSTUV in prod\n")
    monkeypatch.setattr(sys, "argv", ["leak_guard.py", "--msg-file", str(f)])
    assert leak_guard.main() == 1


def test_clean_commit_message_passes(monkeypatch, tmp_path):
    monkeypatch.setattr(leak_guard, "_load_blocklist", lambda: ["acmebank"])
    f = tmp_path / "MSG"
    f.write_text("fix: harden the leak guard against marker-adjacent secrets\n")
    monkeypatch.setattr(sys, "argv", ["leak_guard.py", "--msg-file", str(f)])
    assert leak_guard.main() == 0


# ── Fix: SOFT secrets must NOT be suppressed by an unrelated line substring ──────
# Previously any line containing 'example'/'abcd'/'fake'/… anywhere suppressed EVERY soft
# secret on that line, so a real basic-auth URL against example.com slipped through.

_JWT = "eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 10


def test_real_jwt_with_example_annotation_still_blocked():
    line = f'token = "{_JWT}"  # example token for the prod gateway'
    assert any("JWT" in w for w, _ in leak_guard._scan([("svc.py", line)], TERMS))


def test_real_basic_auth_against_example_host_still_blocked():
    # the credential is real; the host being example.com must NOT relax the soft check
    line = 'u = "https://admin:Hunter2Password@db.example.com/api"'
    assert any(w == "basic-auth URL" for w, _ in leak_guard._scan([("svc.py", line)], TERMS))


def test_real_jwt_with_abcd_substring_still_blocked():
    line = f'auth = "{_JWT}"  abcdefg trailing'
    assert any("JWT" in w for w, _ in leak_guard._scan([("svc.py", line)], TERMS))


def test_in_token_marker_still_suppresses_soft_secret():
    # the documented in-TOKEN relaxation must remain: your_password_here is a fixture
    assert leak_guard._scan([("svc.py", 'password = "your_password_here"')], TERMS) == []


def test_basic_auth_fixture_credential_still_allowed():
    # a fixture marker IN THE CREDENTIAL still suppresses (host being example.com is irrelevant)
    line = 'u = "https://fake_user:fakepass@db.example.com/x"'
    assert leak_guard._scan([("svc.py", line)], TERMS) == []


# ── Fix: non-ASCII client filenames must not be octal-escaped past the guard ─────

def test_unquote_git_path_decodes_octal_utf8():
    # git core.quotepath ON form: "caf\303\251_dump.sql" -> café_dump.sql
    quoted = '"caf\\303\\251_dump.sql"'
    assert leak_guard._unquote_git_path(quoted) == "café_dump.sql"


def test_unquote_git_path_passthrough_for_plain_path():
    assert leak_guard._unquote_git_path("engagements/acmebank_dump.sql") == \
        "engagements/acmebank_dump.sql"


def test_non_ascii_client_filename_blocked():
    # raw UTF-8 path (as emitted with quotepath=false) normalizes and matches the client term
    hits = leak_guard._scan([], ["cafebank"], extra_paths=["data/cafébank_export.csv"])
    assert any(w == "cafebank" for w, _ in hits)


# ── Fix: short curated blocklist terms get a one-time verbatim-only warning ──────

def test_short_term_warns_once(monkeypatch, capsys):
    monkeypatch.setattr(leak_guard, "_WARNED_SHORT_TERMS", False)
    leak_guard._scan([("app.py", "x = 1")], ["acme", "acmebank"])
    err = capsys.readouterr().err
    assert "acme" in err and "VERBATIM" in err
    # second call is silent (one-time)
    leak_guard._scan([("app.py", "x = 1")], ["acme"])
    assert capsys.readouterr().err == ""
