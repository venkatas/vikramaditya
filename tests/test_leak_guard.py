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
    # content is clean, but the client identifier is in the FILE NAME (the colleqbt_*.sql vector)
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
