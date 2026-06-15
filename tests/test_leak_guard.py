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
