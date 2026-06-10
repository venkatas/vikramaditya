"""Tests for hunt.py --targets-file (multi-host scope-lock) host-list handling.

Lets Vikramaditya scan an explicit list of authorized hosts with NO subdomain
enumeration. Host normalization + validation live in Python (testable); recon.sh
just consumes the clean list. Placeholder domains only (never real client names).
"""
import hunt


def _write(tmp_path, text):
    p = tmp_path / "targets.txt"
    p.write_text(text)
    return str(p)


def test_read_targets_file_normalizes_scheme_path_and_dedups(tmp_path):
    f = _write(tmp_path, """
        https://dd.example.com/
        http://app.example.com/some/path?x=1
        mins.example.com
        MINS.example.com
        # a comment line
        docs.example.com

    """.replace("    ", ""))
    hosts = hunt._read_targets_file(f)
    assert hosts == [
        "dd.example.com",
        "app.example.com",
        "mins.example.com",
        "docs.example.com",
    ]  # scheme/path stripped, comment+blank dropped, case-folded dedup, order kept


def test_read_targets_file_skips_comments_and_blanks(tmp_path):
    f = _write(tmp_path, "# header\n\n   \nhost1.example.com\n#mid\nhost2.example.com\n")
    assert hunt._read_targets_file(f) == ["host1.example.com", "host2.example.com"]


def test_read_targets_file_empty_returns_empty(tmp_path):
    f = _write(tmp_path, "# only comments\n\n")
    assert hunt._read_targets_file(f) == []


def test_read_targets_file_rejects_injection_hosts(tmp_path):
    # A crafted "host" with shell metacharacters must be dropped, never passed on
    # (it later becomes a filename/label that is shelled). (Codex HIGH)
    f = _write(tmp_path, "\n".join([
        "good.example.com",
        "x.$(touch /tmp/pwn).com",
        "a;rm -rf ~.com",
        "`id`.example.com",
        "b.example.com|nc evil 1",
        "ok2.example.com",
    ]))
    assert hunt._read_targets_file(f) == ["good.example.com", "ok2.example.com"]


def test_read_targets_file_accepts_host_with_port(tmp_path):
    f = _write(tmp_path, "host.example.com:8443\n")
    assert hunt._read_targets_file(f) == ["host.example.com:8443"]


def test_derive_targets_label_picks_common_apex():
    hosts = ["mins.example.com", "docs.example.com", "a.b.example.com"]
    assert hunt._derive_targets_label(hosts) == "example.com"


def test_derive_targets_label_majority_apex_when_mixed():
    hosts = ["x.foo.com", "y.foo.com", "z.bar.com"]
    assert hunt._derive_targets_label(hosts) == "foo.com"


def test_derive_targets_label_is_shell_safe():
    import re
    assert hunt._derive_targets_label([]) == "targets"
    # :port dropped before apex; result restricted to safe filename chars
    assert hunt._derive_targets_label(["host.example.com:8443"]) == "example.com"
    assert re.fullmatch(r"[a-z0-9.-]+", hunt._derive_targets_label(["a.b.example.com"]))


def test_is_safe_target_accepts_real_targets_rejects_injection():
    for ok in ("example.com", "app.example.com", "192.168.1.1", "10.0.0.0/24", "asn:123456"):
        assert hunt._is_safe_target(ok), ok
    for bad in ("$(whoami).com", "a;rm -rf ~", "`id`", "a.com|nc evil 1", "x y", "", None):
        assert not hunt._is_safe_target(bad), bad
