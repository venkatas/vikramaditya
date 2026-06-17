"""Three gaps surfaced by a live engagement run (2026-06-16), all under a local DNS outage:

1. gau/waymore had NO timeout in recon.sh — a stalled archive provider hangs the whole
   URL-collection phase (observed: gau stuck ~4 min producing 0 output). katana already
   uses `timeout 300`; gau/waymore must use the hard-kill `timeout -k` form like amass/dnsx.
2. `_githound_output_is_error` missed git-hound's Go-panic / login-crash output, so a 22-line
   crash stack trace was counted as "21 results" — a false CRITICAL finding in the report.
3. git-hound v1.7.2 nil-pointer-crashes on missing/placeholder creds (it scrapes
   github.com/login for a CSRF token). Guard the run so a placeholder config skips cleanly.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import hunt  # noqa: E402

REPO = os.path.join(os.path.dirname(__file__), "..")
RECON_SH = os.path.join(REPO, "recon.sh")


def _recon_src():
    with open(RECON_SH) as f:
        return f.read()


# ── Gap 1: gau + waymore must use a hard-kill timeout (like amass/dnsx) ────────

def test_gau_uses_hardkill_timeout():
    s = _recon_src()
    assert 'GAU_TIMEOUT="${GAU_TIMEOUT:-' in s, "GAU_TIMEOUT must be defined/overridable"
    assert 'timeout -k 15 "$GAU_TIMEOUT" gau' in s, "gau must run under timeout -k"
    assert "| gau " not in s, "no bare un-timeout'd `| gau` invocation may remain"


def test_waymore_uses_hardkill_timeout():
    s = _recon_src()
    assert 'WAYMORE_TIMEOUT="${WAYMORE_TIMEOUT:-' in s
    assert 'timeout -k 15 "$WAYMORE_TIMEOUT" waymore' in s


# ── Gap 2: a git-hound CRASH is an error, not "21 results" ─────────────────────

def test_githound_go_panic_counted_as_error():
    crash = (
        "Error getting CSRF token page.\n"
        'Get "https://github.com/login": dial tcp: lookup github.com: i/o timeout\n'
        "panic: runtime error: invalid memory address or nil pointer dereference\n"
        "[signal SIGSEGV: segmentation violation code=0x2 addr=0x48 pc=0x102d2c850]\n"
        "goroutine 1 [running]:\n"
        "github.com/tillson/git-hound/internal/app.GrabCSRFToken(...)\n"
    )
    assert hunt._githound_output_is_error(crash)


def test_githound_login_and_network_failures_are_errors():
    assert hunt._githound_output_is_error("Error getting CSRF token page.")
    assert hunt._githound_output_is_error('Get "https://github.com/login": dial tcp: lookup github.com: i/o timeout')


def test_githound_bare_panic_word_in_result_not_flagged():
    """Codex MED: a real result snippet that merely CONTAINS 'panic:' / 'nil pointer' /
    'i/o timeout' (e.g. matched Go source) must NOT be discarded as a tool crash — a crash
    requires a panic indicator AND a Go/git-hound stack marker (cluster)."""
    snippet = ("https://github.com/x/y/blob/main/server.go\n"
               "// recover from panic: nil pointer dereference; retry on i/o timeout\n")
    assert not hunt._githound_output_is_error(snippet)


def test_githound_real_results_still_not_flagged():
    """Regression: don't over-match — real findings and empty output are NOT errors."""
    real = "https://github.com/acme/repo/blob/main/.env\nAWS_SECRET=AKIAIOSFODNN7EXAMPLE\n"
    assert not hunt._githound_output_is_error(real)
    assert not hunt._githound_output_is_error("")


# ── Gap 3: config-readiness guard — never run git-hound into a crash ───────────

def test_githound_config_ready_true_for_real_token(tmp_path):
    cfg = tmp_path / "config.yml"
    cfg.write_text("github_access_tokens:\n  - ghp_realtokenvalue1234567890abcdef\n")
    assert hunt._githound_config_ready([str(cfg)]) is True


def test_githound_config_ready_false_for_placeholder(tmp_path):
    cfg = tmp_path / "config.yml"
    cfg.write_text("# comment\ngithub_access_tokens:\n  - REPLACE_WITH_YOUR_GITHUB_TOKEN\n")
    assert hunt._githound_config_ready([str(cfg)]) is False


def test_githound_config_ready_false_when_missing(tmp_path):
    assert hunt._githound_config_ready([str(tmp_path / "nope.yml")]) is False


def test_githound_config_ready_false_for_empty_or_no_cred_field(tmp_path):
    cfg = tmp_path / "config.yml"
    cfg.write_text("# only comments, no credential\n")
    assert hunt._githound_config_ready([str(cfg)]) is False


# ── Codex HIGH #1: field present but NO value must be 'not ready' ─────────────

def test_githound_config_ready_false_for_empty_token_field(tmp_path):
    cfg = tmp_path / "config.yml"
    cfg.write_text("github_access_tokens:\n")  # key with no value
    assert hunt._githound_config_ready([str(cfg)]) is False


def test_githound_config_ready_false_for_empty_token_list(tmp_path):
    cfg = tmp_path / "config.yml"
    cfg.write_text("github_access_tokens: []\n")  # empty list
    assert hunt._githound_config_ready([str(cfg)]) is False


# ── Codex HIGH #2: a real token must not be rejected for an incidental substring ─

def test_githound_config_ready_true_for_token_with_incidental_substring(tmp_path):
    # 'todo' appears mid-token; it is NOT a placeholder prefix/exact → usable.
    cfg = tmp_path / "config.yml"
    cfg.write_text("github_access_tokens:\n  - ghp_abctodoREAL1234567890abcdefghij\n")
    assert hunt._githound_config_ready([str(cfg)]) is True


def test_githound_config_ready_true_for_token_with_inline_comment(tmp_path):
    # YAML strips the inline comment → value is the real token.
    cfg = tmp_path / "config.yml"
    cfg.write_text("github_access_tokens:\n  - ghp_real1234567890abcdefghij # TODO rotate\n")
    assert hunt._githound_config_ready([str(cfg)]) is True
