"""Regression guards for fuzzer.py audit fixes (group: fuzzer.py).

All data here is SYNTHETIC (example.invalid / 127.0.0.1 / placeholders).

Covers:
  1. Shell command injection: curl_request must build an argv LIST and run
     it with shell=False, so metacharacters in a crawled URL / header value
     are never interpreted by a shell.
  2. run_cmd must reject string commands (fail closed) — a string would
     re-introduce shell injection.
  3. Recon-URL coverage: no silent [:10] cap; the full set is loaded, a cap
     only applies when --max-urls is set, and it emits a [DEGRADED] marker.
  4. Prototype-pollution heuristic fires on a value reflected even when the
     __proto__ key is echoed back in the body.
  5. Security-header test: HSTS not flagged over plain HTTP; non-2xx
     responses are skipped.
"""
import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import fuzzer  # noqa: E402


# ---------------------------------------------------------------------------
# 1 + 2. Command injection / fail-closed run_cmd
# ---------------------------------------------------------------------------

def test_run_cmd_rejects_string_command():
    """A string command would be shell-interpreted; run_cmd must fail closed."""
    with pytest.raises(TypeError):
        fuzzer.run_cmd('curl "https://example.invalid"')


def test_curl_request_passes_argv_list_no_shell(monkeypatch):
    """curl_request must hand run_cmd an argv LIST with the URL as its own
    element (no surrounding quotes, no shell join)."""
    captured = {}

    def fake_run_cmd(cmd, timeout=15):
        captured["cmd"] = cmd
        # Minimal well-formed HTTP response so parsing succeeds.
        return True, "HTTP/1.1 200 OK\r\n\r\nbody", ""

    monkeypatch.setattr(fuzzer, "run_cmd", fake_run_cmd)

    malicious_url = 'https://example.invalid/"; touch /tmp/pwned; "'
    fuzzer.curl_request(
        malicious_url,
        headers={"X-Test": "value$(id)"},
    )

    cmd = captured["cmd"]
    assert isinstance(cmd, list), "curl_request must build an argv list"
    # URL appears verbatim as a single argv element (not wrapped/joined).
    assert malicious_url in cmd
    # The metacharacter-laden URL is NOT collapsed into a shell string.
    assert all(isinstance(part, str) for part in cmd)
    # Header passed as its own -H element, never concatenated into a shell str.
    assert "X-Test: value$(id)" in cmd


def test_run_cmd_uses_fork_safe_no_shell(monkeypatch):
    """run_cmd routes through procutil.run_capture with shell=False."""
    seen = {}

    def fake_run_capture(spec, timeout=None, shell=True, merge_stderr=True, **kw):
        seen["spec"] = spec
        seen["shell"] = shell
        return {"stdout": "ok", "stderr": "", "returncode": 0, "timed_out": False}

    monkeypatch.setattr(fuzzer.procutil, "run_capture", fake_run_capture)

    ok, out, err = fuzzer.run_cmd(["curl", "-s", "https://example.invalid"])
    assert ok is True
    assert out == "ok"
    assert seen["shell"] is False
    assert seen["spec"] == ["curl", "-s", "https://example.invalid"]


# ---------------------------------------------------------------------------
# 3. Recon URL coverage — no silent cap
# ---------------------------------------------------------------------------

def _write_urls(tmp_path, n):
    live = tmp_path / "live"
    live.mkdir()
    f = live / "urls.txt"
    f.write_text("".join(f"https://host{i}.example.invalid\n" for i in range(n)))
    return tmp_path


def _run_main(monkeypatch, argv):
    """Run fuzzer.main() with argv, stubbing the actual fuzzing, and return
    the list of targets that would have been fuzzed."""
    targets_seen = []

    class FakeFuzzer:
        def __init__(self, target, findings_dir=None, deep=False):
            targets_seen.append(target)

        def run_all_tests(self):
            pass

    monkeypatch.setattr(fuzzer, "ZeroDayFuzzer", FakeFuzzer)
    monkeypatch.setattr(sys, "argv", argv)
    fuzzer.main()
    return targets_seen


def test_recon_urls_no_silent_cap(monkeypatch, tmp_path, capsys):
    """With 25 recon URLs and no --max-urls, ALL 25 are fuzzed (was [:10])."""
    recon = _write_urls(tmp_path, 25)
    targets = _run_main(monkeypatch, ["fuzzer.py", "--recon-dir", str(recon)])
    assert len(targets) == 25
    out = capsys.readouterr().out
    assert "loaded 25" in out
    assert "[DEGRADED]" not in out


def test_recon_urls_explicit_cap_marks_degraded(monkeypatch, tmp_path, capsys):
    """--max-urls caps and emits a loud [DEGRADED] marker (no silent drop)."""
    recon = _write_urls(tmp_path, 25)
    targets = _run_main(
        monkeypatch, ["fuzzer.py", "--recon-dir", str(recon), "--max-urls", "10"]
    )
    assert len(targets) == 10
    out = capsys.readouterr().out
    assert "[DEGRADED]" in out
    assert "15 URL(s) dropped" in out


# ---------------------------------------------------------------------------
# 4. Prototype-pollution heuristic survives URL echo
# ---------------------------------------------------------------------------

def _make_fuzzer(tmp_path, target="https://example.invalid"):
    return fuzzer.ZeroDayFuzzer(target, findings_dir=str(tmp_path / "f"))


def test_prototype_pollution_fires_when_key_echoed(monkeypatch, tmp_path):
    """Body echoes the full request URL (incl. __proto__) AND processes the
    value 'polluted' separately -> must still flag."""
    zf = _make_fuzzer(tmp_path)

    def fake_curl(url, **kw):
        # Reflect the request URL (contains __proto__) AND an extra stray
        # 'polluted' token that is NOT part of the echoed payload.
        body = f"<html>echo: {url} ... result=polluted</html>"
        return 200, "HTTP/1.1 200 OK", body

    monkeypatch.setattr(fuzzer, "curl_request", fake_curl)
    zf.test_prototype_pollution()
    assert any(f["type"] == "prototype_pollution" for f in zf.findings)


def test_prototype_pollution_no_finding_on_plain_echo(monkeypatch, tmp_path):
    """If the body ONLY echoes the payload verbatim, stripping it removes the
    'polluted' token -> no finding (no false positive)."""
    zf = _make_fuzzer(tmp_path)

    def fake_curl(url, **kw):
        # Body contains the payload exactly once (whole-URL echo) and nothing else.
        from urllib.parse import urlparse
        path = url.split("/", 3)[-1]  # everything after host
        return 200, "HTTP/1.1 200 OK", f"echo:{path}"

    monkeypatch.setattr(fuzzer, "curl_request", fake_curl)
    zf.test_prototype_pollution()
    assert not any(f["type"] == "prototype_pollution" for f in zf.findings)


# ---------------------------------------------------------------------------
# 5. Security headers — HSTS over HTTP + status gating
# ---------------------------------------------------------------------------

def test_hsts_not_flagged_over_http(monkeypatch, tmp_path):
    zf = _make_fuzzer(tmp_path, target="http://example.invalid")

    def fake_curl(url, **kw):
        # 200 response with NO security headers at all.
        return 200, "HTTP/1.1 200 OK\r\nServer: x", "body"

    monkeypatch.setattr(fuzzer, "curl_request", fake_curl)
    zf.test_security_headers()
    titles = [f["title"] for f in zf.findings]
    assert not any("HSTS" in t for t in titles), "HSTS must not be flagged over HTTP"
    # Other headers still flagged.
    assert any("X-Frame-Options" in t for t in titles)


def test_hsts_flagged_over_https(monkeypatch, tmp_path):
    zf = _make_fuzzer(tmp_path, target="https://example.invalid")

    def fake_curl(url, **kw):
        return 200, "HTTP/1.1 200 OK\r\nServer: x", "body"

    monkeypatch.setattr(fuzzer, "curl_request", fake_curl)
    zf.test_security_headers()
    assert any("HSTS" in f["title"] for f in zf.findings)


def test_security_headers_skipped_on_non_2xx(monkeypatch, tmp_path):
    zf = _make_fuzzer(tmp_path, target="https://example.invalid")

    def fake_curl(url, **kw):
        # A redirect / error response legitimately omits security headers.
        return 302, "HTTP/1.1 302 Found\r\nLocation: /x", ""

    monkeypatch.setattr(fuzzer, "curl_request", fake_curl)
    zf.test_security_headers()
    assert zf.findings == [], "non-2xx responses must not produce missing-header noise"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
