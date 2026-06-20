"""Regression tests for the hunt.py audit-fix batch (group: hunt.py).

Covers:
  * Command-injection hardening of the shell=True subprocess sinks that
    interpolate ATTACKER/TARGET-controlled values (whatweb URL from archive
    feeds; sqlmap OpenAPI/POST URL+body+param-names). Every interpolated value
    must be shlex.quote'd so a payload like  $(touch /tmp/pwn)  or  x";id #
    survives as a SINGLE inert shell token instead of breaking out of /bin/sh -c.
  * Coverage-honesty: a watchdog SIGKILL / wall-clock timeout drops a
    ``.recon_truncated`` sentinel for the recon phase.
  * CIDR true-host-count reporting (no silent 254 cap in the log line).

All inputs are SYNTHETIC (example.invalid / 127.0.0.1 / placeholder tokens).
"""

from __future__ import annotations

import os
import shlex
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import hunt  # noqa: E402


# ── Shell-injection: whatweb fingerprint loop (target-derived URL) ────────────
class TestWhatwebUrlInjection:
    """run_cms_exploit's whatweb loop interpolates a gau/wayback-derived URL
    into a shell=True command. A $(...) / backtick / quote in that URL must NOT
    break out of the command."""

    _PAYLOADS = [
        "https://example.invalid/$(touch ${HOME}/PWNED)",
        "https://example.invalid/`id`",
        'https://example.invalid/x";id;"',
        "https://example.invalid/x';id;'",
    ]

    def _run(self, tmp_path, monkeypatch, url):
        recon_dir = tmp_path / "recon"
        findings_dir = tmp_path / "findings"
        (recon_dir / "live").mkdir(parents=True)
        (findings_dir).mkdir(parents=True)
        # httpx_full.txt must exist (function early-returns otherwise).
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://example.invalid [200] [nginx]\n")
        (recon_dir / "live" / "urls.txt").write_text(url + "\n")

        monkeypatch.setattr(hunt, "_resolve_recon_dir",
                            lambda *a, **k: str(recon_dir))
        monkeypatch.setattr(hunt, "_resolve_findings_dir",
                            lambda *a, **k: str(findings_dir))
        # whatweb "present"; everything else absent so we exercise only step 1.
        monkeypatch.setattr(hunt, "_tool_bin",
                            lambda name: "whatweb" if name == "whatweb" else "")
        # run_cms_exploit gates the whatweb loop on _which(whatweb_bin); make
        # only "whatweb" resolve so nuclei/drupal/etc. stay absent.
        monkeypatch.setattr(hunt, "_which",
                            lambda name: name == "whatweb")
        monkeypatch.setattr(hunt, "_brain", None, raising=False)

        captured: list[str] = []

        def fake_run_cmd(cmd, *a, **k):
            captured.append(cmd)
            return True, ""

        monkeypatch.setattr(hunt, "run_cmd", fake_run_cmd)
        try:
            hunt.run_cms_exploit("example.invalid")
        except Exception:
            # Downstream steps may bail on the synthetic env; we only care that
            # the whatweb command was captured before any bail-out.
            pass
        return captured

    @pytest.mark.parametrize("url", _PAYLOADS)
    def test_url_is_single_quoted_token(self, tmp_path, monkeypatch, url):
        cmds = self._run(tmp_path, monkeypatch, url)
        whatweb_cmds = [c for c in cmds if "whatweb" in c and "-a1" in c]
        assert whatweb_cmds, "whatweb command was not built"
        cmd = whatweb_cmds[0]
        # The hardened command must contain the shlex.quote'd form of the URL.
        assert shlex.quote(url) in cmd
        # And the raw double-quoted form must NOT appear (the old vulnerable shape).
        assert f'"{url}"' not in cmd
        # Tokenizing the command must yield the URL as exactly one argv token,
        # proving the metacharacters did not split into new shell words.
        tokens = shlex.split(cmd.split(">>")[0])
        assert url in tokens


# ── Shell-injection: sqlmap command builders (string-construction invariant) ──
class TestSqlmapCommandQuoting:
    """Pin the invariant that the sqlmap command builders quote every
    target/attacker-controlled value as a single inert shell token. We rebuild
    the exact f-strings the hardened code uses and assert injection containment,
    plus assert the old vulnerable double/single-quote shapes are gone."""

    def test_openapi_post_body_with_quote_is_contained(self):
        # An OpenAPI property name carrying a single quote + shell metachars —
        # json.dumps does NOT escape single quotes, so manual quoting would break
        # out; shlex.quote must contain it.
        body = '{"a\';id;\'":"test"}'
        url = "https://example.invalid/api/login"
        method = "POST"
        sqli_dir = "/tmp/sqli out"  # space proves quoting of the dir too
        cmd = (
            f'sqlmap -u {shlex.quote(url)} --data={shlex.quote(body)} '
            f'--method {shlex.quote(method)} --output-dir={shlex.quote(sqli_dir)}'
        )
        tokens = shlex.split(cmd)
        # The data value stays attached to its --data= flag as a SINGLE token.
        assert f"--data={body}" in tokens
        assert f"--output-dir={sqli_dir}" in tokens
        # "id" must not appear as its own command word (no break-out).
        assert "id" not in tokens

    def test_post_param_names_with_injection_contained(self):
        # A form input named  x";id #  joined into the data string.
        params_str = 'x";id #=1&y=1'
        url = 'https://example.invalid/$(id)'
        cmd = (
            f'sqlmap -u {shlex.quote(url)} --data={shlex.quote(params_str)} '
            f'--method POST'
        )
        tokens = shlex.split(cmd)
        assert url in tokens                       # -u value is a standalone token
        assert f"--data={params_str}" in tokens    # data value stays attached
        assert "id" not in tokens

    def test_cookie_opt_quoted(self):
        cookies = 'sid=abc"; id; "'
        cookie_opt = f"--cookie={shlex.quote(cookies)}" if cookies else ""
        tokens = shlex.split(f"sqlmap {cookie_opt}")
        assert f"--cookie={cookies}" in tokens
        assert "id" not in tokens

    def test_source_uses_shlex_quote_not_manual_quotes(self):
        """The hunt.py source for these sinks must shlex.quote the values, not
        wrap them in literal double/single quotes."""
        src = open(os.path.join(os.path.dirname(__file__), "..", "hunt.py")).read()
        # Old vulnerable shapes must be gone.
        assert 'f\'--cookie="{cookies}"\'' not in src
        assert 'sqlmap -u "{op["url"]}"' not in src
        assert 'sqlmap -u "{url}" --data="{params_str}"' not in src
        # The hardened shapes must be present.
        assert "--data={shlex.quote(body)}" in src
        assert "--data={shlex.quote(params_str)}" in src
        assert "--cookie={shlex.quote(cookies)}" in src


# ── Coverage-honesty: truncated-recon sentinel ────────────────────────────────
class TestTruncatedReconSentinel:
    def test_marker_dropped_for_recon_timeout(self, tmp_path):
        watch_dir = tmp_path / "recon"
        watch_dir.mkdir()
        hunt._mark_truncated_recon(str(watch_dir), "RECON")
        assert (watch_dir / ".recon_truncated").exists()

    def test_no_marker_for_non_recon_phase(self, tmp_path):
        watch_dir = tmp_path / "scan"
        watch_dir.mkdir()
        hunt._mark_truncated_recon(str(watch_dir), "SCAN")
        assert not (watch_dir / ".recon_truncated").exists()

    def test_no_marker_when_watch_file_missing(self, tmp_path):
        # watch_file None / not a dir must be a no-op, never raise.
        hunt._mark_truncated_recon(None, "RECON")
        hunt._mark_truncated_recon(str(tmp_path / "nope"), "RECON")

    def test_truncated_recon_blocks_resume_completion(self, tmp_path, monkeypatch):
        recon_dir = tmp_path / "recon"
        findings_dir = tmp_path / "findings"
        (recon_dir / "live").mkdir(parents=True)
        findings_dir.mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text("https://example.invalid\n")

        monkeypatch.setattr(hunt, "_resolve_recon_dir", lambda *a, **k: str(recon_dir))
        monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda *a, **k: str(findings_dir))

        # Without the sentinel, recon counts as completed.
        assert "recon" in hunt._collect_completed_steps("example.invalid")
        # With the sentinel, recon must be re-run (not marked completed).
        (recon_dir / ".recon_truncated").write_text("truncated\n")
        assert "recon" not in hunt._collect_completed_steps("example.invalid")


# ── CIDR true-host-count reporting ────────────────────────────────────────────
class TestExpandCidr:
    def test_expand_cidr_cap_unchanged(self):
        # expand_cidr still caps its RETURN at max_hosts (latent-footgun guard),
        # but a /23 has 510 usable hosts; the cap means len(return) <= 254.
        hosts = hunt.expand_cidr("10.0.0.0/23")
        assert len(hosts) == 254

    def test_invalid_cidr_returns_literal(self):
        assert hunt.expand_cidr("not-a-cidr") == ["not-a-cidr"]
