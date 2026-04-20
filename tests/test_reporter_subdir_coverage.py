"""Regression tests for v7.4.4 — reporter.py subdir coverage.

Issue #2 (github.com/venkatas/vikramaditya/issues/2, reporter Harry53)
exposed that the reporter's ``SUBDIR_VTYPE`` map was out of sync with
``scanner.sh``'s output surface. Five finding subdirs —
``deserialize/``, ``import_export/``, ``mfa/``, ``saml/``,
``supply_chain/`` — were being silently ignored; every finding they
contained vanished from the HTML report.

These tests pin:

1. Every scanner.sh output dir is represented in ``SUBDIR_VTYPE``.
2. Every ``SUBDIR_VTYPE`` value has a matching ``VULN_TEMPLATES``
   entry (otherwise the reporter can't render it properly).
3. The new warning-log in ``load_findings`` fires on unknown subdirs
   so future drift is visible in the scan log.
4. A fake findings dir with each new subdir actually produces
   finding entries (end-to-end shape).
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from reporter import SUBDIR_VTYPE, VULN_TEMPLATES, load_findings


# ---------------------------------------------------------------------------
# scanner.sh writes these dirs. Regression: all must be in SUBDIR_VTYPE.
# ---------------------------------------------------------------------------


_SCANNER_FINDINGS_DIRS = (
    "sqli", "xss", "ssti", "upload", "rce", "cves", "metasploit",
    # v5.2 additions — previously missing from reporter:
    "mfa", "saml",
    # scanner.sh long-running additions that also slipped out:
    "deserialize", "import_export", "supply_chain",
)


class TestSubdirCoverage:
    @pytest.mark.parametrize("subdir", _SCANNER_FINDINGS_DIRS)
    def test_every_scanner_subdir_is_mapped(self, subdir: str) -> None:
        """Regression for issue #2 — all scanner.sh output dirs must map."""
        assert subdir in SUBDIR_VTYPE, (
            f"scanner.sh writes findings to '{subdir}/' but reporter has no "
            f"SUBDIR_VTYPE entry — findings will be silently dropped."
        )

    def test_every_mapped_vtype_has_template(self) -> None:
        """Each SUBDIR_VTYPE value must have a matching VULN_TEMPLATES entry."""
        missing = []
        for subdir, vtype in SUBDIR_VTYPE.items():
            if vtype not in VULN_TEMPLATES:
                missing.append((subdir, vtype))
        assert not missing, (
            f"{len(missing)} vtype(s) lack a VULN_TEMPLATES entry: {missing}"
        )

    def test_new_vuln_classes_have_complete_templates(self) -> None:
        """v7.4.4's new templates must carry the full field set."""
        required = {"title", "severity", "cvss", "cwe", "impact", "remediation",
                     "references"}
        for vtype in ("deserialization", "supply_chain", "jwt", "graphql",
                       "smuggling"):
            tmpl = VULN_TEMPLATES.get(vtype)
            assert tmpl is not None, f"missing template: {vtype}"
            assert required.issubset(tmpl.keys()), (
                f"{vtype} template missing fields: "
                f"{required - set(tmpl.keys())}"
            )


# ---------------------------------------------------------------------------
# End-to-end: build a fake findings dir, check load_findings picks up new dirs
# ---------------------------------------------------------------------------


class TestLoadFindingsPicksUpNewSubdirs:
    def _seed_findings_dir(self, tmp_path, subdir: str, payload: str):
        """Create ``<tmp>/<subdir>/findings.txt`` with a single line."""
        d = tmp_path / subdir
        d.mkdir()
        (d / "findings.txt").write_text(payload + "\n")
        return tmp_path

    def test_mfa_findings_reach_report(self, tmp_path) -> None:
        self._seed_findings_dir(tmp_path, "mfa",
                                 "HIGH https://target/api/login — MFA bypass via OTP reuse")
        findings = load_findings(str(tmp_path))
        assert any(f.get("vtype") == "auth_bypass" for f in findings), \
            "mfa/ findings must render as auth_bypass vtype"

    def test_saml_findings_reach_report(self, tmp_path) -> None:
        self._seed_findings_dir(tmp_path, "saml",
                                 "HIGH https://target/saml/sso — XML signature wrapping")
        findings = load_findings(str(tmp_path))
        assert any(f.get("vtype") == "auth_bypass" for f in findings), \
            "saml/ findings must render as auth_bypass vtype"

    def test_deserialize_findings_reach_report(self, tmp_path) -> None:
        self._seed_findings_dir(tmp_path, "deserialize",
                                 "CRITICAL https://target/api — Python pickle deserialization")
        findings = load_findings(str(tmp_path))
        assert any(f.get("vtype") == "deserialization" for f in findings)

    def test_supply_chain_findings_reach_report(self, tmp_path) -> None:
        self._seed_findings_dir(tmp_path, "supply_chain",
                                 "HIGH https://target/static/app.js — jQuery 1.4.1 (CVE-2020-11022)")
        findings = load_findings(str(tmp_path))
        assert any(f.get("vtype") == "supply_chain" for f in findings)

    def test_import_export_findings_reach_report(self, tmp_path) -> None:
        self._seed_findings_dir(tmp_path, "import_export",
                                 "HIGH https://target/api/import — CSV formula injection")
        findings = load_findings(str(tmp_path))
        assert any(f.get("vtype") == "business_logic" for f in findings), \
            "import_export/ findings should render as business_logic class"


# ---------------------------------------------------------------------------
# Warning log fires on unknown subdirs
# ---------------------------------------------------------------------------


class TestUnknownSubdirWarning:
    def test_unknown_subdir_with_payload_triggers_warning(self, tmp_path, capsys) -> None:
        """Adding a brand-new ``mystery/findings.txt`` should warn loudly."""
        d = tmp_path / "mystery_new_class"
        d.mkdir()
        (d / "findings.txt").write_text("HIGH https://target — new finding class\n")

        load_findings(str(tmp_path))

        captured = capsys.readouterr()
        assert "mystery_new_class" in captured.out
        assert "SUBDIR_VTYPE" in captured.out
        assert "IGNORED" in captured.out

    def test_meta_dirs_do_not_warn(self, tmp_path, capsys) -> None:
        """``summary/``, ``brain/``, ``screenshots/`` etc. are known-meta."""
        for meta in ("brain", "screenshots", "exploits", "manual_review"):
            d = tmp_path / meta
            d.mkdir()
            (d / "notes.txt").write_text("not a finding\n")

        load_findings(str(tmp_path))
        captured = capsys.readouterr()
        # None of the meta dirs should appear in the warning stream.
        for meta in ("brain", "screenshots", "exploits", "manual_review"):
            assert f"'{meta}/'" not in captured.out, \
                f"meta dir {meta} should not trigger the warning"

    def test_known_dir_does_not_warn(self, tmp_path, capsys) -> None:
        """mfa/ is now mapped; must NOT trigger the unknown-subdir warning."""
        d = tmp_path / "mfa"
        d.mkdir()
        (d / "findings.txt").write_text("HIGH https://target — MFA bypass\n")

        load_findings(str(tmp_path))
        captured = capsys.readouterr()
        assert "'mfa/'" not in captured.out

    def test_empty_unknown_dir_does_not_warn(self, tmp_path, capsys) -> None:
        """A subdir with no .txt/.json content is not interesting."""
        (tmp_path / "empty_unknown").mkdir()
        load_findings(str(tmp_path))
        captured = capsys.readouterr()
        assert "empty_unknown" not in captured.out
