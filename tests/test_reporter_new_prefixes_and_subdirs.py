"""Regression tests for the recon-skills-adoption batch (Task 10) — reporter.py
wiring for the new hunt.py phases added in Task 9 (xxe/redirect/saml/actuator/
ldap) and hardened across 4 fix rounds.

Task 9's fix rounds introduced several new unverified "lead" prefixes
([XXE-CANDIDATE], [XXE-UPLOAD-CANDIDATE], [SPEL-CANDIDATE],
[JOLOKIA-REACHABLE], [LDAP-FUZZ-CANDIDATE], [LDAP-BYPASS-CANDIDATE]) that must
never be auto-shipped as findings, and new confirmed-finding subdirs (xxe,
redirects, actuator, ldap) that must map to a real vtype so they render in the
report instead of silently vanishing (same failure class as issue #2 /
test_reporter_subdir_coverage.py).

These tests pin:

1. Each new CANDIDATE/info-only prefix is suppressed via NON_FINDING_PREFIXES.
2. [WAF-BLOCK-DETECTED] (already added in Task 9 Fix Round 3) is present
   exactly once — no accidental duplicate from this task's edits.
3. Each new subdir (xxe, redirects, actuator, ldap) maps to the correct vtype
   in SUBDIR_VTYPE, and saml_xsw is deliberately NOT a separate key (its
   [SAML-XSW-CONFIRMED] findings share findings/saml/ with the pre-existing
   "saml" mapping).
4. VULN_TEMPLATES has a complete "xxe" entry.
5. End-to-end: a CONFIRMED line in each new subdir reaches load_findings()
   with the right vtype, while a CANDIDATE line in the same dir is dropped.
"""

from __future__ import annotations

import inspect
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import reporter
from reporter import SUBDIR_VTYPE, VULN_TEMPLATES, load_findings


# ---------------------------------------------------------------------------
# 1. New candidate / info-only prefixes must be suppressed.
# ---------------------------------------------------------------------------

NEW_NON_FINDING_PREFIXES = (
    "[XXE-CANDIDATE]",
    "[XXE-UPLOAD-CANDIDATE]",
    "[SPEL-CANDIDATE]",
    "[JOLOKIA-REACHABLE]",
    "[LDAP-FUZZ-CANDIDATE]",
    "[LDAP-BYPASS-CANDIDATE]",
)


class TestNewCandidatePrefixesAreNonFinding:
    def test_each_new_prefix_is_registered(self) -> None:
        """NON_FINDING_PREFIXES is a local tuple inside load_findings(), not a
        module attribute, so we check the source text (same approach the
        original task brief's test used)."""
        source = inspect.getsource(reporter)
        missing = [p for p in NEW_NON_FINDING_PREFIXES if p not in source]
        assert not missing, f"prefixes missing from reporter.py: {missing}"

    def test_waf_block_detected_not_duplicated(self) -> None:
        """Task 9 Fix Round 3 already added [WAF-BLOCK-DETECTED]; this task
        must not introduce a second copy of the literal."""
        source = inspect.getsource(reporter)
        assert source.count('"[WAF-BLOCK-DETECTED]"') == 1, (
            "[WAF-BLOCK-DETECTED] should appear exactly once in reporter.py"
        )

    def test_candidate_lines_are_dropped_end_to_end(self, tmp_path) -> None:
        cases = {
            "xxe": "[XXE-CANDIDATE] https://target/api/xml | 500 + XML parser error",
            "actuator": "[SPEL-CANDIDATE] https://target/actuator/env | 2+2=4 evaluated",
            "ldap": "[LDAP-FUZZ-CANDIDATE] https://target/login | payload='*)(uid=*'",
        }
        for subdir, line in cases.items():
            d = tmp_path / subdir
            d.mkdir()
            (d / "findings.txt").write_text(line + "\n")

        findings = load_findings(str(tmp_path))
        raws = [f.get("raw", "") for f in findings]
        for line in cases.values():
            assert not any(line in raw for raw in raws), (
                f"candidate line should have been suppressed: {line!r}"
            )


# ---------------------------------------------------------------------------
# 2. New subdirs map to the correct vtype.
# ---------------------------------------------------------------------------


class TestNewSubdirMappings:
    def test_xxe_subdir_is_mapped(self) -> None:
        assert SUBDIR_VTYPE.get("xxe") == "xxe"

    def test_redirects_subdir_is_mapped(self) -> None:
        assert SUBDIR_VTYPE.get("redirects") == "open_redirect"

    def test_actuator_subdir_is_mapped(self) -> None:
        assert SUBDIR_VTYPE.get("actuator") == "misconfig"

    def test_ldap_subdir_is_mapped(self) -> None:
        assert SUBDIR_VTYPE.get("ldap") == "auth_bypass"

    def test_saml_xsw_is_not_a_separate_key(self) -> None:
        """[SAML-XSW-CONFIRMED] lands in findings/saml/ — the same dir the
        pre-existing 'saml' mapping already covers. No 'saml_xsw' key needed."""
        assert "saml_xsw" not in SUBDIR_VTYPE
        assert SUBDIR_VTYPE.get("saml") == "auth_bypass"


# ---------------------------------------------------------------------------
# 3. VULN_TEMPLATES has a complete "xxe" entry.
# ---------------------------------------------------------------------------


class TestXxeTemplate:
    def test_xxe_template_exists_and_is_complete(self) -> None:
        required = {"title", "severity", "cvss", "cwe", "impact", "remediation",
                    "references"}
        tmpl = VULN_TEMPLATES.get("xxe")
        assert tmpl is not None, "VULN_TEMPLATES missing 'xxe' entry"
        assert required.issubset(tmpl.keys()), (
            f"xxe template missing fields: {required - set(tmpl.keys())}"
        )


# ---------------------------------------------------------------------------
# 4. End-to-end: CONFIRMED findings in the new subdirs reach the report.
# ---------------------------------------------------------------------------


class TestLoadFindingsPicksUpNewSubdirs:
    def _seed(self, tmp_path, subdir: str, payload: str):
        d = tmp_path / subdir
        d.mkdir()
        (d / "findings.txt").write_text(payload + "\n")
        return tmp_path

    def test_xxe_confirmed_reaches_report(self, tmp_path) -> None:
        self._seed(tmp_path, "xxe",
                   "[XXE-CONFIRMED] https://target/api/xml | /etc/passwd contents echoed")
        findings = load_findings(str(tmp_path))
        assert any(f.get("vtype") == "xxe" for f in findings)

    def test_redirects_confirmed_reaches_report(self, tmp_path) -> None:
        self._seed(tmp_path, "redirects",
                   "[OPEN-REDIRECT-CONFIRMED] https://target/login?next=// | param=next")
        findings = load_findings(str(tmp_path))
        assert any(f.get("vtype") == "open_redirect" for f in findings)

    def test_actuator_confirmed_reaches_report(self, tmp_path) -> None:
        self._seed(tmp_path, "actuator",
                   "[ACTUATOR-ENV-SECRET-CONFIRMED] https://target/actuator/env | AWS_SECRET_ACCESS_KEY=...")
        findings = load_findings(str(tmp_path))
        assert any(f.get("vtype") == "misconfig" for f in findings)

    def test_ldap_confirmed_reaches_report(self, tmp_path) -> None:
        self._seed(tmp_path, "ldap",
                   "[LDAP-INJECTION-CONFIRMED] https://target/login | admin bypass via *)(uid=*")
        findings = load_findings(str(tmp_path))
        assert any(f.get("vtype") == "auth_bypass" for f in findings)
