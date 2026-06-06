"""Regression tests — reporter.py sqlmap-result ingestion + email_auth per-finding CVSS.

Two report-ingestion-contract bugs surfaced by the 2026-06-06 clientd.com run:

1. ``sqlmap/sqlmap_results.txt`` (hunt.py ``--results-file`` CSV) had NO ingestion
   path, so a sqlmap-confirmed SQLi would be silently dropped from the report even
   though the ``sqli_sqlmap_confirmed`` template already exists. The dir also tripped
   the unmapped-subdir WARNING. Fixed with a dedicated loader (Method 1f) plus
   ``meta_dirs`` suppression — the generic Method-1 ``.txt`` scan must NOT touch the
   dir (it also holds ``candidates.txt`` / ``post_*.txt`` console dumps).

2. Every ``email_auth`` finding rendered CVSS 5.3 regardless of its LOW/INFO/HIGH
   label, because the Method 1d loader set per-finding *severity* but never per-finding
   *cvss*, so the renderer fell back to the template's fixed 5.3. Fixed by deriving
   cvss from severity (``CVSS_DEFAULT``) / honoring an explicit per-item ``cvss``.

The header line below is sqlmap's real ``--results-file`` CSV header; a confirmed
injection is a data row with a non-empty ``Technique(s)`` column.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from reporter import CVSS_DEFAULT, VULN_TEMPLATES, load_findings

# sqlmap --results-file header, verbatim.
_SQLMAP_HEADER = "Target URL,Place,Parameter,Technique(s),Note(s)"


def _seed_sqlmap(tmp_path, data_rows, *, name="sqlmap_results.txt", bom=False):
    d = tmp_path / "sqlmap"
    if not d.exists():
        d.mkdir()
    content = "\n".join([_SQLMAP_HEADER] + list(data_rows)) + "\n"
    # ``utf-8-sig`` prepends a BOM, reproducing sqlmap-on-Windows / concatenated CSVs.
    (d / name).write_text(content, encoding="utf-8-sig" if bom else "utf-8")
    return d


def _sqlmap_findings(findings):
    return [f for f in findings if f.get("vtype") == "sqli_sqlmap_confirmed"]


class TestSqlmapIngestion:
    def test_confirmed_injection_becomes_finding(self, tmp_path):
        _seed_sqlmap(tmp_path, ["http://victim.test/item.php?id=1,GET,id,BEUST,"])
        fs = _sqlmap_findings(load_findings(str(tmp_path)))
        assert len(fs) == 1, "a confirmed sqlmap injection must reach the report"
        f = fs[0]
        assert f["severity"] == "critical"
        assert "victim.test" in f["title"]
        assert "item.php" in f["url"]
        assert "id" in f["poc"]

    def test_header_only_results_file_yields_no_finding(self, tmp_path):
        # The real clientd.com case: sqlmap ran, confirmed nothing → header only.
        # Must NOT fabricate a CRITICAL.
        _seed_sqlmap(tmp_path, [])
        assert _sqlmap_findings(load_findings(str(tmp_path))) == []

    def test_row_with_empty_technique_is_not_confirmed(self, tmp_path):
        # No Technique(s) column => sqlmap did not confirm injection => not a finding.
        _seed_sqlmap(tmp_path, ["http://victim.test/p.php?id=1,GET,id,,"])
        assert _sqlmap_findings(load_findings(str(tmp_path))) == []

    def test_multiple_injections_each_become_findings(self, tmp_path):
        _seed_sqlmap(tmp_path, [
            "http://victim.test/a.php?id=1,GET,id,BEUST,",
            "http://victim.test/b.php?cat=2,GET,cat,BU,",
        ])
        fs = _sqlmap_findings(load_findings(str(tmp_path)))
        assert len(fs) == 2

    def test_duplicate_rows_collapse(self, tmp_path):
        _seed_sqlmap(tmp_path, [
            "http://victim.test/a.php?id=1,GET,id,BEUST,",
            "http://victim.test/a.php?id=1,GET,id,BEUST,",
        ])
        fs = _sqlmap_findings(load_findings(str(tmp_path)))
        assert len(fs) == 1, "identical sqlmap rows must dedupe, not double-report"

    def test_sqlmap_dir_does_not_trigger_unmapped_warning(self, tmp_path, capsys):
        d = _seed_sqlmap(tmp_path, [])
        (d / "candidates.txt").write_text("http://victim.test/p.php?id=FUZZ\n")
        load_findings(str(tmp_path))
        out = capsys.readouterr().out
        assert "'sqlmap/' is not" not in out, (
            "sqlmap/ is handled by a dedicated loader; it must not warn as unmapped"
        )

    def test_candidate_urls_never_become_findings(self, tmp_path):
        # candidates.txt / post_*.txt are sqlmap *inputs/console*, never findings.
        d = _seed_sqlmap(tmp_path, [])
        (d / "candidates.txt").write_text(
            "http://victim.test/p.php?id=FUZZ\nhttp://victim.test/q.php?x=FUZZ\n"
        )
        (d / "post_victim.test_api.txt").write_text("[*] starting @ ...\nFUZZ console noise\n")
        findings = load_findings(str(tmp_path))
        blob = " ".join(
            (f.get("url", "") + f.get("title", "") + f.get("detail", "") + f.get("poc", ""))
            for f in findings
        )
        assert "FUZZ" not in blob, "sqlmap candidate/console files must not be parsed as findings"

    def test_false_positive_note_row_skipped(self, tmp_path):
        # sqlmap tags unexploitable candidates "false positive or unexploitable" in
        # Note(s); brain.py already rejects these — the reporter must too, else a
        # scanner-rejected row becomes a CRITICAL report finding.
        _seed_sqlmap(tmp_path, [
            'http://victim.test/p.php?id=1,GET,id,BEUST,false positive or unexploitable',
        ])
        assert _sqlmap_findings(load_findings(str(tmp_path))) == []

    def test_post_results_csv_confirmed_injection_ingested(self, tmp_path):
        # OpenAPI/POST runs write sqlmap's default results-<ts>.csv (same columns),
        # NOT sqlmap_results.txt. A confirmed POST SQLi there must reach the report.
        _seed_sqlmap(tmp_path, ["http://victim.test/api/login,POST,user,BEU,"],
                     name="results-1700000000.csv")
        fs = _sqlmap_findings(load_findings(str(tmp_path)))
        assert len(fs) == 1
        assert "victim.test" in fs[0]["title"]

    def test_bom_prefixed_header_still_parses_confirmed_row(self, tmp_path):
        # A UTF-8 BOM on the header must not hide every confirmed row.
        _seed_sqlmap(tmp_path, ["http://victim.test/i.php?id=1,GET,id,BEUST,"], bom=True)
        assert len(_sqlmap_findings(load_findings(str(tmp_path)))) == 1

    def test_same_param_different_query_values_collapse(self, tmp_path):
        # Same endpoint+parameter probed with different sample values is ONE vuln,
        # not N CRITICALs. Dedup must canonicalize away the query values.
        _seed_sqlmap(tmp_path, [
            "http://victim.test/i.php?id=1,GET,id,BEUST,",
            "http://victim.test/i.php?id=9999,GET,id,BEUST,",
        ])
        assert len(_sqlmap_findings(load_findings(str(tmp_path)))) == 1

    def test_incomplete_row_does_not_drop_good_rows(self, tmp_path):
        # A junk/incomplete row between good rows must be skipped, not abort the file.
        _seed_sqlmap(tmp_path, [
            "http://victim.test/a.php?id=1,GET,id,BEUST,",
            "incomplete_row_with_no_commas",
            "http://victim.test/b.php?cat=2,GET,cat,BU,",
        ])
        urls = {f["url"] for f in _sqlmap_findings(load_findings(str(tmp_path)))}
        assert any("a.php" in u for u in urls) and any("b.php" in u for u in urls)

    def test_multiline_quoted_false_positive_note_still_skipped(self, tmp_path):
        # A quoted Note(s) with an embedded newline whose FP phrase lands on the 2nd
        # physical line must STILL be recognized as a false positive — record-aware
        # parsing + whitespace-normalized matching, else a sqlmap-rejected row would
        # become a CRITICAL false positive.
        d = tmp_path / "sqlmap"
        d.mkdir()
        (d / "sqlmap_results.txt").write_text(
            _SQLMAP_HEADER + "\n"
            'http://victim.test/p.php?id=1,GET,id,BEUST,"false positive or\nunexploitable"\n'
        )
        assert _sqlmap_findings(load_findings(str(tmp_path))) == []

    def test_distinct_query_context_not_merged(self, tmp_path):
        # Same injected param 'id' but different OTHER query context (op=users vs
        # op=orders) are distinct injection contexts and must both be reported —
        # dedup may drop the injected param's value, not the whole query.
        _seed_sqlmap(tmp_path, [
            "http://victim.test/s.php?op=users&id=1,GET,id,BEUST,",
            "http://victim.test/s.php?op=orders&id=1,GET,id,BEUST,",
        ])
        assert len(_sqlmap_findings(load_findings(str(tmp_path)))) == 2


def _seed_email_auth(tmp_path, items):
    d = tmp_path / "email_auth"
    d.mkdir()
    (d / "findings.json").write_text(json.dumps(items))
    return d


def _email_auth_findings(findings):
    return [f for f in findings if f.get("vtype") == "email_auth"]


class TestEmailAuthPerFindingCVSS:
    def test_low_finding_gets_low_band_cvss(self, tmp_path):
        _seed_email_auth(tmp_path, [{"severity": "low", "title": "SPF softfail", "notes": "n"}])
        f = _email_auth_findings(load_findings(str(tmp_path)))[0]
        assert f.get("cvss") == CVSS_DEFAULT["low"], "a LOW finding must not render the template's 5.3"

    def test_info_finding_gets_info_band_cvss(self, tmp_path):
        _seed_email_auth(tmp_path, [{"severity": "info", "title": "No BIMI record", "notes": "n"}])
        f = _email_auth_findings(load_findings(str(tmp_path)))[0]
        assert f.get("cvss") == CVSS_DEFAULT["info"]

    def test_medium_finding_preserves_template_cvss(self, tmp_path):
        # MEDIUM matches the email_auth template severity, so its deliberately-authored
        # 5.3 must be preserved (no needless 5.3->5.0 drift, no split with peer templates).
        _seed_email_auth(tmp_path, [{"severity": "medium", "title": "DMARC missing", "notes": "n"}])
        f = _email_auth_findings(load_findings(str(tmp_path)))[0]
        assert f.get("cvss") == VULN_TEMPLATES["email_auth"]["cvss"]

    def test_high_finding_gets_high_band_cvss(self, tmp_path):
        _seed_email_auth(tmp_path, [{"severity": "high", "title": "Spoofable", "notes": "n"}])
        f = _email_auth_findings(load_findings(str(tmp_path)))[0]
        assert f.get("cvss") == CVSS_DEFAULT["high"]

    def test_explicit_item_cvss_is_honored(self, tmp_path):
        _seed_email_auth(tmp_path, [{"severity": "medium", "title": "DMARC", "notes": "n", "cvss": "6.5"}])
        f = _email_auth_findings(load_findings(str(tmp_path)))[0]
        assert f.get("cvss") == "6.5"
