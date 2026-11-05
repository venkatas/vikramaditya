"""Resume-appended duplicates collapse, but distinct recorded proof stays intact."""
import json

import pytest

import hunt
import reporter


def _write(root, name, data):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else json.dumps(data))
    return path


@pytest.mark.parametrize("repeats", [2, 5])
def test_resume_duplicate_csp_is_one_finding_in_summary_html_and_md(tmp_path, repeats):
    line = "[LOW] Missing Content-Security-Policy (CSP) response header — https://target.invalid/\n"
    source = _write(tmp_path, "misconfig/csp_missing.txt", line * repeats)
    before = source.read_bytes()
    findings = reporter._apply_verification_gating(reporter.load_findings(str(tmp_path)))
    assert len(findings) == hunt._structured_finding_count(str(tmp_path)) == 1
    assert "_consolidated_count" not in findings[0]

    html = reporter.render_html_report(findings, "target.invalid", str(tmp_path), "", "", "VAPT")
    markdown = reporter.render_markdown_report(findings, "target.invalid", str(tmp_path), "", "", "VAPT")
    assert 'id="VN-001"' in html and 'id="VN-002"' not in html
    assert "### VN-001" in markdown and "### VN-002" not in markdown
    assert source.read_bytes() == before


def test_different_csp_observations_same_endpoint_are_preserved(tmp_path):
    _write(tmp_path, "misconfig/csp.txt", "\n".join([
        "[LOW] Missing CSP header https://target.invalid/",
        "[LOW] CSP permits unsafe-inline https://target.invalid/",
    ]) + "\n")
    assert len(reporter.load_findings(str(tmp_path))) == 2
    assert hunt._structured_finding_count(str(tmp_path)) == 2


def test_distinct_parameter_findings_same_endpoint_are_preserved(tmp_path):
    _write(tmp_path, "sqlmap/sqlmap_results.txt",
           "Target URL,Place,Parameter,Technique(s),Note(s)\n"
           "https://target.invalid/search?a=1&b=1,GET,a,U,\n"
           "https://target.invalid/search?a=1&b=1,GET,b,U,\n")
    findings = reporter.load_findings(str(tmp_path))
    assert len(findings) == hunt._structured_finding_count(str(tmp_path)) == 2
    assert "'a'" in findings[0]["detail"] and "'b'" in findings[1]["detail"]


def test_distinct_cve_ids_same_endpoint_are_preserved(tmp_path):
    _write(tmp_path, "cves_custom/hits.txt", "\n".join([
        "[CVE-2025-12345] [http] [high] https://target.invalid/",
        "[CVE-2025-54321] [http] [high] https://target.invalid/",
    ]) + "\n")
    assert len(reporter.load_findings(str(tmp_path))) == 2
    assert hunt._structured_finding_count(str(tmp_path)) == 2


@pytest.mark.parametrize("count", [2, 4])
def test_same_title_url_detail_with_distinct_evidence_is_not_deduped_or_consolidated(tmp_path, count):
    for i in range(count):
        _write(tmp_path, f"finding_{i}.json", {
            "type": "misconfig", "severity": "low", "url": "https://target.invalid/",
            "detail": "Observed security-header issue", "evidence": f"Observation {i}",
            "verification_method": "manual_verified",
        })
    findings = reporter.load_findings(str(tmp_path))
    assert len(findings) == hunt._structured_finding_count(str(tmp_path)) == count
    assert {f["evidence"] for f in findings} == {f"Observation {i}" for i in range(count)}
    assert all("_consolidated_count" not in f for f in findings)


def test_exact_dedupe_compares_case_sensitive_complete_record():
    original = {"vtype": "misconfig", "url": "https://target.invalid/", "title": "Same issue",
                "poc": "Token=AbCd", "evidence": {"status": 200, "headers": ["X-Test: A"]}}
    reordered = dict(reversed(list(original.items())))
    changed_poc = {**original, "poc": "Token=abcd"}
    changed_evidence = {**original, "evidence": {"status": 200, "headers": ["X-Test: B"]}}
    findings = reporter._dedupe_exact_findings([original, reordered, changed_poc, changed_evidence])
    assert findings == [original, changed_poc, changed_evidence]
    assert original == reordered  # No fingerprint or other source mutation.
