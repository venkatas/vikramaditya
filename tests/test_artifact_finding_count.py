"""Brain artifact summaries must count findings, never control metadata/raw leads."""
import json

import hunt


def _write(root, name, data):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else json.dumps(data))
    return path


def test_metadata_and_duplicate_csp_lines_do_not_inflate_findings(tmp_path):
    finding = "[LOW] Missing Content-Security-Policy (CSP) response header — https://target.invalid/\n"
    _write(tmp_path, "misconfig/csp_missing.txt", finding * 2)
    _write(tmp_path, "coverage.json", [{"tool": "browser", "reason": "blocked"}])
    _write(tmp_path, "phase_manifest.json", {"version": 1, "phases": {"RECON": {"status": "complete"}}})
    _write(tmp_path, "coverage_degraded.json", {"findings": [], "status": "incomplete", "counts": 26})
    _write(tmp_path, "misconfig/guarded_pages.json", [{"url": "https://target.invalid/", "error": "blocked"}])
    _write(tmp_path, "misconfig/blocked_requests.jsonl", '{"url":"https://external.invalid/"}\n')
    _write(tmp_path, "rce/summary.txt", "Confirmed RCE: 0\nJava targets: 1\n")
    _write(tmp_path, "manual_review/candidates.txt", "https://target.invalid/?id=1\n")

    assert hunt._structured_finding_count(str(tmp_path)) == 1
    summary = hunt._artifact_summary({"findings": str(tmp_path)})
    assert "classified_findings=1" in summary
    assert "includes metadata/raw candidates, not findings" in summary


def test_arbitrary_root_json_and_raw_lines_are_not_findings(tmp_path):
    _write(tmp_path, "unknown.json", {"findings": [{"a": 1}, {"b": 2}], "status": "ok"})
    _write(tmp_path, "result.jsonl", '{"status":"success"}\n{"reason":"timeout"}\n')
    _write(tmp_path, "sqli.txt", "INJ https://target.invalid/?id=1\n")
    _write(tmp_path, "notes.txt", "3 possible issues\nArjun complete\n")
    assert hunt._structured_finding_count(str(tmp_path)) == 0
    assert "raw candidates" in hunt._artifact_summary({"findings": str(tmp_path)})


def test_scanner_candidate_model_and_dast_leads_are_not_counted(tmp_path):
    _write(tmp_path, "sqli/timebased_candidates.txt", "[SQLI-CANDIDATE] https://target.invalid/?id=1\n")
    _write(tmp_path, "rce/raw.txt", "Possible issue at https://target.invalid/run\n")
    _write(tmp_path, "misconfig/model.txt", "[MODEL CLAIM — verify PoC] [LOW] issue https://target.invalid/\n")
    _write(tmp_path, "misconfig/unverified.txt", "[UNVERIFIED] [LOW] issue https://target.invalid/\n")
    _write(tmp_path, "dast/hits.txt", "[blind-sql] [http] [high] https://target.invalid/?id=1\n")
    _write(tmp_path, "cves/cve_database_matches.json", [{"cve_id": "CVE-2025-12345", "severity": "critical"}])
    _write(tmp_path, "finding_pending.json", {
        "type": "idor", "severity": "low", "url": "https://target.invalid/users/2",
        "detail": "heuristic only", "verification_method": "unverified",
    })
    assert hunt._structured_finding_count(str(tmp_path)) == 0


def test_supported_proof_bearing_text_and_json_formats_remain_counted(tmp_path):
    _write(tmp_path, "sqli/confirmed.txt", "[SQLI-POC-VERIFIED] https://target.invalid/?id=1\n")
    _write(tmp_path, "cves_custom/hits.txt", "[test-template] [http] [medium] https://target.invalid/config\n")
    _write(tmp_path, "finding_verified.json", {
        "type": "idor", "severity": "high", "url": "https://target.invalid/users/2",
        "detail": "other user's record returned", "verification_method": "manual_verified",
        "evidence": "redacted second user record",
    })
    _write(tmp_path, "email_auth/findings.json", [{
        "severity": "medium", "vuln_class": "dmarc", "area": "DNS",
        "result": "missing", "endpoint": "target.invalid", "notes": "No DMARC policy observed",
    }])
    _write(tmp_path, "cves/cve_database_matches.json", [{
        "cve_id": "CVE-2025-12345", "severity": "high", "confirmed": True,
    }])
    _write(tmp_path, "sqlmap/sqlmap_results.txt",
           "Target URL,Place,Parameter,Technique(s),Note(s)\n"
           "https://target.invalid/search?q=1,GET,q,U,\n")
    assert hunt._structured_finding_count(str(tmp_path)) == 6


def test_dedupe_keeps_distinct_confirmed_parameters_at_same_endpoint(tmp_path):
    _write(tmp_path, "sqlmap/sqlmap_results.txt",
           "Target URL,Place,Parameter,Technique(s),Note(s)\n"
           "https://target.invalid/search?a=1&b=1,GET,a,U,\n"
           "https://target.invalid/search?a=1&b=1,GET,b,U,\n")
    assert hunt._structured_finding_count(str(tmp_path)) == 2


def test_dedupe_collapses_duplicate_flat_verified_findings(tmp_path):
    finding = {"type": "xss", "severity": "high", "url": "https://target.invalid/search?q=1",
               "detail": "verified execution", "verification_method": "manual_verified"}
    _write(tmp_path, "finding_one.json", finding)
    _write(tmp_path, "finding_two.json", finding)
    assert hunt._structured_finding_count(str(tmp_path)) == 1


def test_count_does_not_modify_any_input_artifacts(tmp_path):
    _write(tmp_path, "misconfig/csp.txt", "[LOW] Missing CSP https://target.invalid/\n")
    _write(tmp_path, "coverage.json", [{"tool": "browser", "reason": "blocked"}])
    before = {str(path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    assert hunt._structured_finding_count(str(tmp_path)) == 1
    assert before == {str(path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}


def test_parser_failure_summary_is_unknown_not_clean_zero(tmp_path, monkeypatch):
    def fail(path):
        raise ValueError("unsupported/corrupt parser input")
    monkeypatch.setattr(hunt, "_structured_finding_count", fail)
    summary = hunt._artifact_summary({"findings": str(tmp_path)})
    assert "classified_findings=unavailable (report parser failed)" in summary
    assert "classified_findings=0" not in summary


def test_missing_findings_directory_is_zero(tmp_path):
    assert hunt._structured_finding_count(str(tmp_path / "not-created")) == 0
