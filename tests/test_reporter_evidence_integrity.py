from datetime import datetime as real_datetime
import json

import reporter


def test_source_audit_without_affected_url_is_only_a_review_lead(tmp_path):
    exposure = tmp_path / "exposure"
    exposure.mkdir()
    (exposure / "source_audit.txt").write_text(
        "[HIGH] [SOURCE-AUDIT] source.hardcoded_secret: credential in config "
        "| file=Web.config:11 | evidence=Password=<redacted>\n"
    )

    findings = reporter.load_findings(str(tmp_path))

    assert len(findings) == 1
    finding = findings[0]
    assert finding["url"] == "N/A"
    assert finding["severity"] == "low"
    assert finding["original_severity"] == "high"
    assert finding["verification_method"] == "source_review"
    assert finding["_unconfirmed_lead"] is True
    assert "manual verification required" in finding["title"].lower()
    assert reporter._apply_verification_gating(findings)[0]["severity"] == "low"


def test_email_auth_high_is_capped_and_labelled_as_posture(tmp_path):
    email_auth = tmp_path / "email_auth"
    email_auth.mkdir()
    (email_auth / "findings.json").write_text(json.dumps([{
        "severity": "high",
        "cvss": "8.1",
        "vuln_class": "email_spf",
        "title": "SPF exceeds the DNS lookup limit",
        "endpoint": "dns:spf:example.invalid",
        "result": "confirmed",
        "notes": "The published SPF tree requires 17 DNS lookups.",
    }]))

    findings = reporter.load_findings(str(tmp_path))

    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "medium"
    assert finding["original_severity"] == "high"
    assert finding["cvss"] == reporter.VULN_TEMPLATES["email_auth"]["cvss"]
    assert finding["finding_kind"] == "posture"
    assert finding["verification_method"] == "configuration_observed"
    assert finding["title"].startswith("Email security posture: ")
    assert "No spoofing or delivery exploit was performed or confirmed" in finding["poc"]
    assert reporter._apply_verification_gating(findings)[0]["severity"] == "medium"


class _FrozenDatetime(real_datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 9, 4, 15, 30, 0, tzinfo=tz)


def test_reports_separate_old_session_date_from_generation_date(tmp_path, monkeypatch):
    report_dir = (
        tmp_path / "reports" / "example.invalid" / "sessions" /
        "20260823_101432_2e65"
    )
    report_dir.mkdir(parents=True)
    monkeypatch.setattr(reporter, "datetime", _FrozenDatetime)

    html = reporter.render_html_report(
        [], "example.invalid", str(report_dir), "Client", "Consultant", "VAPT"
    )
    markdown = reporter.render_markdown_report(
        [], "example.invalid", str(report_dir), "Client", "Consultant", "VAPT"
    )

    assert "Assessment session date</td>" in html
    assert "23 August 2026" in html
    assert "Report generated</td>" in html
    assert "04 September 2026" in html
    assert "Report generation does not refresh the session evidence" in html
    assert "**Assessment session date:** 23 August 2026" in markdown
    assert "**Report generated:** 04 September 2026" in markdown


def test_report_does_not_invent_session_date_when_path_has_no_session_id(
        tmp_path, monkeypatch):
    monkeypatch.setattr(reporter, "datetime", _FrozenDatetime)

    markdown = reporter.render_markdown_report(
        [], "example.invalid", str(tmp_path / "reports"), "", "", "VAPT"
    )

    assert "**Assessment session date:** Not recorded" in markdown
    assert "**Report generated:** 04 September 2026" in markdown
