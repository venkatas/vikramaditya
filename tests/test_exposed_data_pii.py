"""Exposed-directory PII check: when recon flags an open dir (/db/, /uploads/), actually
FETCH its listing/content and check for exposed PII + downloadable DB backups — not just
flag the path. Reuses the strong PII regex from cred_blast_radius. (gap surfaced on a live engagement)
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import exposed_data_pii as edp  # noqa: E402


# ── directory-listing detection ───────────────────────────────────────────────

def test_detects_apache_and_nginx_listing():
    assert edp.is_dir_listing("<title>Index of /db</title><h1>Index of /db</h1>")
    assert edp.is_dir_listing("<html><head><title>Directory listing for /uploads/</title>")
    assert not edp.is_dir_listing("<html><body>Welcome to Mumbai University</body></html>")


def test_extract_listing_files():
    html = (
        '<h1>Index of /db</h1><pre>'
        '<a href="students_aadhaar.csv">students_aadhaar.csv</a>'
        '<a href="backup_2024.sql">backup_2024.sql</a>'
        '<a href="../">Parent Directory</a>'
        '<a href="logo.png">logo.png</a></pre>'
    )
    files = edp.extract_listing_files(html)
    assert "students_aadhaar.csv" in files
    assert "backup_2024.sql" in files
    assert "logo.png" in files
    assert "../" not in files and "Parent Directory" not in files  # nav links dropped


# ── PII + backup classification ───────────────────────────────────────────────

def test_scan_for_pii_flags_strong_indicators_only():
    names = ["students_aadhaar.csv", "pan_cards.xlsx", "salary_2024.xls",
             "index.html", "logo.png", "style.css"]
    hits = edp.scan_for_pii(names)
    flagged = {h["item"] for h in hits}
    assert "students_aadhaar.csv" in flagged and "pan_cards.xlsx" in flagged and "salary_2024.xls" in flagged
    assert "index.html" not in flagged and "logo.png" not in flagged  # no generic false positives


def test_classify_backups():
    names = ["backup_2024.sql", "db.dump", "site.bak", "archive.tar.gz", "data.csv", "page.html"]
    backups = set(edp.classify_backups(names))
    assert {"backup_2024.sql", "db.dump", "site.bak", "archive.tar.gz"} <= backups
    assert "page.html" not in backups


# ── end-to-end assessment of one exposed URL (fetch mocked) ───────────────────

def test_assess_exposed_url_critical_on_pii_listing(monkeypatch):
    listing = ('<h1>Index of /db</h1>'
               '<a href="students_aadhaar.csv">x</a><a href="payroll.sql">y</a>')
    monkeypatch.setattr(edp, "_fetch", lambda url, timeout=15: (200, listing))
    r = edp.assess_exposed_url("http://victim.example/db/")
    assert r["is_listing"] is True
    assert r["pii_indicators"]            # found aadhaar/payroll
    assert r["backups"]                   # payroll.sql
    assert r["severity"] == "critical"    # open listing + PII + backup


def test_assess_exposed_url_low_when_no_pii(monkeypatch):
    monkeypatch.setattr(edp, "_fetch", lambda url, timeout=15: (200, "<h1>Index of /img</h1><a href='logo.png'>x</a>"))
    r = edp.assess_exposed_url("http://victim.example/img/")
    assert r["is_listing"] is True
    assert not r["pii_indicators"]
    assert r["severity"] in ("low", "info")


def test_assess_unreachable_is_graceful(monkeypatch):
    monkeypatch.setattr(edp, "_fetch", lambda url, timeout=15: (0, ""))
    r = edp.assess_exposed_url("http://victim.example/db/")
    assert r["severity"] in ("info", "low") and r["pii_indicators"] == []


# ── hunt.py wiring: write CRITICAL/HIGH exposed-data findings for the reporter ──

def test_hunt_writes_exposed_data_pii_findings(tmp_path):
    import hunt
    results = [
        {"url": "http://x/db/", "severity": "critical",
         "backups": ["dump.sql", "finance_db.sql"],
         "pii_indicators": [{"item": "students_aadhaar.csv", "indicator": "aadhaar"},
                            {"item": "payroll.xls", "indicator": "payroll"}]},
        {"url": "http://x/old/", "severity": "high",
         "backups": [], "pii_indicators": [{"item": "emails.csv", "indicator": "email"}]},
        {"url": "http://x/img/", "severity": "low", "backups": [], "pii_indicators": []},
        {"url": "http://x/empty/", "severity": "info", "backups": [], "pii_indicators": []},
    ]
    findings_dir = tmp_path / "findings"
    n = hunt._write_exposed_data_pii_findings(results, str(findings_dir))
    assert n == 2, "only critical+high are written"
    out = findings_dir / "exposure" / "exposed_data_pii.txt"
    assert out.is_file()
    text = out.read_text()
    assert "[CRITICAL] http://x/db/" in text
    assert "dump.sql" in text and "finance_db.sql" in text
    assert "aadhaar" in text and "payroll" in text
    assert "[HIGH] http://x/old/" in text
    assert "/img/" not in text and "/empty/" not in text  # low/info skipped


def test_hunt_write_exposed_data_pii_noop_when_clean(tmp_path):
    import hunt
    results = [{"url": "http://x/img/", "severity": "low", "backups": [], "pii_indicators": []}]
    n = hunt._write_exposed_data_pii_findings(results, str(tmp_path / "findings"))
    assert n == 0
    assert not (tmp_path / "findings" / "exposure" / "exposed_data_pii.txt").exists()
