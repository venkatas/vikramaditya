"""reporter.load_findings must ingest CONFIRMED findings that engines write into
finding subdirs the reporter previously did not map — the friends full-tool
review found real CRITICALs vanishing from the client report because their dir
was neither in SUBDIR_VTYPE nor read by a dedicated loader (only a WARNING).

  - nextjs_bypass/  : whitebox/nextjs_bypass.py writes a CONFIRMED CVE-2025-29927
                      middleware auth bypass as `[CRITICAL] ... url`.
  - sqlmap_reqfile/ : run_sqlmap_request_file (--request-file path) writes a
                      confirmed sqlmap results CSV (--results-file=results.txt).
  - sqlmap_post/    : run_sqlmap_targeted's POST pass writes a confirmed sqlmap
                      results CSV.

Reporter Method 1f previously read only findings/sqlmap/, so the reqfile/post
CSVs were dropped. All three must now surface at their real (critical) severity.
All test data is SYNTHETIC (example.invalid).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import reporter  # noqa: E402


def _sevs(tmp_path):
    return [str(f.get("severity", "")).lower()
            for f in reporter.load_findings(str(tmp_path)) if isinstance(f, dict)]


def test_nextjs_bypass_confirmed_is_ingested(tmp_path):
    d = tmp_path / "nextjs_bypass"
    d.mkdir()
    (d / "findings.txt").write_text(
        "[CRITICAL] CVE-2025-29927: middleware bypass on /admin "
        "https://t.example.invalid/admin\n")
    assert "critical" in _sevs(tmp_path), (
        "confirmed Next.js middleware auth bypass (CVE-2025-29927) was dropped "
        "from the report")


# A minimal, valid sqlmap results-file CSV (the exact columns Method 1f keys on).
_SQLMAP_CSV = (
    "Target URL,Place,Parameter,Technique(s),Note(s)\n"
    "https://t.example.invalid/p?id=1,GET,id,\"boolean-based blind, UNION query\",\n"
)


def test_sqlmap_reqfile_confirmed_is_ingested(tmp_path):
    d = tmp_path / "sqlmap_reqfile"
    d.mkdir()
    # run_sqlmap_request_file writes --results-file=<dir>/results.txt (a CSV).
    (d / "results.txt").write_text(_SQLMAP_CSV)
    assert "critical" in _sevs(tmp_path), (
        "sqlmap-confirmed SQLi from the --request-file path was dropped")


def test_sqlmap_post_confirmed_is_ingested(tmp_path):
    d = tmp_path / "sqlmap_post"
    d.mkdir()
    (d / "results-t.example.invalid.csv").write_text(_SQLMAP_CSV)
    assert "critical" in _sevs(tmp_path), (
        "sqlmap-confirmed SQLi from the POST path was dropped")


def test_unmapped_reqfile_post_do_not_warn(tmp_path, capsys):
    """Once handled by Method 1f, sqlmap_reqfile/ and sqlmap_post/ must not trip
    the 'subdir not in SUBDIR_VTYPE — contents IGNORED' warning."""
    for sub in ("sqlmap_reqfile", "sqlmap_post"):
        (tmp_path / sub).mkdir()
        (tmp_path / sub / "results.txt").write_text(_SQLMAP_CSV)
    reporter.load_findings(str(tmp_path))
    warned = capsys.readouterr().out
    assert "is not " not in warned or "sqlmap_reqfile" not in warned, warned
    assert "sqlmap_post" not in warned or "IGNORED" not in warned, warned
