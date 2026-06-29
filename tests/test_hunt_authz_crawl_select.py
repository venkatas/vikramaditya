"""hunt._authz_select_pages / _authz_select_object_refs — feed the authz audit from the
crawl (urls/all.txt -> PII page-scan; urls/with_params.txt -> IDOR id enumeration).

Pure file-reading selection logic (no network). SYNTHETIC data only.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import hunt  # noqa: E402


def test_select_pages_returns_distinct_same_host_paths(tmp_path):
    f = tmp_path / "all.txt"
    f.write_text("\n".join([
        "https://app.invalid/Home",
        "https://app.invalid/ClientList?page=1",
        "https://other.invalid/Skip",          # different host -> excluded
        "https://app.invalid/Home",            # duplicate path -> deduped
    ]))
    pages = hunt._authz_select_pages(str(f), "app.invalid", limit=10)
    assert "/Home" in pages and "/ClientList" in pages
    assert all("other.invalid" not in p for p in pages)
    assert pages.count("/Home") == 1


def test_select_pages_respects_limit(tmp_path):
    f = tmp_path / "all.txt"
    f.write_text("\n".join(f"https://app.invalid/p{i}" for i in range(100)))
    assert len(hunt._authz_select_pages(str(f), "app.invalid", limit=5)) == 5


def test_select_pages_missing_file_is_empty(tmp_path):
    assert hunt._authz_select_pages(str(tmp_path / "nope.txt"), "app.invalid") == []


def test_select_object_refs_mines_numeric_id_params(tmp_path):
    f = tmp_path / "wp.txt"
    f.write_text("\n".join([
        "https://app.invalid/RecordDetails?recordId=83",
        "https://app.invalid/RecordDetails?recordId=84",
        "https://app.invalid/Search?q=hello",      # non-id param -> not enumerated
        "https://app.invalid/Fee?feeRecordId=5",
    ]))
    refs = hunt._authz_select_object_refs(str(f), "app.invalid", per_param=3)
    assert "/RecordDetails?recordId=1" in refs
    assert "/RecordDetails?recordId=3" in refs
    assert any(r.startswith("/Fee?feeRecordId=") for r in refs)
    assert all("q=" not in r for r in refs)


def test_select_object_refs_missing_file_is_empty(tmp_path):
    assert hunt._authz_select_object_refs(str(tmp_path / "nope.txt"), "app.invalid") == []
