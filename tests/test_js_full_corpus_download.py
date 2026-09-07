import inspect
from pathlib import Path

import hunt


def test_download_js_corpus_fetches_each_unique_url_once(tmp_path, monkeypatch):
    urls = tmp_path / "js_urls.txt"
    urls.write_text("https://example.test/a.js\nhttps://example.test/b.js\nhttps://example.test/a.js\n")
    calls = []

    def fake_run_capture(spec, **_kwargs):
        calls.append(spec[-1])
        destination = Path(spec[spec.index("-o") + 1])
        destination.write_text(f"console.log({spec[-1]!r});")
        return {"stdout": "", "stderr": "", "returncode": 0, "timed_out": False}

    monkeypatch.setattr(hunt, "run_capture", fake_run_capture)
    requested, downloaded = hunt._download_js_corpus(str(urls), str(tmp_path / "downloaded"))

    assert (requested, downloaded) == (2, 2)
    assert sorted(calls) == ["https://example.test/a.js", "https://example.test/b.js"]
    manifest = (tmp_path / "downloaded" / "manifest.tsv").read_text().splitlines()
    assert manifest[0] == "file\turl\treturncode\ttimed_out\tbytes\tsha256"
    assert len(manifest) == 3
    assert len(list((tmp_path / "downloaded").glob("*.js"))) == 2


def test_js_analyzers_use_manifest_proven_local_corpus_without_shell_pipelines():
    source = inspect.getsource(hunt.run_js_analysis)
    assert "_download_js_corpus(js_scan_file, dl_dir)" in source
    assert "_current_js_manifest_files(dl_dir)" in source
    assert "_run_jsluice_files(" in source
    assert "_run_secretfinder_files(" in source
    assert "_run_trufflehog_files(" in source
    assert "find " not in source
    assert "xargs " not in source
