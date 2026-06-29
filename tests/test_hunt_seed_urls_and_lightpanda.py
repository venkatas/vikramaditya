"""hunt --seed-urls helpers + lightpanda --header capability probe.

--seed-urls is the fix for WebForms/SPA apps whose GET endpoints the link-crawl can't
discover; _lightpanda_supports_header gates around a build that rejects --header. Synthetic.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import hunt  # noqa: E402


def test_parse_seed_urls_comma_list():
    s = hunt._parse_seed_urls("https://a.invalid/x?id=1, https://a.invalid/y?n=2 , not-a-url")
    assert s == ["https://a.invalid/x?id=1", "https://a.invalid/y?n=2"]


def test_parse_seed_urls_file(tmp_path):
    f = tmp_path / "seeds.txt"
    f.write_text("https://a.invalid/x?id=1\n# comment\nhttps://a.invalid/x?id=1\nhttps://b.invalid/z?q=3\n")
    s = hunt._parse_seed_urls(str(f))
    assert s == ["https://a.invalid/x?id=1", "https://b.invalid/z?q=3"]   # deduped, comment dropped


def test_seed_urls_into_recon_writes_and_dedups(tmp_path):
    recon = str(tmp_path / "recon")
    n1 = hunt._seed_urls_into_recon(recon, ["https://a.invalid/x?id=1", "https://a.invalid/y?n=2"])
    assert n1 == 2
    wp = os.path.join(recon, "urls", "with_params.txt")
    assert os.path.isfile(wp)
    # re-seed: 1 new, 1 dup
    n2 = hunt._seed_urls_into_recon(recon, ["https://a.invalid/x?id=1", "https://a.invalid/z?k=9"])
    assert n2 == 1
    lines = [l.strip() for l in open(wp) if l.strip()]
    assert lines.count("https://a.invalid/x?id=1") == 1 and len(lines) == 3


def test_lightpanda_header_probe(monkeypatch):
    monkeypatch.setattr(hunt, "_lightpanda_bin", lambda: "/fake/lp")
    monkeypatch.setattr(hunt, "_LP_HEADER_OK", None)
    monkeypatch.setattr(hunt, "run_capture",
                        lambda *a, **k: {"stdout": "options: --log_level --timeout  URL", "stderr": "", "returncode": 0, "timed_out": False})
    assert hunt._lightpanda_supports_header() is False
    monkeypatch.setattr(hunt, "_LP_HEADER_OK", None)
    monkeypatch.setattr(hunt, "run_capture",
                        lambda *a, **k: {"stdout": "options: --header <h>  --log_level URL", "stderr": "", "returncode": 0, "timed_out": False})
    assert hunt._lightpanda_supports_header() is True
