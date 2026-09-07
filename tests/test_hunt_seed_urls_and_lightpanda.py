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


def test_scope_seed_urls_uses_exact_targets_file_allowlist(tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("api.allowed.invalid\nassets.allowed.invalid:8443\n")
    allowed, rejected = hunt._scope_seed_urls(
        [
            "https://api.allowed.invalid/v1/health",
            "https://assets.allowed.invalid:8443/app.js",
            "https://sub.api.allowed.invalid/v1/escape",
            "https://outside.invalid/api/data",
        ],
        "allowed.invalid",
        scope_lock=True,
        targets_file=str(targets),
    )
    assert allowed == [
        "https://api.allowed.invalid/v1/health",
        "https://assets.allowed.invalid:8443/app.js",
    ]
    assert rejected == [
        "https://sub.api.allowed.invalid/v1/escape",
        "https://outside.invalid/api/data",
    ]


def test_seed_urls_populate_canonical_recon_corpus(tmp_path):
    recon = str(tmp_path / "recon")
    seeds = [
        "https://api.allowed.invalid/api/v1/items?id=1",
        "https://abc.execute-api.ap-south-1.amazonaws.com/default/task",
        "https://assets.allowed.invalid/_next/static/chunks/app.js",
        "https://allowed.invalid/dashboard",
    ]
    counts = hunt._seed_urls_into_recon_corpus(recon, seeds)
    assert counts == {
        "urls/all.txt": 4,
        "live/urls.txt": 4,
        "urls/api_endpoints.txt": 2,
        "urls/js_files.txt": 1,
        "urls/with_params.txt": 4,
    }

    def lines(relpath):
        return (tmp_path / "recon" / relpath).read_text().splitlines()

    assert lines("urls/all.txt") == seeds
    assert lines("live/urls.txt") == seeds
    assert lines("urls/api_endpoints.txt") == seeds[:2]
    assert lines("urls/js_files.txt") == [seeds[2]]
    assert hunt._seed_urls_into_recon_corpus(recon, seeds) == {
        "urls/all.txt": 0,
        "live/urls.txt": 0,
        "urls/api_endpoints.txt": 0,
        "urls/js_files.txt": 0,
        "urls/with_params.txt": 0,
    }


def test_seed_urls_without_cookie_do_not_crash_main(tmp_path, monkeypatch):
    seeds = tmp_path / "seeds.txt"
    seeds.write_text("https://allowed.invalid/api/health\n")
    monkeypatch.setattr(
        sys,
        "argv",
        ["hunt.py", "--status", "--no-brain", "--seed-urls", str(seeds)],
    )
    monkeypatch.setattr(hunt, "show_status", lambda: None)
    hunt.main()


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
