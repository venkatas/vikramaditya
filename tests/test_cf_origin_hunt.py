"""cf_origin_hunt.py — Cloudflare/CDN origin discovery (WAF bypass).

Validates the logic that found the real origin (13.202.128.173 via a non-proxied
sibling) without needing the network: IP classification (incl. the IPv6-Cloudflare
miss that bit the first attempt), origin-candidate mining, and the Host-header
verification (incl. the `_is_cf_error` over-broadness that false-rejected the real
origin because its HTML referenced 'cloudflare').
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import cf_origin_hunt as cf  # noqa: E402


def test_is_cloudflare_ipv4():
    assert cf.is_cloudflare("104.26.3.120") is True       # CF
    assert cf.is_cloudflare("172.67.75.3") is True        # CF
    assert cf.is_cloudflare("13.202.128.173") is False    # AWS origin (the real origin)
    assert cf.is_cloudflare("3.111.184.255") is False     # AWS


def test_is_cloudflare_ipv6():
    # the bug in the first attempt: IPv6 CF addresses were classified as "direct"
    assert cf.is_cloudflare("2606:4700:99e9:364f:afd:0:a263:c09") is True
    assert cf.is_cloudflare("2400:cb00::1") is True
    assert cf.is_cloudflare("2404:6800:4000:1006::79") is False  # Google v6, not CF


def test_origin_candidate_excludes_cf_mail_private():
    assert cf._is_origin_candidate("13.202.128.173") is True     # real origin
    assert cf._is_origin_candidate("104.26.3.120") is False       # Cloudflare
    assert cf._is_origin_candidate("142.250.134.121") is False    # Google mail
    assert cf._is_origin_candidate("10.0.0.5") is False           # private
    assert cf._is_origin_candidate("2606:4700::1") is False       # CF v6


def test_classify(monkeypatch):
    table = {
        "app.example.edu": ["104.26.3.120", "2606:4700::1"],   # all CF -> proxied
        "medical.example.edu": ["13.202.128.173"],              # direct -> leaks origin
        "mail.example.edu": ["142.250.134.121"],                # google -> not origin
    }
    monkeypatch.setattr(cf, "resolve", lambda h: table.get(h, []))
    out = cf.classify(table.keys())
    assert out["app.example.edu"]["proxied"] is True
    assert out["medical.example.edu"]["proxied"] is False
    assert out["medical.example.edu"]["origin_ips"] == ["13.202.128.173"]
    assert out["mail.example.edu"]["origin_ips"] == []           # google excluded


def test_cf_error_not_overbroad():
    # a real origin page that merely references cloudflare assets must NOT be flagged
    legit = '<html><head><title>Acme</title><script src="https://cdn.cloudflare.com/x.js"></script></head>'
    assert cf._is_cf_error(legit) is False
    # genuine challenge / block pages ARE flagged
    assert cf._is_cf_error("<title>Attention Required! | Cloudflare</title>") is True
    assert cf._is_cf_error("Sorry, you have been blocked ... Ray ID: 1a2b") is True
    assert cf._is_cf_error("Just a moment...") is True


def test_verify_origin_confirms_real_site(monkeypatch):
    # origin IP serves a real 200 page with a title -> confirmed bypass
    monkeypatch.setattr(cf, "_fetch",
                        lambda ip, host, scheme="https", timeout=10:
                        (200, "<html><head><title>Acme Bank Portal</title></head><body>..</body>"))
    v = cf.verify_origin("13.202.128.173", "app.example.edu", expected_title=None)
    assert v["matched"] is True and v["status"] == 200


def test_verify_origin_rejects_cf_challenge(monkeypatch):
    monkeypatch.setattr(cf, "_fetch",
                        lambda ip, host, scheme="https", timeout=10:
                        (403, "<title>Attention Required! | Cloudflare</title>Just a moment..."))
    v = cf.verify_origin("104.26.3.120", "app.example.edu")
    assert v["matched"] is False


def test_hunt_end_to_end(monkeypatch):
    table = {
        "app.example.edu": ["104.26.3.120"],
        "medical.example.edu": ["13.202.128.173"],
    }
    monkeypatch.setattr(cf, "resolve", lambda h: table.get(h, []))
    # _fronted_baseline now takes a timeout arg (concurrent/deadline-bounded probing)
    monkeypatch.setattr(cf, "_fronted_baseline", lambda host, timeout=None: (403, None))

    def fake_fetch(ip, host, scheme="https", timeout=10):
        if ip == "13.202.128.173":
            return 200, "<html><head><title>Acme Bank</title></head>"   # origin
        return None, ""
    monkeypatch.setattr(cf, "_fetch", fake_fetch)

    res = cf.hunt("app.example.edu", table.keys())
    assert res["bypass"] is True
    assert res["verified"][0]["ip"] == "13.202.128.173"
    assert res["is_cloudflare"] is True
    assert res["deadline_hit"] is False   # fast mocked probes finish well inside any deadline


def test_hunt_writes_result_under_deadline(monkeypatch):
    # Regression for a real-run gap: sequential slow probes overran recon.sh's
    # timeout wrapper and the module was killed with ZERO output. With the concurrent
    # + deadline-bounded probe phase, hunt() must RETURN a usable result (not hang),
    # marking deadline_hit when the per-candidate probes cannot finish in time.
    table = {
        "app.example.edu": ["104.26.3.120"],          # CF-fronted target
        "a.example.edu": ["13.202.128.173"],          # direct AWS siblings -> origin candidates
        "b.example.edu": ["3.111.184.255"],           # (real routable IPs, pass the candidate gate)
    }
    monkeypatch.setattr(cf, "resolve", lambda h: table.get(h, []))
    monkeypatch.setattr(cf, "_fronted_baseline", lambda host, timeout=None: (403, None))

    def slow_fetch(ip, host, scheme="https", timeout=10):
        time.sleep(1)            # each probe is slower than the deadline below
        return None, ""
    monkeypatch.setattr(cf, "_fetch", slow_fetch)

    res = cf.hunt("app.example.edu", table.keys(), deadline=0.2)
    assert res["bypass"] is False          # nothing verified
    assert res["deadline_hit"] is True     # but it returned a result instead of hanging
    assert isinstance(res["origin_candidates"], list) and res["origin_candidates"]


def test_recon_sh_wires_the_origin_hunt():
    src = open(os.path.join(os.path.dirname(__file__), "..", "recon.sh"), encoding="utf-8").read()
    assert "cf_origin_hunt.py" in src, "recon.sh does not invoke cf_origin_hunt"
    assert "cf_origin.json" in src and "CF BYPASS" in src
