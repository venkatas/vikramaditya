"""cf_origin_hunt.py — Cloudflare/CDN origin discovery (WAF bypass).

Validates the logic that found the KIMS origin (13.202.128.173 via a non-proxied
sibling) without needing the network: IP classification (incl. the IPv6-Cloudflare
miss that bit the first attempt), origin-candidate mining, and the Host-header
verification (incl. the `_is_cf_error` over-broadness that false-rejected the real
origin because its HTML referenced 'cloudflare').
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import cf_origin_hunt as cf  # noqa: E402


def test_is_cloudflare_ipv4():
    assert cf.is_cloudflare("104.26.3.120") is True       # CF
    assert cf.is_cloudflare("172.67.75.3") is True        # CF
    assert cf.is_cloudflare("13.202.128.173") is False    # AWS origin (the KIMS origin)
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
        "kims.example.edu": ["104.26.3.120", "2606:4700::1"],   # all CF -> proxied
        "medical.example.edu": ["13.202.128.173"],              # direct -> leaks origin
        "mail.example.edu": ["142.250.134.121"],                # google -> not origin
    }
    monkeypatch.setattr(cf, "resolve", lambda h: table.get(h, []))
    out = cf.classify(table.keys())
    assert out["kims.example.edu"]["proxied"] is True
    assert out["medical.example.edu"]["proxied"] is False
    assert out["medical.example.edu"]["origin_ips"] == ["13.202.128.173"]
    assert out["mail.example.edu"]["origin_ips"] == []           # google excluded


def test_cf_error_not_overbroad():
    # a real origin page that merely references cloudflare assets must NOT be flagged
    legit = '<html><head><title>KIMS</title><script src="https://cdn.cloudflare.com/x.js"></script></head>'
    assert cf._is_cf_error(legit) is False
    # genuine challenge / block pages ARE flagged
    assert cf._is_cf_error("<title>Attention Required! | Cloudflare</title>") is True
    assert cf._is_cf_error("Sorry, you have been blocked ... Ray ID: 1a2b") is True
    assert cf._is_cf_error("Just a moment...") is True


def test_verify_origin_confirms_real_site(monkeypatch):
    # origin IP serves a real 200 page with a title -> confirmed bypass
    monkeypatch.setattr(cf, "_fetch",
                        lambda ip, host, scheme="https", timeout=10:
                        (200, "<html><head><title>KIMS - Kalinga Institute</title></head><body>..</body>"))
    v = cf.verify_origin("13.202.128.173", "kims.example.edu", expected_title=None)
    assert v["matched"] is True and v["status"] == 200


def test_verify_origin_rejects_cf_challenge(monkeypatch):
    monkeypatch.setattr(cf, "_fetch",
                        lambda ip, host, scheme="https", timeout=10:
                        (403, "<title>Attention Required! | Cloudflare</title>Just a moment..."))
    v = cf.verify_origin("104.26.3.120", "kims.example.edu")
    assert v["matched"] is False


def test_hunt_end_to_end(monkeypatch):
    table = {
        "kims.example.edu": ["104.26.3.120"],
        "medical.example.edu": ["13.202.128.173"],
    }
    monkeypatch.setattr(cf, "resolve", lambda h: table.get(h, []))
    monkeypatch.setattr(cf, "_fronted_baseline", lambda host: (403, None))  # CF blocks the public host

    def fake_fetch(ip, host, scheme="https", timeout=10):
        if ip == "13.202.128.173":
            return 200, "<html><head><title>KIMS - Kalinga</title></head>"   # origin
        return None, ""
    monkeypatch.setattr(cf, "_fetch", fake_fetch)

    res = cf.hunt("kims.example.edu", table.keys())
    assert res["bypass"] is True
    assert res["verified"][0]["ip"] == "13.202.128.173"
    assert res["is_cloudflare"] is True


def test_recon_sh_wires_the_origin_hunt():
    src = open(os.path.join(os.path.dirname(__file__), "..", "recon.sh"), encoding="utf-8").read()
    assert "cf_origin_hunt.py" in src, "recon.sh does not invoke cf_origin_hunt"
    assert "cf_origin.json" in src and "CF BYPASS" in src
