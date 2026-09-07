"""Regression tests for the fingerprint stage's network safety boundary."""

from types import SimpleNamespace

import requests

import vikramaditya


def _response(status=200, text="", headers=None):
    return SimpleNamespace(status_code=status, text=text, headers=headers or {})


def test_fingerprint_never_posts_blank_login_attempts(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        if url == "https://app.example.test":
            return _response(text="plain home page")
        return _response(status=404)

    def forbidden_post(*args, **kwargs):
        raise AssertionError("fingerprinting must not send POST requests")

    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setattr(requests, "post", forbidden_post)

    result = vikramaditya.fingerprint_webapp("https://app.example.test")

    assert result["login_detected"] is False
    assert calls
    assert all(url.startswith("https://app.example.test") for url, _ in calls)


def test_cross_origin_api_from_javascript_is_recorded_but_not_probed(monkeypatch):
    calls = []
    html = '<script src="/assets/app-12345678.js"></script>'
    js = 'const cfg = { baseURL: "https://outside.invalid/v1" };'

    def fake_get(url, **kwargs):
        calls.append(url)
        if url == "https://app.example.test":
            return _response(text=html)
        if url == "https://app.example.test/assets/app-12345678.js":
            return _response(text=js)
        return _response(status=404)

    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setattr(
        requests,
        "post",
        lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("fingerprinting must not send POST requests")
        ),
    )

    result = vikramaditya.fingerprint_webapp("https://app.example.test")

    assert "https://outside.invalid/v1" in result["cross_origin_api_candidates"]
    assert result["api_base"] != "https://outside.invalid/v1"
    assert not any("outside.invalid" in url for url in calls)


def test_conventional_api_subdomain_is_not_probed_implicitly(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        if url == "https://www.example.test":
            return _response(text='<input type="password">')
        return _response(status=404)

    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setattr(
        requests,
        "post",
        lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("fingerprinting must not send POST requests")
        ),
    )

    result = vikramaditya.fingerprint_webapp("https://www.example.test")

    assert "https://api.example.test" in result["cross_origin_api_candidates"]
    assert not any(url.startswith("https://api.example.test") for url in calls)
