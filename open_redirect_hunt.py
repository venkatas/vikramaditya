#!/usr/bin/env python3
"""open_redirect_hunt.py — generic parametric open-redirect fuzzer.

Confirmed gap: scanner.sh only mkdir's findings/redirects/ and lists "redirects"
in DEFAULT_SKIP_SET with zero actual probing logic; oauth_tester.py only covers
OAuth redirect_uri, not generic ?next=/?url=/?return=/?goto= params. Confirms
ONLY via a real Location header to the attacker-controlled host — a redirect
back to the app's own domain is not a finding, regardless of status code.
"""
from __future__ import annotations

import re
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
    # The last raw HTTP response probe_url examined (None if the URL had no
    # bypass-variant candidates at all). Lets callers check for a
    # bot-management/WAF block without a second round-trip.
    response: object = None


# Matches "scheme:/host" (a single slash after the colon, NOT "scheme://host").
# Browsers auto-correct this shape by inserting the missing slash; Python's
# strict RFC-3986 urlparse does not, so we mimic the browser here.
_SCHEME_SINGLE_SLASH_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*):/(?!/)")

# Collapses a leading run of 2+ slashes down to exactly "//" so protocol-relative
# variants that pick up an extra slash (e.g. from backslash normalization) still
# parse to an authority component instead of being swallowed into the path.
_LEADING_SLASHES_RE = re.compile(r"^/{2,}")


def _normalize_location(location: str) -> str:
    """Lenient, browser-like pre-normalization of a raw Location header value.

    Python's urlparse is strict RFC-3986 and will NOT auto-correct shapes that
    real browsers happily normalize (backslash-as-slash, missing double-slash
    after a scheme). A target reflecting an open-redirect payload verbatim into
    its Location header may produce exactly these lenient shapes, so we
    normalize before parsing rather than conditionally per-variant, since a
    real target's response could contain either shape regardless of which
    bypass variant triggered it.
    """
    normalized = location.replace("\\", "/")
    normalized = _SCHEME_SINGLE_SLASH_RE.sub(lambda m: f"{m.group(1)}://", normalized, count=1)
    normalized = _LEADING_SLASHES_RE.sub("//", normalized)
    return normalized


def _get_location_header(headers) -> str:
    """Case-insensitive Location header lookup.

    HTTP/2 mandates lowercase header names on the wire, and this tool is meant
    to run against real-world clients (httpx/requests/curl_cffi) whose header
    mapping objects are already case-insensitive. Try that native .get() first
    so we don't break it; only fall back to a manual case-insensitive scan for
    plain-dict fixtures (e.g. this module's own tests) that may use
    inconsistent casing. Deliberately does NOT wrap headers in dict() first,
    since that would discard case-insensitivity on a real mapping.
    """
    location = headers.get("Location")
    if location:
        return location
    for key, value in headers.items():
        if key.lower() == "location":
            return value
    return ""


def probe_url(client, url: str, param: str, attacker_host: str) -> RedirectResult:
    """Replace param's value with each bypass variant; confirm the first variant
    whose Location header actually points at attacker_host."""
    last_response = None
    for variant in build_bypass_variants(attacker_host):
        parsed = urlsplit(url)
        query = parse_qs(parsed.query)
        query[param] = [variant]
        new_query = "&".join(f"{k}={v[0]}" for k, v in query.items())
        test_url = parsed._replace(query=new_query).geturl()

        response = client.get(test_url, allow_redirects=False)
        last_response = response
        if response.status_code not in (301, 302, 303, 307, 308):
            continue
        location = _get_location_header(response.headers)
        if not location:
            continue
        location_host = urlparse(_normalize_location(location)).hostname or ""
        if location_host == attacker_host or location_host.endswith("." + attacker_host):
            return RedirectResult(confirmed=True, location=location, response=response)
    return RedirectResult(confirmed=False, response=last_response)
