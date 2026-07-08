"""open_redirect_hunt — generic ?next=/?url=/?return=/?goto= fuzzer.

Populates the currently-empty findings/redirects/ category. Confirms ONLY via a
real Location header pointing at the attacker-controlled host — a bare 3xx to
the original destination is not a finding.
"""
import open_redirect_hunt as orh


class _FakeResponse:
    def __init__(self, status_code, location=None, header_key="Location"):
        self.status_code = status_code
        self.headers = {header_key: location} if location else {}


class _FakeClient:
    def __init__(self, response):
        self._response = response

    def get(self, url, **kwargs):
        return self._response


def test_extract_redirect_params_finds_known_names():
    url = "https://example.com/login?next=/dashboard&other=1"
    assert orh.extract_redirect_params(url) == ["next"]


def test_extract_redirect_params_multiple_matches():
    url = "https://example.com/go?url=/a&return_to=/b&unrelated=1"
    assert set(orh.extract_redirect_params(url)) == {"url", "return_to"}


def test_extract_redirect_params_empty_when_none_match():
    assert orh.extract_redirect_params("https://example.com/page?id=5") == []


def test_build_bypass_variants_includes_double_encoding_and_at_sign():
    variants = orh.build_bypass_variants("evil.example")
    assert "https://evil.example" in variants
    assert any("%2F%2F" in v or "//" in v for v in variants)
    assert any("@evil.example" in v for v in variants)


def test_probe_url_confirms_on_location_to_attacker_host():
    client = _FakeClient(_FakeResponse(302, location="https://evil.example/"))
    result = orh.probe_url(client, "https://example.com/login?next=X", "next", "evil.example")
    assert result.confirmed is True


def test_probe_url_not_confirmed_when_location_is_original_host():
    client = _FakeClient(_FakeResponse(302, location="https://example.com/dashboard"))
    result = orh.probe_url(client, "https://example.com/login?next=X", "next", "evil.example")
    assert result.confirmed is False


def test_probe_url_not_confirmed_on_non_redirect_status():
    client = _FakeClient(_FakeResponse(200))
    result = orh.probe_url(client, "https://example.com/login?next=X", "next", "evil.example")
    assert result.confirmed is False


# --- Fix Round 1: false-negative regression coverage -----------------------

def test_probe_url_confirms_userinfo_at_sign_variant():
    """Important #1: the `https://example.com@{attacker_host}` bypass variant
    must be confirmed via .hostname (which strips userinfo), not .netloc
    (which would incorrectly compare against 'example.com@evil.example')."""
    client = _FakeClient(_FakeResponse(302, location="https://example.com@evil.example/"))
    result = orh.probe_url(client, "https://example.com/login?next=X", "next", "evil.example")
    assert result.confirmed is True


def test_probe_url_confirms_lenient_scheme_single_slash_variant():
    """Important #2: `https:/{attacker_host}` (single slash after the colon) is
    one of the two variants Python's strict urlparse cannot natively resolve
    to a host. Lenient pre-normalization must auto-correct it to
    `https://{attacker_host}` (mimicking browser behaviour) before parsing."""
    client = _FakeClient(_FakeResponse(302, location="https:/evil.example/"))
    result = orh.probe_url(client, "https://example.com/login?next=X", "next", "evil.example")
    assert result.confirmed is True


def test_probe_url_confirms_backslash_slash_variant():
    """Important #2 (bonus coverage): the `/\\/{attacker_host}` variant relies
    on backslash-as-forward-slash browser normalization. After replacing
    backslashes and collapsing the resulting leading slash-run, it should
    resolve to attacker_host too."""
    client = _FakeClient(_FakeResponse(302, location="/\\/evil.example/"))
    result = orh.probe_url(client, "https://example.com/login?next=X", "next", "evil.example")
    assert result.confirmed is True


def test_probe_url_confirms_lowercase_location_header_key():
    """Important #3: HTTP/2 mandates lowercase header names on the wire. A
    server emitting `location:` instead of `Location:` must still be
    detected — this simulates a real-world case-insensitive-mapping-less
    (plain dict) fixture with the lowercase key, as real HTTP/2 traffic
    would produce via curl_cffi/httpx over h2."""
    client = _FakeClient(_FakeResponse(302, location="https://evil.example/", header_key="location"))
    result = orh.probe_url(client, "https://example.com/login?next=X", "next", "evil.example")
    assert result.confirmed is True


def test_probe_url_confirms_capitalized_location_header_key_still_works():
    """Important #3 regression guard: the httpx/requests-normalized 'Location'
    casing (capitalized) must continue to work after switching away from the
    case-destroying dict(response.headers) wrapper."""
    client = _FakeClient(_FakeResponse(302, location="https://evil.example/", header_key="Location"))
    result = orh.probe_url(client, "https://example.com/login?next=X", "next", "evil.example")
    assert result.confirmed is True
