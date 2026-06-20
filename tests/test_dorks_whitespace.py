"""Regression: rendered Google dorks must not carry stray trailing whitespace.

Previously the SharePoint /sites/ dork literal contained ~13 trailing spaces,
which urllib.parse.quote encoded into %20%20... and appended to the inurl:
operator value, producing a malformed search URL. generate() now strips each
rendered dork, and the literal itself was cleaned up. SYNTHETIC target only.
"""
import dorks


def test_no_rendered_dork_has_trailing_or_leading_whitespace():
    results = dorks.generate("example.invalid", "all")
    offenders = [d["dork"] for d in results if d["dork"] != d["dork"].strip()]
    assert offenders == [], f"dorks with stray whitespace: {offenders!r}"


def test_sharepoint_sites_dork_url_has_no_encoded_trailing_spaces():
    results = dorks.generate("example.invalid", "microsoft365")
    sites = [d for d in results if "inurl:/sites/" in d["dork"]]
    assert sites, "expected the SharePoint /sites/ dork to be present"
    for d in sites:
        assert d["dork"] == "site:example.invalid inurl:/sites/"
        # No run of encoded spaces tacked onto the operator value.
        assert "%20%20" not in d["url"], d["url"]
        assert not d["url"].rstrip("&num=50").endswith("%20")
