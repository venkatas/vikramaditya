"""CVE-hunter must not hallucinate a CMS from a status-200-only probe.

GAP (audit 2026-06-14): cve.py Method 4 accepted a CMS if its fingerprint path returned HTTP 200
using `curl -o /dev/null` (status only, no body). A React/Vite SPA (client-spa.example) serves
index.html with 200 for EVERY unmatched path, so /typo3/ /umbraco/ /sitecore/ /sitefinity/
/administrator/ /user/login all returned 200 → six phantom CMS detected → 18 bogus ancient CVEs
(CVE-1999-0238, CVE-2005-3773 Joomla 1.0.4, CVE-2015-8814 Umbraco, ...) in cve_database_matches.json.

FIX: _cms_path_confirms() requires (a) HTTP 200, (b) the body to differ materially from a
baseline random-path 200 (rejects SPA catch-all), and (c) a CMS-specific body marker.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cve  # noqa: E402

_SPA_INDEX = "<!doctype html><div id=root></div><script src=/assets/index-505aa34d.js></script>" * 8


def test_rejects_spa_catchall_identical_to_baseline():
    # SPA returns the SAME index for the baseline random path AND the CMS fingerprint path.
    assert cve._cms_path_confirms("joomla", "200", _SPA_INDEX, "200", _SPA_INDEX) is False
    assert cve._cms_path_confirms("typo3", "200", _SPA_INDEX, "200", _SPA_INDEX) is False
    assert cve._cms_path_confirms("sitecore", "200", _SPA_INDEX, "200", _SPA_INDEX) is False


def test_accepts_real_wordpress_with_marker():
    base = "404 not found"
    wp = "<html><head><link href='/wp-includes/css/x.css'><meta name='generator' content='WordPress 6.5'></head><body>wp-content</body></html>"
    assert cve._cms_path_confirms("wordpress", "200", wp, "404", base) is True


def test_requires_a_cms_marker_even_when_body_differs():
    base = "x"
    generic = "<html><body>" + ("generic content " * 40) + "</body></html>"  # 200, different len, but no drupal marker
    assert cve._cms_path_confirms("drupal", "200", generic, "404", base) is False


def test_rejects_non_200():
    assert cve._cms_path_confirms("wordpress", "301", "wp-content wp-includes", "404", "x") is False
    assert cve._cms_path_confirms("joomla", "403", "com_content joomla!", "404", "x") is False


def test_accepts_real_cms_even_when_length_near_baseline():
    """Codex MED: a real CMS page with a marker must NOT be rejected just because its length is
    close to the baseline 404 (the old `abs(len) < 64` heuristic false-negatived it)."""
    baseline = "Error 404: page not found on this server, please check the URL and retry now!!"
    cms = "Login required. <link href=/wp-includes/x.css> wp-content present here, folks, okay!"
    assert abs(len(cms) - len(baseline)) < 64           # similar length on purpose
    assert cve._cms_path_confirms("wordpress", "200", cms, "200", baseline) is True


def test_accepts_when_no_baseline_200_and_marker_present():
    # If the baseline random path did NOT return 200 (normal site), a 200 + marker is real evidence.
    drupal = "<html>" + ("a" * 200) + " Drupal.settings /sites/default/ </html>"
    assert cve._cms_path_confirms("drupal", "200", drupal, "404", "not found") is True
