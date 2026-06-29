"""Regression tests for waf_bypass.py built-in mangler bypass classification.

The built-in fallback mangler (used only when `bypass-url-parser` is absent)
previously tagged ANY status not in (401, 403, 404) as [BYPASS], so 5xx WAF
blocks, 3xx login redirects, and baseline-identical 200s were all mis-flagged
as access-control bypasses. These tests pin the corrected baseline-aware
classification in `_mangle_marker`.

All data here is synthetic.
"""

import waf_bypass


def test_genuine_bypass_blocked_baseline_then_2xx_different_body():
    # Baseline path was access-controlled (403) and the mangled request now
    # returns a 2xx whose body is materially different from the blocked page.
    assert waf_bypass._mangle_marker(200, 5000, base_blocked=True, base_sz=120) == "[BYPASS]"
    assert waf_bypass._mangle_marker(204, 0, base_blocked=True, base_sz=4000) == "[BYPASS]"


def test_5xx_is_not_a_bypass():
    # 5xx is a common WAF block response, never an access-control bypass.
    assert waf_bypass._mangle_marker(500, 300, base_blocked=True, base_sz=120) == "[ ]"
    assert waf_bypass._mangle_marker(503, 300, base_blocked=True, base_sz=120) == "[ ]"


def test_3xx_redirect_is_not_a_bypass():
    # A 301/302 to a login page is the OPPOSITE of a bypass.
    assert waf_bypass._mangle_marker(301, 0, base_blocked=True, base_sz=120) == "[ ]"
    assert waf_bypass._mangle_marker(302, 0, base_blocked=True, base_sz=120) == "[ ]"


def test_2xx_identical_to_blocked_baseline_is_not_a_bypass():
    # A 200 byte-near-identical to the blocked baseline page is not a bypass.
    assert waf_bypass._mangle_marker(200, 130, base_blocked=True, base_sz=120) == "[ ]"


def test_still_blocked_is_not_a_bypass():
    # Mangled request still returns the same block status.
    assert waf_bypass._mangle_marker(403, 120, base_blocked=True, base_sz=120) == "[ ]"
    assert waf_bypass._mangle_marker(401, 120, base_blocked=True, base_sz=120) == "[ ]"


def test_2xx_without_blocked_baseline_is_ambiguous_not_dropped():
    # If the baseline was never a clean block we cannot prove a bypass, but we
    # must not silently drop it either — surface as [?] for manual triage.
    assert waf_bypass._mangle_marker(200, 5000, base_blocked=False, base_sz=4000) == "[?]"


def test_size_delta_threshold():
    # Just under the 64-byte delta gate -> not a bypass; over it -> bypass.
    assert waf_bypass._mangle_marker(200, 120 + 64, base_blocked=True, base_sz=120) == "[ ]"
    assert waf_bypass._mangle_marker(200, 120 + 65, base_blocked=True, base_sz=120) == "[BYPASS]"
