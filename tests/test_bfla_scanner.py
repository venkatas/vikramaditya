"""bfla_scanner — forced-browsing / Broken Function-Level Authorization detector.

Closes the authorization gap: a low-privilege MAKER reached admin pages (/AdminQueue,
/RecordDetails, /FeeRecordDetails) that returned 200 instead of 403/SSO-redirect.
Per the friends' review, a status-200 check alone is insufficient — confirm by
DIFFERENTIAL: the low-priv session reaches the page BUT an unauthenticated request is
gated => the page is auth-gated, not role-gated => BFLA.

Synthetic fixtures only.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import bfla_scanner  # noqa: E402


def _r(status, body="", location=""):
    return (status, body, location)


def test_low_priv_reaches_admin_page_confirmed_bfla():
    low = lambda p: _r(200, "<h1>Approval Queue</h1><table>rows</table><a href='/logout'>Logout</a>")
    unauth = lambda p: _r(302, "", "/login")
    fs = bfla_scanner.scan(low, ["/AdminQueue", "/Other"], unauth_get=unauth)
    f = next((x for x in fs if x["path"] == "/AdminQueue"), None)
    assert f is not None
    assert f["confidence"] == "confirmed"
    assert f["severity"] in ("high", "critical")


def test_properly_gated_low_priv_redirect_not_flagged():
    low = lambda p: _r(302, "", "/login")
    fs = bfla_scanner.scan(low, ["/AdminPanel"], unauth_get=lambda p: _r(302, "", "/login"))
    assert fs == []


def test_403_not_flagged():
    fs = bfla_scanner.scan(lambda p: _r(403, "Forbidden"), ["/AdminPanel"])
    assert fs == []


def test_sso_redirect_not_flagged():
    low = lambda p: _r(302, "", "https://login.microsoftonline.com/x/oauth2/authorize")
    fs = bfla_scanner.scan(low, ["/AdminPanel"], unauth_get=lambda p: _r(302, "", "/login"))
    assert fs == []


def test_200_login_page_rendered_not_flagged():
    low = lambda p: _r(200, '<form><input type="password" name="pwd"></form>')
    fs = bfla_scanner.scan(low, ["/AdminPanel"])
    assert fs == []


def test_404_not_flagged():
    fs = bfla_scanner.scan(lambda p: _r(404, "Not Found"), ["/Missing"])
    assert fs == []


def test_public_page_reachable_unauth_not_flagged():
    # low-priv 200 AND unauth 200 -> public page, not a privilege issue
    low = lambda p: _r(200, "<h1>Public</h1>")
    fs = bfla_scanner.scan(low, ["/Reports"], unauth_get=lambda p: _r(200, "<h1>Public</h1>"))
    assert fs == []


def test_accessible_without_baseline_is_candidate():
    fs = bfla_scanner.scan(lambda p: _r(200, "<h1>Reports</h1><table>x</table>"), ["/Reports"])
    assert fs and fs[0]["confidence"] == "candidate"
    assert fs[0]["severity"] in ("medium", "high")


def test_default_admin_wordlist_present():
    assert len(bfla_scanner.DEFAULT_ADMIN_PATHS) >= 10
    assert any("admin" in p.lower() for p in bfla_scanner.DEFAULT_ADMIN_PATHS)
