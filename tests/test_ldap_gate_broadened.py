"""The LDAP-injection gate must fire on real blackbox AD/LDAP signals, not only
on tech-fingerprint tags that are never actually emitted.

friends full-tool review F8: looks_like_ldap_backed_auth intersected the tech
names from cve.detect_technologies (php/iis/tomcat/...) with a marker set
(active-directory/adfs/spring-security/...) that detect_technologies NEVER
produces — so the phase always skipped, even on an obvious AD/ADFS login. The
gate must also recognise ADFS/SSO login URL paths and NTLM/Negotiate/Kerberos
WWW-Authenticate challenges (the signals a blackbox scan actually observes).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ldap_injection_tester import looks_like_ldap_backed_auth  # noqa: E402


def test_fires_on_explicit_tech_marker():
    assert looks_like_ldap_backed_auth({"active-directory"})
    assert looks_like_ldap_backed_auth({"spring-security"})


def test_fires_on_adfs_or_sso_login_url():
    assert looks_like_ldap_backed_auth(
        {"iis", "asp.net"}, urls=["https://t.example.invalid/adfs/ls/?wa=wsignin1.0"])
    assert looks_like_ldap_backed_auth(
        {"iis"}, urls=["https://t.example.invalid/simplesaml/module.php"])


def test_fires_on_ntlm_or_negotiate_challenge():
    assert looks_like_ldap_backed_auth({"iis"}, www_authenticate=["Negotiate", "NTLM"])
    assert looks_like_ldap_backed_auth({"tomcat"}, www_authenticate="Kerberos")


def test_still_skips_plain_php_app():
    assert not looks_like_ldap_backed_auth(
        {"php", "nginx"},
        urls=["https://t.example.invalid/login", "https://t.example.invalid/api/users"],
        www_authenticate=["Basic realm=api"])
