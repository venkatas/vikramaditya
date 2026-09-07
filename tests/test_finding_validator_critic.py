#!/usr/bin/env python3
"""Severity-inflation critic tests for finding_validator.

All hosts are synthetic *.example.invalid only.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import finding_validator as fv  # noqa: E402


def test_admin_login_alone_downgrades():
    f = {
        "raw": "[HIGH] WordPress wp-admin login page exposed at https://app.example.invalid/wp-admin/",
        "severity": "high",
        "url": "https://app.example.invalid/wp-admin/",
    }
    infl = fv.assess_severity_inflation(f)
    assert infl["action"] == "downgrade"
    assert infl.get("to_severity") == "info"
    out = fv.validate_finding(f)
    assert out["decision"] == "downgrade"
    assert out.get("to_severity") == "info"


def test_admin_login_with_default_creds_passes_inflation():
    f = {
        "raw": "wp-admin at https://app.example.invalid/wp-admin/ accepts default creds admin:admin",
        "severity": "high",
    }
    infl = fv.assess_severity_inflation(f)
    assert infl["action"] == "pass"
    out = fv.validate_finding(f)
    assert out["decision"] == "pass"


def test_directory_listing_no_sensitive_downgrades():
    f = {
        "raw": "Directory listing enabled at https://files.example.invalid/uploads/ Index of /",
        "severity": "medium",
    }
    infl = fv.assess_severity_inflation(f)
    assert infl["action"] == "downgrade"
    assert fv.validate_finding(f)["decision"] == "downgrade"


def test_directory_listing_with_sensitive_passes():
    f = {
        "raw": "Directory listing at https://files.example.invalid/ shows sensitive file .env and id_rsa",
        "severity": "high",
    }
    assert fv.assess_severity_inflation(f)["action"] == "pass"


def test_banner_disclosure_killed():
    f = {
        "raw": "Banner disclosure Server: Apache/2.4.49 on https://web.example.invalid/",
        "severity": "medium",
    }
    infl = fv.assess_severity_inflation(f)
    assert infl["action"] == "kill"
    assert fv.validate_finding(f)["decision"] == "kill"


def test_banner_with_cve_passes():
    f = {
        "raw": "version disclosure Apache/2.4.49 CVE-2021-41773 path traversal confirmed with root:x:0:0:",
        "severity": "critical",
    }
    assert fv.assess_severity_inflation(f)["action"] == "pass"


def test_missing_headers_on_json_api_killed():
    f = {
        "raw": "Missing CSP header on JSON API https://api.example.invalid/v1/users application/json",
        "severity": "low",
    }
    # may also hit never-submit; either kill is fine
    out = fv.validate_finding(f)
    assert out["decision"] in ("kill", "downgrade")


def test_self_signed_cert_downgrades():
    f = {
        "raw": "Self-signed certificate on internal service https://intranet.example.invalid:8443/",
        "severity": "medium",
    }
    infl = fv.assess_severity_inflation(f)
    assert infl["action"] == "downgrade"
    assert infl.get("to_severity") == "info"


def test_open_port_as_vuln_killed():
    f = {
        "raw": "[HIGH] Open port 3306 is vulnerable on db.example.invalid",
        "severity": "high",
    }
    infl = fv.assess_severity_inflation(f)
    assert infl["action"] == "kill"
    # critical/high + never-submit-like phrasing: inflation runs after never-submit;
    # open port pattern is inflation-only → kill via critic
    out = fv.validate_finding(f)
    assert out["decision"] in ("kill", "chain_required")


def test_outdated_without_cve_killed():
    f = {
        "raw": "Outdated software nginx 1.14 detected on https://old.example.invalid/",
        "severity": "medium",
    }
    assert fv.assess_severity_inflation(f)["action"] == "kill"
    assert fv.validate_finding(f)["decision"] == "kill"


def test_outdated_with_cve_passes():
    f = {
        "raw": "Outdated nginx 1.14 on https://old.example.invalid/ — CVE-2019-9511 actively exploited",
        "severity": "high",
    }
    assert fv.assess_severity_inflation(f)["action"] == "pass"


def test_nuclei_version_match_downgrades():
    f = {
        "raw": "nuclei [vulnerable] version-match template detected Apache on https://t.example.invalid/",
        "severity": "high",
    }
    infl = fv.assess_severity_inflation(f)
    assert infl["action"] == "downgrade"
    assert infl.get("to_severity") == "info"


def test_real_sqli_unaffected():
    f = {
        "raw": "confirmed boolean-based sqli http://acme.example.invalid/id?x=1 injectable",
        "severity": "critical",
        "vtype": "sqli",
    }
    assert fv.assess_severity_inflation(f)["action"] == "pass"
    assert fv.validate_finding(f)["decision"] == "pass"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
