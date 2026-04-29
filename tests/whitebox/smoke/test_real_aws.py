import os
import pytest
from whitebox.profiles import CloudProfile, validate

pytestmark = pytest.mark.skipif(
    os.environ.get("WHITEBOX_SMOKE") != "1",
    reason="set WHITEBOX_SMOKE=1 to run real-account tests",
)


@pytest.mark.parametrize("profile_name,expected_account", [
    ("adf-erp",     "443370705278"),
    ("adf-pranapr", "591335425990"),
])
def test_validate_real_profile(profile_name, expected_account):
    prof = validate(CloudProfile(name=profile_name))
    assert prof.account_id == expected_account
    assert prof.permission_probe["simulate_principal_policy"] is True


@pytest.mark.parametrize("profile_name", ["adf-erp", "adf-pranapr"])
def test_route53_zones_returned(profile_name):
    from whitebox.inventory.route53 import candidate_domains
    prof = validate(CloudProfile(name=profile_name))
    domains = candidate_domains(prof)
    # At least one of the expected domains should appear
    assert any(d.endswith(".com") for d in domains), f"no zones for {profile_name}"
