"""Two API-security playbooks ported from xalgorix that fill real autopilot gaps:
mass-assignment (auto-binding privilege escalation) and excessive-data-exposure
(over-fetching / object property leakage). They must be on disk, reachable by
alias, and suggested for REST/API/GraphQL fingerprints."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import skills_lib as sl  # noqa: E402


def test_new_playbooks_exist():
    pbs = sl.list_playbooks()
    assert "mass-assignment" in pbs
    assert "excessive-data-exposure" in pbs


def test_mass_assignment_reachable_by_alias():
    for alias in ("mass-assignment", "mass_assignment", "auto-binding"):
        body = sl.read_playbook(alias)
        assert "Mass Assignment" in body, f"alias {alias} should resolve"
        assert "isAdmin" in body or "is_admin" in body  # the escalation field hint


def test_excessive_data_exposure_reachable_by_alias():
    for alias in ("excessive-data-exposure", "data-exposure", "over-fetching"):
        body = sl.read_playbook(alias)
        assert "Excessive Data Exposure" in body, f"alias {alias} should resolve"


def test_api_tech_suggests_both_new_playbooks():
    sugg = sl.suggest_for_tech(["REST API", "swagger"])
    assert "mass-assignment" in sugg
    assert "excessive-data-exposure" in sugg


def test_playbooks_have_confirm_and_fp_sections():
    for name in ("mass-assignment", "excessive-data-exposure"):
        body = sl.read_playbook(name)
        assert "Confirm" in body or "Validation" in body
        assert "False-Positive" in body or "False Positive" in body
