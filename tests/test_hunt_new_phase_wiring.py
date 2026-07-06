"""Verifies the new phases (xxe_hunt, open_redirect_hunt, saml_xsw,
actuator_probe, ldap_injection) are correctly wired in hunt.py: the run_*()
functions exist, and hunt_target()'s source registers each phase's key in
its _phase_requested gating dict (a phase with only an appended run_*()
function but no _phase_requested entry silently misreports its dashboard
status). Also verifies run_jwt_audit() was extended in place to call
jwt_kid_injection.

NOTE: the sequential Phase 7.x phase-call pattern (the _phase_tool_map /
_phase_requested dicts and the "if <gate> and not skip_has(...): try: ...
result[key] = run_xxx(domain)" call sites) live inside hunt_target(), the
default (non --autonomous) orchestrator invoked from main() — NOT inside
run_autonomous_hunt(), which is a separate, --autonomous-only step-based
orchestrator with its own independent phase list. Verified directly against
the live hunt.py source before writing this test."""
import inspect

import hunt


def test_new_phase_functions_exist():
    for name in ("run_xxe_hunt", "run_open_redirect_hunt", "run_saml_xsw",
                 "run_actuator_probe", "run_ldap_injection"):
        assert hasattr(hunt, name), f"hunt.py is missing {name}"
        assert callable(getattr(hunt, name))


def test_new_phases_registered_in_phase_requested_source():
    source = inspect.getsource(hunt.hunt_target)
    for key in ("xxe_hunt", "open_redirect_hunt", "saml_xsw", "actuator_probe", "ldap_injection"):
        assert f'"{key}"' in source, f"_phase_requested missing entry for {key}"
        # each phase must actually be CALLED (result["<key>"] = run_...), not just
        # declared in the dashboard dict — otherwise it's dead code.
        assert f'result["{key}"]' in source, f"{key} is registered but never assigned in result[...]"


def test_new_phases_actually_called():
    source = inspect.getsource(hunt.hunt_target)
    assert "run_xxe_hunt(domain)" in source
    assert "run_open_redirect_hunt(domain)" in source
    assert "run_saml_xsw(domain)" in source
    assert "run_actuator_probe(domain)" in source
    assert "run_ldap_injection(domain)" in source


def test_run_jwt_audit_source_calls_kid_injection_module():
    source = inspect.getsource(hunt.run_jwt_audit)
    assert "jwt_kid_injection" in source
