"""A GROUNDED brain verdict must rest on evidence relevant to the claim, not on
any successful script whatsoever.

friends full-tool review F9: _verdict_findings tagged a verdict
``[VERIFIED — grounded run]`` whenever ANY script produced real output
(``grounded = successful_runs > 0``). So a script that only printed
``Server: nginx/1.24`` grounded an unrelated "SQL injection CONFIRMED" verdict,
which the reporter then KEPT as a verified critical. When the grounded output is
purely passive fingerprint/banner data (no exploitation evidence), the verdict
must drop to ``[MODEL CLAIM]`` (the reporter drops those at medium+). Substantive
output that isn't obviously just a banner must NOT be downgraded (no regression).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import brain_scanner as bs  # noqa: E402


def test_grounded_but_only_a_server_banner_is_not_verified():
    out = bs._verdict_findings(
        "SQL injection CONFIRMED on /x", grounded=True,
        grounded_output="Server: nginx/1.24\nX-Powered-By: PHP/7.4\n")
    assert out and out[0].startswith("[MODEL CLAIM"), out


def test_grounded_with_real_exploit_evidence_is_verified():
    out = bs._verdict_findings(
        "SQL injection CONFIRMED", grounded=True,
        grounded_output="ERROR: syntax error at or near \"'\"\n id | email\n 1 | admin@x\n")
    assert out and out[0].startswith("[VERIFIED"), out


def test_grounded_output_omitted_preserves_legacy_verified():
    # Backward-compat: callers that don't pass grounded_output keep the old
    # grounded==verified behaviour.
    out = bs._verdict_findings("RCE CONFIRMED", grounded=True)
    assert out and out[0].startswith("[VERIFIED"), out


def test_ungrounded_stays_model_claim():
    out = bs._verdict_findings("XSS CONFIRMED", grounded=False,
                               grounded_output="uid=0(root) gid=0(root)")
    assert out and out[0].startswith("[MODEL CLAIM"), out
