"""scanner.sh must NOT write non-confirmed MFA/SAML markers into the CONFIRMED
findings.txt files (which map to the critical auth_bypass template).

friends full-tool review (Group A): three markers were written to
``mfa/findings.txt`` / ``saml/findings.txt`` and shipped as CRITICAL 9.8
"Broken Authentication" even though none is a confirmed auth bypass:

  - [MFA-RESPONSE-MANIP]  — server returns JSON {"success":false} for a WRONG
                            OTP, i.e. SECURE behaviour (pure false positive).
  - [MFA-NO-RATE-LIMIT]   — missing 429 burst; at most a MEDIUM rate-limit gap.
  - [SAML-METADATA-EXPOSED] — a public SP/IdP metadata document (public by
                            design); a LEAD for XSW, not an auth bypass.

They must be routed to manual_review/ as leads (like the existing
[MFA-WORKFLOW-SKIP-CANDIDATE]/[SAML-SIG-STRIP-CANDIDATE] siblings). The
genuinely-confirmed markers [MFA-WORKFLOW-SKIP] and [SAML-SIG-STRIP] must stay
in their findings.txt.
"""
import os
import subprocess

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANNER_SH = os.path.join(HERE, "scanner.sh")

UNCONFIRMED = ["[MFA-RESPONSE-MANIP]", "[MFA-NO-RATE-LIMIT]", "[SAML-METADATA-EXPOSED]"]
CONFIRMED = ["[MFA-WORKFLOW-SKIP]", "[SAML-SIG-STRIP]"]


def _emit_lines(marker):
    src = open(SCANNER_SH).read()
    # scanner.sh writes markers via `echo "[MARKER] ..." >> "$FINDINGS_DIR/..."`.
    # Match the exact marker token (bracketed) to avoid catching the -CANDIDATE
    # variants that already live in manual_review.
    out = []
    for ln in src.splitlines():
        if "echo" not in ln:
            continue
        # exact marker followed by a space (not the -CANDIDATE suffix)
        if (marker + " ") in ln:
            out.append(ln.strip())
    return out


def test_scanner_still_parses():
    subprocess.run(["bash", "-n", SCANNER_SH], check=True)


def test_unconfirmed_markers_routed_to_manual_review():
    for m in UNCONFIRMED:
        emits = _emit_lines(m)
        assert emits, f"expected scanner.sh to still emit {m} somewhere"
        for ln in emits:
            assert "manual_review" in ln, (
                f"{m} must be routed to manual_review/, not a confirmed findings file: {ln}")
            assert "findings.txt" not in ln, (
                f"{m} still written to a confirmed findings.txt: {ln}")


def test_confirmed_markers_stay_in_findings():
    for m in CONFIRMED:
        emits = _emit_lines(m)
        assert emits, f"expected scanner.sh to still emit {m}"
        assert any("findings.txt" in ln for ln in emits), (
            f"{m} is a CONFIRMED auth bypass and must remain in a findings.txt: {emits}")
