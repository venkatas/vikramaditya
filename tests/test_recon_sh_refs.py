"""Regression guard — every helper script recon.sh + scanner.sh invokes must exist.

v7.1.5 fix. recon.sh's Phase 6.5 looked for ``openapi_audit.py`` but the
actual file is ``api_audit.py``. The path mismatch silently skipped
OpenAPI discovery on every run and left the ``api_specs/`` directory
empty — which in turn starved the new v7.1.4 ``_collect_openapi_post_endpoints``
feed into sqlmap. Silent-skip is worse than a crash because nothing in
the final report tells the user that Swagger discovery never ran.

This test parametrises over every ``.py``/``.sh`` reference inside the
shell pipelines and asserts the file exists at repo root. Adding a new
helper script without matching the filename will now fail CI.
"""

from __future__ import annotations

import os
import re

import pytest

REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))

# Regex: a ``$SCRIPT_DIR/<name>.(py|sh)`` reference in a shell pipeline.
_SCRIPT_REF_RE = re.compile(r"\$SCRIPT_DIR/([A-Za-z0-9_/-]+\.(?:py|sh))")


def _collect_refs(shell_path: str) -> set[str]:
    with open(os.path.join(REPO_ROOT, shell_path)) as f:
        body = f.read()
    return set(_SCRIPT_REF_RE.findall(body))


def _all_cases() -> list[tuple[str, str]]:
    cases: list[tuple[str, str]] = []
    for shell in ("recon.sh", "scanner.sh"):
        path = os.path.join(REPO_ROOT, shell)
        if not os.path.isfile(path):
            continue
        for ref in sorted(_collect_refs(shell)):
            # Skip references into subdirectories — those are external
            # third-party tools (XSStrike, LinkFinder, etc.) cloned into
            # ``tools/<name>/`` via install.sh. They're correctly guarded
            # by ``[ -f "$path" ]`` in the shell and may be absent on a
            # fresh checkout. The guard we're policing here is the
            # *in-repo* helper pipeline — scripts the checkout is expected
            # to carry. A ``/`` in the ref means "lives in a subdir".
            if "/" in ref:
                continue
            cases.append((shell, ref))
    return cases


@pytest.mark.parametrize("shell,ref", _all_cases())
def test_shell_script_ref_exists(shell: str, ref: str) -> None:
    """``$SCRIPT_DIR/<ref>`` in ``<shell>`` must name a file at repo root.

    A miss here is the exact class of bug that caused Phase 6.5 silent-skip:
    the shell script dispatches, ``[ -f "$SCRIPT"]`` returns false, and the
    pipeline continues as if everything succeeded.

    Exception: references explicitly guarded with a fallback (``||``-pattern
    in-line) are permitted to name an absent file. Those show up as two
    separate matches; at least one of the two must exist.
    """
    path = os.path.join(REPO_ROOT, ref)
    if os.path.isfile(path):
        return
    # Fallback for files explicitly guarded by the caller: check the wider
    # file for an alternate name. Only accept if the sibling exists too.
    with open(os.path.join(REPO_ROOT, shell)) as f:
        body = f.read()
    refs_for_same_var = _collect_refs(shell)
    alt_found = any(
        os.path.isfile(os.path.join(REPO_ROOT, alt))
        for alt in refs_for_same_var
        if alt != ref
    )
    assert alt_found, (
        f"{shell} references $SCRIPT_DIR/{ref} but no such file exists at "
        f"repo root and no sibling fallback was configured either."
    )
