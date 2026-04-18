"""Repo-wide syntax smoke test.

Every ``.py`` file at the repo root must compile. This exists because a
duplicate ``from __future__ import annotations`` (one before the module
docstring, one after) slipped into ``api_audit.py`` and ``agent.py`` — a
``SyntaxError`` that only surfaced when Vikramaditya's runtime ``import``
hit the file mid-scan. v7.1.3 pins the repo against that class of
regression.
"""

from __future__ import annotations

import os
import py_compile

import pytest

REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def _root_py_files() -> list[str]:
    """All *.py files at repo root. Submodule trees are excluded — their
    own test files cover them."""
    return sorted(
        f for f in os.listdir(REPO_ROOT)
        if f.endswith(".py")
        and os.path.isfile(os.path.join(REPO_ROOT, f))
        and not f.startswith(".")
    )


# One test case per .py file so failures name the culprit directly.
@pytest.mark.parametrize("filename", _root_py_files())
def test_root_py_compiles(filename: str) -> None:
    """``python -m py_compile <filename>`` must succeed.

    A failure here is almost always one of:
    - ``from __future__ import`` placed after a statement (e.g. a
      docstring that pushes the import below line 1).
    - Missing ``:`` / mismatched paren from a partial edit.
    - Copy-paste of code using syntax newer than the repo's Python floor
      (Python 3.11 at time of writing).
    """
    path = os.path.join(REPO_ROOT, filename)
    try:
        py_compile.compile(path, doraise=True)
    except py_compile.PyCompileError as e:
        pytest.fail(f"{filename} failed to compile:\n{e.msg}")
