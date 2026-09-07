#!/usr/bin/env python3
"""Deterministic local environment checks for Vikramaditya.

This module performs no network access and does not modify the environment.  It
is shared by setup verification and the CLI readiness display so binary
presence cannot be mistaken for a usable Python environment.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from collections.abc import Callable, Iterable
from typing import Any


REQUIRED_RUNTIME_TOOLS = ("uro",)


def _compact_output(stdout: str | None, stderr: str | None) -> str:
    lines = [
        line.strip()
        for line in f"{stdout or ''}\n{stderr or ''}".splitlines()
        if line.strip()
    ]
    return "; ".join(lines) if lines else "pip check failed without diagnostic output"


def check_environment_readiness(
    *,
    python_executable: str | None = None,
    required_tools: Iterable[str] = REQUIRED_RUNTIME_TOOLS,
    which: Callable[[str], str | None] = shutil.which,
    runner: Callable[..., Any] = subprocess.run,
) -> list[dict[str, str]]:
    """Return fail-closed readiness gaps for the active Python environment.

    The return shape matches ``hunt.check_tool_readiness`` so callers can merge
    the results without translating them.
    """

    gaps: list[dict[str, str]] = []
    python = python_executable or sys.executable

    try:
        result = runner(
            [python, "-m", "pip", "check"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        gaps.append(
            {
                "tool": "python-dependencies",
                "reason": f"pip check could not complete: {exc}",
            }
        )
    else:
        if result.returncode != 0:
            gaps.append(
                {
                    "tool": "python-dependencies",
                    "reason": _compact_output(result.stdout, result.stderr),
                }
            )

    for tool in required_tools:
        if not which(tool):
            gaps.append(
                {
                    "tool": tool,
                    "reason": f"required runtime command not found on PATH: {tool}",
                }
            )

    return gaps


def main() -> int:
    gaps = check_environment_readiness()
    if not gaps:
        print("Environment readiness: PASS")
        return 0

    print("Environment readiness: FAIL", file=sys.stderr)
    for gap in gaps:
        print(f"- {gap['tool']}: {gap['reason']}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
