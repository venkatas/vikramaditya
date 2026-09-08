#!/usr/bin/env python3
"""Clean-room HexStrike pattern notes for Vikramaditya.

Ideas only. This module does not import, vendor, fork, or subprocess HexStrike.
Source attributed in NOTICE: https://github.com/0x4m4/hexstrike-ai (MIT).

Three patterns, nothing else:
  1. MCP facade (opt-in, narrow, no shell tool)
  2. Session tool-result cache (same target+tool+args, disk under the session)
  3. Optional cloud/CTF coverage notes for gaps Vik does not already run
"""

from __future__ import annotations

SOURCE_URL = "https://github.com/0x4m4/hexstrike-ai"
LICENSE_NAME = "MIT"
NOT_VENDORED = True

# Explicit non-goals. Used by tests and the MCP facade so a client cannot
# discover a command runner through this surface.
REFUSED_CAPABILITIES = (
    "run_command",
    "shell",
    "exec",
    "subprocess",
    "hexstrike_server",
    "arbitrary_tool_exec",
)

# Short optional list. Not a dump of HexStrike's 150+ tools, and not a
# required install. setup.sh must not grow a package for these names.
OPTIONAL_COVERAGE = (
    {
        "id": "cloud-iam-notes",
        "kind": "cloud",
        "summary": (
            "IAM posture notes for accounts already in authorized scope. "
            "Use existing whitebox/Prowler when AWS creds are in scope. "
            "Do not install enumerate-iam as a required dependency."
        ),
        "skill": "cloud-iam-notes",
        "already_in_vik": (
            "whitebox/cloud_hunt.py",
            "skills/cloud/cloud-metadata-imds",
            "skills/cloud/storage-exposure",
        ),
        "optional_local": (),
        "installed_by_setup": False,
        "on_default_scan_path": False,
    },
    {
        "id": "cloud-bucket-name-notes",
        "kind": "cloud",
        "summary": (
            "Bucket/container name discovery beyond the storage-exposure "
            "checklist. Operator-owned optional binaries only. Not wired "
            "into hunt TOOL_REGISTRY and not installed by setup.sh."
        ),
        "skill": "cloud-iam-notes",
        "already_in_vik": (
            "skills/cloud/storage-exposure",
        ),
        "optional_local": ("s3scanner",),
        "installed_by_setup": False,
        "on_default_scan_path": False,
    },
    {
        "id": "ctf-coverage-notes",
        "kind": "ctf",
        "summary": (
            "Coverage map only. Vik is not a CTF solver and does not run "
            "forensics, stego, offline hash, or disassembly tools. Optional "
            "local lab binaries an operator may already have; never invoked "
            "by hunt or the MCP facade."
        ),
        "skill": "ctf-coverage-notes",
        "already_in_vik": (),
        "optional_local": ("binwalk", "steghide", "john", "radare2"),
        "installed_by_setup": False,
        "on_default_scan_path": False,
    },
)


def coverage_notes() -> dict:
    """Return the optional cloud/CTF coverage map (read-only data)."""
    return {
        "source": SOURCE_URL,
        "license": LICENSE_NAME,
        "vendored": False,
        "runtime": "skipped",
        "refused_capabilities": list(REFUSED_CAPABILITIES),
        "optional_coverage": [dict(item) for item in OPTIONAL_COVERAGE],
        "defaults_unchanged": {
            "ALLOW_STATE_CHANGES": "unchanged",
            "aggression": "unchanged",
            "default_scan_new_tools": False,
        },
    }
