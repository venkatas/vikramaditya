---
name: ctf-coverage-notes
description: Optional CTF coverage map. Vik is not a CTF solver. No default tool runs.
---

# CTF coverage notes (optional)

Vikramaditya is an authorized VAPT orchestrator. It is not a CTF runtime and it does not ship a challenge solver. These notes exist so operators can see categories the default scan does not cover. They are not procedures, payloads, or an install list.

## Not on the default scan path
| Category | Optional local binary | Hunt / MCP |
|---|---|---|
| File carving / firmware unpack | binwalk | not invoked |
| Stego | steghide | not invoked |
| Offline password hash | john | not invoked |
| Disassembly | radare2 | not invoked |

`setup.sh` does not install these. The MCP facade has no tool that launches them. `TOOL_REGISTRY` is unchanged.

## Rules
- Use only on authorized labs or CTF files you already have.
- Do not point lab binaries at a production hunt target from the default scan path.
- Do not change `ALLOW_STATE_CHANGES` or aggression defaults to "cover CTF".
- A missing binary is a coverage note, not a setup failure.

## Vik wiring
- Checklist / coverage map only. No second orchestrator. No HexStrike tool dump.
