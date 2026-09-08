# HexStrike patterns (ideas only)

Reviewed https://github.com/0x4m4/hexstrike-ai (MIT) and skipped it as a runtime.

Vik already orchestrates tools and uses local Ollama. This port does **not**
fork, vendor, import, or subprocess HexStrike. It does **not** add the 150+
tool MCP server or a cloud LLM loop. `ALLOW_STATE_CHANGES` and aggression
defaults are unchanged. The default scan path does not run new tools.

Three clean-room patterns only:

| Pattern | Where | Default |
|---|---|---|
| MCP facade | `mcp/vik-mcp/server.py` | off the scan path; start only if an MCP client is pointed at it |
| Session tool cache | `session_tool_cache.py`, consulted by `hunt.py` runners | off unless `VIK_SESSION_TOOL_CACHE=1` |
| Optional cloud/CTF notes | `skills/cloud/cloud-iam-notes`, `skills/recon/ctf-coverage-notes`, `hexstrike_patterns.py` | documentation and skill context only |

## 1. MCP facade

Stdlib JSON-RPC over stdin/stdout (MCP-shaped `Content-Length` framing, plus
NDJSON for tests). No required MCP package, so `setup.sh` does not gain one.

Exposed tools (explicit list, nothing else):

- `vik_list_skills` - skill pack names
- `vik_load_skill` - one pack, truncated
- `vik_session_status` - session metadata, cache stats, phase manifest summary
- `vik_cached_tool_lookup` - prior cached result only; does not execute the tool
- `vik_scope_check` - dry-run `ScopeChecker` (no traffic)
- `vik_coverage_notes` - the optional coverage map

There is no `run_command`, shell, or exec tool. Session paths are limited to
`recon/`, `findings/`, `reports/`, `engagements/`, or `VIK_SESSION_DIR`.

### Point Cursor at it

Use an absolute path. Example `mcp.json` (see also `mcp/vik-mcp/config.json`):

```json
{
  "mcpServers": {
    "vikramaditya": {
      "command": "python3",
      "args": ["/ABS/PATH/TO/obsidian/mcp/vik-mcp/server.py"],
      "env": {
        "VIK_SCOPE": "*.example.com"
      }
    }
  }
}
```

Optional env:

- `VIK_SCOPE` - allowlist for `vik_scope_check` when `domains` is omitted
- `VIK_SESSION_DIR` - session directory for status/cache lookup when the client does not pass one
- `VIK_CACHE_TARGET` - fallback target name

Sanity check (prints tool names, starts no scan):

```bash
python3 mcp/vik-mcp/server.py --check
```

## 2. Session tool cache

Avoid re-running the same tool on the same inputs inside one session. The
cache lives under the session directory, not a global world-writable cache:

```
recon/<target>/sessions/<id>/tool_cache/<sha256>.json
```

Cache key: `target + tool + canonical args`.

Skipped (always runs, never stored) when:

- the env flag is off (the default)
- args or output look like secrets (tokens, passwords, cookies, keys)
- a host in the args fails `ScopeChecker` / `scope/allow.txt`
- the invocation watches an artefact file, uses shell redirection, or is a
  wrapper / state-changing binary (`bash`, `sqlmap`, `msfconsole`, ...)

Enable for a hunt process:

```bash
export VIK_SESSION_TOOL_CACHE=1
python3 hunt.py --target example.com
```

A replayed hit is prefixed with `[session-tool-cache hit]` so reports can see
that the tool was not executed again. The first run still executes.

## 3. Optional cloud / CTF coverage

Vik already covers cloud metadata and storage checklists, plus opt-in
whitebox Prowler. Gaps are notes, not a new install wall:

- IAM posture: `skills/cloud/cloud-iam-notes` (prefer existing whitebox/Prowler)
- CTF categories: `skills/recon/ctf-coverage-notes` (not a solver; binaries not invoked)

`setup.sh` only prints a pointer. It does not install HexStrike or the
optional names listed in those notes.
