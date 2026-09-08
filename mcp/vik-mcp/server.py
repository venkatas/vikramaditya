#!/usr/bin/env python3
"""Opt-in Vikramaditya MCP facade (stdlib JSON-RPC over stdin/stdout).

Clean-room pattern: a narrow MCP surface so a client such as Cursor can call
an explicit list of Vik helpers. Not a HexStrike runtime. No shell/exec tool.
No arbitrary command tool. Off the default scan path.

Tools:
  vik_list_skills
  vik_load_skill
  vik_session_status
  vik_cached_tool_lookup
  vik_scope_check
  vik_coverage_notes

Point Cursor at this file. See docs/hexstrike-patterns.md and config.json.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

_THIS = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.abspath(os.path.join(_THIS, "..", ".."))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

SERVER_NAME = "vik-mcp"
SERVER_VERSION = "0.1.0"
PROTOCOL_DEFAULT = "2024-11-05"
SKILL_CHAR_CAP = 16000

# Names that must never appear as tools. Asserted by tests.
FORBIDDEN_TOOL_NAMES = (
    "run_command",
    "run_cmd",
    "shell",
    "exec",
    "subprocess",
    "execute",
    "terminal",
)


def _text(payload: Any, *, is_error: bool = False) -> dict:
    if not isinstance(payload, str):
        payload = json.dumps(payload, indent=2, default=str)
    return {
        "content": [{"type": "text", "text": payload}],
        "isError": is_error,
    }


def _repo_root() -> str:
    return _REPO


def _allowed_roots() -> list[str]:
    roots = [
        os.path.realpath(os.path.join(_REPO, name))
        for name in ("recon", "findings", "reports", "engagements")
    ]
    env = os.environ.get("VIK_SESSION_DIR", "").strip()
    if env:
        roots.append(os.path.realpath(env))
    return roots


def session_dir_allowed(path: str) -> bool:
    if not path:
        return False
    real = os.path.realpath(path)
    for root in _allowed_roots():
        if real == root or real.startswith(root + os.sep):
            return True
    return False


def resolve_session_dir(target: str = "", session_dir: str = "",
                        session_id: str = "") -> tuple[str | None, str | None]:
    """Return (session_dir, error). Read-only. Does not create directories."""
    explicit = (session_dir or os.environ.get("VIK_SESSION_DIR") or "").strip()
    if explicit:
        if not session_dir_allowed(explicit):
            return None, "session_dir is outside the checkout session roots"
        if not os.path.isdir(explicit):
            return None, "session_dir does not exist"
        return os.path.realpath(explicit), None

    target = (target or os.environ.get("VIK_CACHE_TARGET") or "").strip()
    if not target:
        return None, "target or session_dir is required"

    safe = target.replace("/", "").replace("..", "")
    recon_root = os.path.join(_REPO, "recon", safe)
    if session_id and session_id not in {"", "latest"}:
        candidate = os.path.join(recon_root, "sessions", session_id)
        if os.path.isdir(candidate) and session_dir_allowed(candidate):
            return os.path.realpath(candidate), None
        return None, "session_id not found under recon/<target>/sessions"

    meta_path = os.path.join(recon_root, "active_session.json")
    if os.path.isfile(meta_path):
        try:
            with open(meta_path, encoding="utf-8") as fh:
                meta = json.load(fh)
        except (OSError, json.JSONDecodeError):
            meta = {}
        sid = meta.get("session_id") if isinstance(meta, dict) else None
        if sid:
            candidate = os.path.join(recon_root, "sessions", sid)
            if os.path.isdir(candidate) and session_dir_allowed(candidate):
                return os.path.realpath(candidate), None

    sessions = os.path.join(recon_root, "sessions")
    if os.path.isdir(sessions):
        names = sorted(
            name for name in os.listdir(sessions)
            if os.path.isdir(os.path.join(sessions, name))
        )
        if names:
            candidate = os.path.join(sessions, names[-1])
            if session_dir_allowed(candidate):
                return os.path.realpath(candidate), None
    return None, "no session found for target"


def tool_list() -> list[dict]:
    return [
        {
            "name": "vik_list_skills",
            "description": "List Vik skill pack names (read-only). Does not run tools.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "vik_load_skill",
            "description": "Load one skill pack markdown by name (read-only, truncated).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Skill pack name, e.g. storage-exposure"},
                },
                "required": ["name"],
                "additionalProperties": False,
            },
        },
        {
            "name": "vik_session_status",
            "description": "Read session metadata, cache stats, and phase manifest summary. Does not start a scan.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "session_dir": {"type": "string"},
                    "session_id": {"type": "string"},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "vik_cached_tool_lookup",
            "description": "Look up a previously cached tool result for target+tool+args. Does not execute the tool.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "tool": {"type": "string"},
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Canonical argv. Include the tool binary as args[0] if that is how it was cached.",
                    },
                    "session_dir": {"type": "string"},
                    "session_id": {"type": "string"},
                },
                "required": ["target", "tool"],
                "additionalProperties": False,
            },
        },
        {
            "name": "vik_scope_check",
            "description": "Dry-run ScopeChecker.is_in_scope. Does not send traffic.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Host or URL to check"},
                    "domains": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Allowlist. Falls back to VIK_SCOPE if omitted.",
                    },
                    "excluded": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": ["host"],
                "additionalProperties": False,
            },
        },
        {
            "name": "vik_coverage_notes",
            "description": "Optional cloud/CTF coverage notes. Not an installer and not a tool runner.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    ]


def call_tool(name: str, arguments: dict | None) -> dict:
    args = arguments or {}
    if not isinstance(args, dict):
        return _text("arguments must be an object", is_error=True)
    if name in FORBIDDEN_TOOL_NAMES or name not in {t["name"] for t in tool_list()}:
        return _text(f"unknown tool: {name}", is_error=True)
    try:
        if name == "vik_list_skills":
            return _list_skills()
        if name == "vik_load_skill":
            return _load_skill(str(args.get("name") or ""))
        if name == "vik_session_status":
            return _session_status(args)
        if name == "vik_cached_tool_lookup":
            return _cached_lookup(args)
        if name == "vik_scope_check":
            return _scope_check(args)
        if name == "vik_coverage_notes":
            return _coverage()
    except Exception as exc:  # noqa: BLE001 — surface to the MCP client, never exec
        return _text({"error": "tool failed", "detail": str(exc)}, is_error=True)
    return _text(f"unknown tool: {name}", is_error=True)


def _list_skills() -> dict:
    import skill_loader
    names = skill_loader.list_skills()
    return _text({"skills": names, "count": len(names)})


def _load_skill(name: str) -> dict:
    if not name.strip():
        return _text("name is required", is_error=True)
    import skill_loader
    body = skill_loader.load_skill(name)
    truncated = False
    if len(body) > SKILL_CHAR_CAP:
        body = body[:SKILL_CHAR_CAP] + "\n[truncated]\n"
        truncated = True
    return _text({"name": name, "truncated": truncated, "markdown": body})


def _session_status(args: dict) -> dict:
    session_dir, err = resolve_session_dir(
        target=str(args.get("target") or ""),
        session_dir=str(args.get("session_dir") or ""),
        session_id=str(args.get("session_id") or ""),
    )
    if err or not session_dir:
        return _text({"error": err or "no session", "read_only": True}, is_error=True)

    import session_tool_cache
    meta = _read_json(os.path.join(os.path.dirname(os.path.dirname(session_dir)), "active_session.json"))
    # recon/<target>/sessions/<id> -> findings/<target>/sessions/<id>
    findings_dir = _sibling_kind(session_dir, "findings")
    manifest = None
    if findings_dir and os.path.isdir(findings_dir):
        try:
            import phase_manifest
            doc = phase_manifest.read_manifest(findings_dir)
            manifest = {
                "overall_status": doc.get("overall_status"),
                "success": doc.get("success"),
                "phase_count": len(doc.get("phases") or []),
            }
        except Exception:
            manifest = None
    return _text({
        "read_only": True,
        "session_dir": session_dir,
        "exists": True,
        "active_session": meta if isinstance(meta, dict) else None,
        "findings_dir": findings_dir if findings_dir and os.path.isdir(findings_dir) else None,
        "cache": session_tool_cache.stats(session_dir),
        "phase_manifest": manifest,
    })


def _cached_lookup(args: dict) -> dict:
    target = str(args.get("target") or "").strip()
    tool = str(args.get("tool") or "").strip()
    raw_args = args.get("args") or []
    if not isinstance(raw_args, list) or not all(isinstance(item, str) for item in raw_args):
        return _text("args must be a list of strings", is_error=True)
    session_dir, err = resolve_session_dir(
        target=target,
        session_dir=str(args.get("session_dir") or ""),
        session_id=str(args.get("session_id") or ""),
    )
    if err or not session_dir:
        return _text({"error": err or "no session", "hit": False}, is_error=True)
    import session_tool_cache
    hit = session_tool_cache.lookup(target, tool, raw_args, session_dir)
    if not hit:
        return _text({
            "hit": False,
            "executed": False,
            "target": target,
            "tool": tool,
            "session_dir": session_dir,
        })
    # Do not echo the on-disk path if it would leak outside the session root.
    hit = dict(hit)
    hit["executed"] = False
    hit.pop("path", None)
    return _text(hit)


def _scope_check(args: dict) -> dict:
    host = str(args.get("host") or "").strip()
    if not host:
        return _text("host is required", is_error=True)
    domains = args.get("domains")
    if not domains:
        raw = os.environ.get("VIK_SCOPE", "")
        domains = [p.strip() for p in raw.replace(",", " ").split() if p.strip()]
    if not isinstance(domains, list) or not domains:
        return _text(
            {"error": "domains required (or set VIK_SCOPE)", "in_scope": False, "traffic": False},
            is_error=True,
        )
    excluded = args.get("excluded") or []
    if not isinstance(excluded, list):
        return _text("excluded must be a list", is_error=True)
    from scope_checker import ScopeChecker
    checker = ScopeChecker([str(d) for d in domains], excluded_domains=[str(d) for d in excluded])
    return _text({
        "host": host,
        "in_scope": bool(checker.is_in_scope(host)),
        "domains": domains,
        "excluded": excluded,
        "traffic": False,
    })


def _coverage() -> dict:
    import hexstrike_patterns
    return _text(hexstrike_patterns.coverage_notes())


def _read_json(path: str) -> Any:
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def _sibling_kind(session_dir: str, kind: str) -> str | None:
    # .../recon/<target>/sessions/<id> -> .../<kind>/<target>/sessions/<id>
    parts = os.path.realpath(session_dir).split(os.sep)
    if "sessions" not in parts:
        return None
    idx = len(parts) - 1 - parts[::-1].index("sessions")
    if idx < 2:
        return None
    kind_idx = idx - 2
    parts[kind_idx] = kind
    return os.sep.join(parts)


def dispatch(message: dict) -> dict | None:
    """Handle one JSON-RPC message. Notifications return None."""
    if not isinstance(message, dict):
        return _rpc_error(None, -32600, "invalid request")
    method = message.get("method")
    msg_id = message.get("id", None)
    is_notification = "id" not in message
    params = message.get("params") or {}
    if not isinstance(params, dict):
        params = {}

    if method == "initialize":
        requested = str(params.get("protocolVersion") or PROTOCOL_DEFAULT)
        version = requested if requested[:4].isdigit() else PROTOCOL_DEFAULT
        return _rpc_result(msg_id, {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": (
                "Read-only/dry-run Vik facade. No shell tool. "
                "No scan is started by this server."
            ),
        })
    if method and method.startswith("notifications/"):
        return None
    if method == "ping":
        return _rpc_result(msg_id, {})
    if method == "tools/list":
        return _rpc_result(msg_id, {"tools": tool_list()})
    if method == "tools/call":
        tool_name = str(params.get("name") or "")
        result = call_tool(tool_name, params.get("arguments") or {})
        return _rpc_result(msg_id, result)
    if is_notification:
        return None
    return _rpc_error(msg_id, -32601, f"method not found: {method}")


def _rpc_result(msg_id: Any, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _rpc_error(msg_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def encode_message(obj: dict) -> bytes:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
    return header + body


def read_message(stream) -> dict | None:
    """Read one MCP/LSP framed message, or one NDJSON line."""
    first = stream.read(1)
    if not first:
        return None
    if first == b"{":
        line = first + stream.readline()
        return json.loads(line.decode("utf-8"))
    buf = bytearray(first)
    while b"\r\n\r\n" not in buf and b"\n\n" not in buf:
        chunk = stream.read(1)
        if not chunk:
            return None
        buf.extend(chunk)
        if len(buf) > 65536:
            raise ValueError("header too large")
    header_blob, _, rest = bytes(buf).partition(b"\r\n\r\n")
    if not rest and b"\n\n" in bytes(buf):
        header_blob, _, rest = bytes(buf).partition(b"\n\n")
    length = None
    for line in header_blob.decode("ascii", errors="replace").splitlines():
        if line.lower().startswith("content-length:"):
            length = int(line.split(":", 1)[1].strip())
    if length is None:
        raise ValueError("missing Content-Length")
    body = rest
    while len(body) < length:
        chunk = stream.read(length - len(body))
        if not chunk:
            break
        body += chunk
    return json.loads(body.decode("utf-8"))


def serve(stdin=None, stdout=None) -> int:
    stdin = stdin or sys.stdin.buffer
    stdout = stdout if stdout is not None else sys.stdout.buffer
    while True:
        try:
            message = read_message(stdin)
        except Exception as exc:  # noqa: BLE001
            stdout.write(encode_message(_rpc_error(None, -32700, str(exc))))
            stdout.flush()
            continue
        if message is None:
            return 0
        response = dispatch(message)
        if response is None:
            continue
        stdout.write(encode_message(response))
        stdout.flush()


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in {"--check", "--tools"}:
        names = [t["name"] for t in tool_list()]
        print("\n".join(names))
        return 0
    if argv:
        print("usage: python3 mcp/vik-mcp/server.py [--check]", file=sys.stderr)
        print("stdio MCP server otherwise. No scan flags.", file=sys.stderr)
        return 2
    return serve()


if __name__ == "__main__":
    raise SystemExit(main())
