#!/usr/bin/env python3
"""Session-scoped tool result cache.

Clean-room idea (not vendored source): avoid re-running the same tool on the
same inputs within a session. This is a helper for hunt.py runners, not a
second orchestrator.

Rules:
  - Off unless VIK_SESSION_TOOL_CACHE=1, so the default scan path is unchanged.
  - Cache key is target + tool + canonical args.
  - Disk lives under <session_dir>/tool_cache/ (0700), never a global cache.
  - Refuse world-writable session directories.
  - Never store secret-looking args or secret-looking output.
  - Respect ScopeChecker (and an optional exact-host allow file). Out-of-scope
    invocations are not cached and are not short-circuited.
  - Artefact-writing / watchdog invocations are never replayed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import stat
from datetime import datetime, timezone
from typing import Any

_SECRET_RE = re.compile(
    r"(?i)("
    r"password|passwd|api[_-]?key|authorization|"
    r"bearer\s+[A-Za-z0-9._\-]{8,}|"
    r"cookie\s*[:=]|set-cookie|"
    r"sessionid|aws_secret|private[_-]?key|"
    r"access[_-]?token|refresh[_-]?token|x-api-key|"
    r"-----BEGIN |"
    r"\bAKIA[0-9A-Z]{16}\b"
    r")"
)

_URL_RE = re.compile(r"https?://([^/\s\"']+)", re.I)
_HOST_FLAG_RE = re.compile(
    r"^(?:-u|--url|-target|--target|--host|-d|--domain|--host-header)$",
    re.I,
)

# Wrappers and state-changing tools are never replayed from cache.
_DENY_TOOLS = frozenset({
    "bash", "sh", "zsh", "env", "sudo", "python", "python3", "perl", "ruby",
    "osascript", "msfconsole", "msfvenom", "sqlmap", "hydra", "medusa",
    "ncrack", "nc", "ncat", "netcat", "socat",
})

_OUTPUT_CAP = 128_000
_CACHE_DIRNAME = "tool_cache"

# In-process binding for the hunt runner. Not process-global disk state.
_BOUND: dict[str, Any] = {}


def cache_enabled(env: dict | None = None) -> bool:
    src = os.environ if env is None else env
    raw = str(src.get("VIK_SESSION_TOOL_CACHE", "")).strip().lower()
    return raw in {"1", "true", "yes", "on"}


def clear_binding() -> None:
    _BOUND.clear()


def current_binding() -> dict:
    return dict(_BOUND)


def bind_session(
    target: str,
    session_dir: str,
    scope_domains: list[str] | None = None,
    scope_ips: list[str] | None = None,
) -> None:
    """Remember the active session. Does not create cache files unless enabled
    and a later store() succeeds."""
    target = (target or "").strip()
    session_dir = os.path.abspath(session_dir) if session_dir else ""
    _BOUND.clear()
    _BOUND.update({
        "target": target,
        "session_dir": session_dir,
        "scope_domains": [d.strip() for d in (scope_domains or []) if d and d.strip()],
        "scope_ips": [d.strip() for d in (scope_ips or []) if d and d.strip()],
    })


def contains_secret(text: str) -> bool:
    if not text:
        return False
    return _SECRET_RE.search(text) is not None


def _looks_like_ip(host: str) -> bool:
    host = (host or "").strip().lower().strip("[]")
    if ":" in host:
        return True
    parts = host.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def tool_name_from_invocation(invocation: str | list[str]) -> str:
    parts = canonicalize_args(invocation)
    for token in parts:
        if "=" in token and not token.startswith("-") and not token.startswith("/"):
            # leading KEY=value env prefix
            key = token.split("=", 1)[0]
            if key.replace("_", "").isalnum():
                continue
        base = os.path.basename(token)
        return base
    return ""


def canonicalize_args(invocation: str | list[str]) -> list[str]:
    if isinstance(invocation, str):
        try:
            return shlex.split(invocation)
        except ValueError:
            return invocation.split()
    return [str(part) for part in invocation]


def make_key(target: str, tool: str, args: list[str]) -> str:
    payload = json.dumps(
        {
            "target": (target or "").strip().lower(),
            "tool": (tool or "").strip(),
            "args": args,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _extract_hosts(args: list[str]) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()

    def _add(raw: str) -> None:
        host = (raw or "").strip().strip("[]").split("/")[0]
        if host.startswith("*."):
            host = host[2:]
        # drop :port on host:port (keep IPv6 alone)
        if host.count(":") == 1 and not _looks_like_ip(host):
            host = host.split(":", 1)[0]
        host = host.lower().rstrip(".")
        if not host or host in seen:
            return
        if host.startswith("-"):
            return
        seen.add(host)
        hosts.append(host)

    for idx, token in enumerate(args):
        for match in _URL_RE.findall(token):
            _add(match)
        if idx + 1 < len(args) and _HOST_FLAG_RE.match(token):
            nxt = args[idx + 1]
            if "://" in nxt:
                for match in _URL_RE.findall(nxt):
                    _add(match)
            else:
                _add(nxt)
    return hosts


def _load_allow_file(session_dir: str) -> list[str] | None:
    path = os.path.join(session_dir, "scope", "allow.txt")
    if not os.path.isfile(path):
        return None
    hosts: list[str] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                item = line.strip()
                if item and not item.startswith("#"):
                    hosts.append(item)
    except OSError:
        return None
    return hosts


def _scope_allows(target: str, args: list[str], session_dir: str,
                  scope_domains: list[str], scope_ips: list[str]) -> bool:
    """Fail closed when a host is present and not in the bound scope."""
    hosts = _extract_hosts(args)
    allow = _load_allow_file(session_dir) if session_dir else None

    domains = list(scope_domains)
    ips = {ip.lower().strip("[]") for ip in scope_ips}
    if allow:
        for item in allow:
            if _looks_like_ip(item):
                ips.add(item.lower().strip("[]"))
            else:
                domains.append(item)
    elif target:
        if _looks_like_ip(target):
            ips.add(target.lower().strip("[]"))
        else:
            domains.append(target)
            wild = "*." + target.lstrip("*.").lower()
            if wild not in domains:
                domains.append(wild)

    if not hosts:
        # No host in args: still require the session target itself to be allowed.
        if not target:
            return False
        return _host_ok(target, domains, ips)

    return all(_host_ok(host, domains, ips) for host in hosts)


def _host_ok(host: str, domains: list[str], ips: set[str]) -> bool:
    host = host.lower().rstrip(".").strip("[]")
    if _looks_like_ip(host):
        return host in ips
    if not domains:
        return False
    try:
        from scope_checker import ScopeChecker
    except Exception:
        return False
    try:
        return ScopeChecker(domains).is_in_scope(host)
    except Exception:
        return False


def _dir_is_private(path: str) -> bool:
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return False
    if not stat.S_ISDIR(mode):
        return False
    # world-writable cache is refused outright
    if mode & stat.S_IWOTH:
        return False
    return True


def cache_dir(session_dir: str) -> str:
    return os.path.join(os.path.abspath(session_dir), _CACHE_DIRNAME)


def _ensure_cache_dir(session_dir: str) -> str | None:
    if not session_dir or not os.path.isdir(session_dir):
        return None
    if not _dir_is_private(session_dir):
        return None
    path = cache_dir(session_dir)
    try:
        os.makedirs(path, exist_ok=True)
        os.chmod(path, 0o700)
    except OSError:
        return None
    if not _dir_is_private(path):
        return None
    return path


def _record_path(session_dir: str, key: str) -> str:
    return os.path.join(cache_dir(session_dir), key + ".json")


def _cacheable(invocation: str | list[str], *, watch_file: str | None = None) -> tuple[bool, str, list[str]]:
    if watch_file:
        return False, "", []
    if isinstance(invocation, str) and (">" in invocation or "`" in invocation or "$(" in invocation):
        return False, "", []
    args = canonicalize_args(invocation)
    if not args:
        return False, "", []
    joined = " ".join(args)
    if contains_secret(joined):
        return False, "", []
    tool = tool_name_from_invocation(args)
    if not tool or tool.lower() in _DENY_TOOLS:
        return False, "", []
    if any(flag in args for flag in ("--allow-destructive", "--exploit")):
        return False, "", []
    return True, tool, args


def lookup(target: str, tool: str, args: str | list[str], session_dir: str) -> dict | None:
    """Read a cached result. Never runs a tool. Returns None on miss/unsafe."""
    if not session_dir or not target or not tool:
        return None
    ok, tool_name, canon = _cacheable([tool, *canonicalize_args(args)] if not isinstance(args, list) else args)
    # lookup accepts an explicit tool + args; do not require the tool token twice
    canon_args = canonicalize_args(args)
    if tool and (not canon_args or os.path.basename(canon_args[0]) != os.path.basename(tool)):
        canon_args = [tool, *canon_args]
    if contains_secret(" ".join(canon_args)) or contains_secret(tool):
        return None
    tool_name = os.path.basename(tool)
    if tool_name.lower() in _DENY_TOOLS:
        return None
    if not _scope_allows(target, canon_args, session_dir, [], []):
        # explicit lookup still checks scope via allow file / target
        if not _scope_allows(target, canon_args, session_dir,
                             _BOUND.get("scope_domains") or [],
                             _BOUND.get("scope_ips") or []):
            return None
    key = make_key(target, tool_name, canon_args)
    path = _record_path(session_dir, key)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(doc, dict):
        return None
    if doc.get("target", "").lower() != target.strip().lower():
        return None
    if doc.get("tool") != tool_name:
        return None
    output = doc.get("output") or ""
    if contains_secret(output):
        return None
    return {
        "hit": True,
        "target": doc.get("target"),
        "tool": tool_name,
        "ok": bool(doc.get("ok")),
        "output": output,
        "truncated": bool(doc.get("truncated")),
        "created_at": doc.get("created_at"),
        "key": key,
        "path": path,
    }


def store(target: str, tool: str, args: str | list[str], ok: bool, output: str,
          session_dir: str,
          scope_domains: list[str] | None = None,
          scope_ips: list[str] | None = None) -> str | None:
    """Persist a successful, non-secret result. Returns path or None if skipped."""
    if not cache_enabled() or not ok:
        return None
    if not session_dir or not target:
        return None
    canon_args = canonicalize_args(args)
    tool_name = os.path.basename(tool or tool_name_from_invocation(canon_args))
    if not tool_name or tool_name.lower() in _DENY_TOOLS:
        return None
    if contains_secret(tool_name) or contains_secret(" ".join(canon_args)):
        return None
    text = output or ""
    if contains_secret(text):
        return None
    domains = list(scope_domains or [])
    ips = list(scope_ips or [])
    if not _scope_allows(target, canon_args, session_dir, domains, ips):
        return None
    dest_dir = _ensure_cache_dir(session_dir)
    if not dest_dir:
        return None
    truncated = False
    if len(text) > _OUTPUT_CAP:
        text = text[:_OUTPUT_CAP]
        truncated = True
    key = make_key(target, tool_name, canon_args)
    path = os.path.join(dest_dir, key + ".json")
    doc = {
        "version": 1,
        "target": target.strip().lower(),
        "tool": tool_name,
        "args": canon_args,
        "ok": True,
        "output": text,
        "truncated": truncated,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "key": key,
    }
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
            fh.write("\n")
        os.chmod(path, 0o600)
        _update_index(dest_dir, key, tool_name, target)
    except OSError:
        return None
    return path


def stats(session_dir: str) -> dict:
    path = cache_dir(session_dir) if session_dir else ""
    count = 0
    if path and os.path.isdir(path):
        count = sum(1 for name in os.listdir(path) if name.endswith(".json") and name != "index.json")
    return {
        "session_dir": session_dir,
        "cache_dir": path,
        "entries": count,
        "enabled": cache_enabled(),
    }


def _update_index(dest_dir: str, key: str, tool: str, target: str) -> None:
    index_path = os.path.join(dest_dir, "index.json")
    doc: dict[str, Any] = {"entries": {}}
    if os.path.isfile(index_path):
        try:
            with open(index_path, encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict) and isinstance(loaded.get("entries"), dict):
                doc = loaded
        except (OSError, json.JSONDecodeError):
            doc = {"entries": {}}
    doc.setdefault("entries", {})[key] = {
        "tool": tool,
        "target": target.strip().lower(),
    }
    with open(index_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    try:
        os.chmod(index_path, 0o600)
    except OSError:
        pass


def lookup_for_runner(invocation: str | list[str], *, watch_file: str | None = None) -> tuple[bool, str] | None:
    """hunt.py hook. None means 'do not short-circuit'."""
    if not cache_enabled():
        return None
    ok, tool, args = _cacheable(invocation, watch_file=watch_file)
    if not ok:
        return None
    target = str(_BOUND.get("target") or "")
    session_dir = str(_BOUND.get("session_dir") or "")
    if not target or not session_dir:
        return None
    if not _scope_allows(
        target, args, session_dir,
        list(_BOUND.get("scope_domains") or []),
        list(_BOUND.get("scope_ips") or []),
    ):
        return None
    hit = lookup(target, tool, args, session_dir)
    if not hit or not hit.get("ok"):
        return None
    output = hit.get("output") or ""
    prefix = "[session-tool-cache hit] "
    if output.startswith(prefix):
        return True, output
    return True, prefix + output


def store_for_runner(invocation: str | list[str], ok: bool, output: str,
                     *, watch_file: str | None = None) -> str | None:
    """hunt.py hook. No-op unless cache is enabled and the call is cacheable."""
    if not cache_enabled() or not ok:
        return None
    cacheable, tool, args = _cacheable(invocation, watch_file=watch_file)
    if not cacheable:
        return None
    target = str(_BOUND.get("target") or "")
    session_dir = str(_BOUND.get("session_dir") or "")
    if not target or not session_dir:
        return None
    # Avoid caching our own replay prefix as a new body.
    text = output or ""
    prefix = "[session-tool-cache hit] "
    if text.startswith(prefix):
        return None
    return store(
        target, tool, args, True, text, session_dir,
        scope_domains=list(_BOUND.get("scope_domains") or []),
        scope_ips=list(_BOUND.get("scope_ips") or []),
    )
