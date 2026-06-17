"""Stop the LLM-driven agent / brain_scanner from attacking the OPERATOR'S OWN machine.

Adapted from xalgorix (MIT) — internal/scopeguard/scopeguard.go.

The agent and brain_scanner execute LLM-authored commands/code against arbitrary hosts.
A poisoned page or an SSRF payload the agent "tests" could otherwise pivot into the
operator's own box or the Vikramaditya listener — outside authorized scope. This gate
blocks ONLY self-targets:

  * loopback (127.0.0.0/8, ::1, localhost) and unspecified (0.0.0.0, ::)
  * the operator's own listener (bind addr + port, incl. 0.0.0.0/:: on that port)
  * any IP matching one of THIS machine's network interfaces (operator's own services)

It deliberately does NOT blanket-block RFC1918 / link-local / cloud-metadata
(169.254.169.254): those are LEGITIMATE SSRF and internal-pivot targets on the *scanned*
host's network during an authorized engagement. The goal is "don't attack ourselves",
not "restrict pentesting".

Operator-listener identity comes from OPERATOR_BIND_ADDR / OPERATOR_PORT (Config.from_env()).
"""
import ipaddress
import os
import socket
from urllib.parse import urlparse


class OutOfScopeError(Exception):
    """Raised when a tool target classifies as the operator's own machine/listener."""


class Config:
    def __init__(self, bind_addr: str = "127.0.0.1", port: int = 0):
        self.bind_addr = bind_addr
        self.port = port

    @classmethod
    def from_env(cls) -> "Config":
        bind = os.environ.get("OPERATOR_BIND_ADDR", "127.0.0.1")
        try:
            port = int(os.environ.get("OPERATOR_PORT", "0") or "0")
        except ValueError:
            port = 0
        return cls(bind_addr=bind, port=port)


def _lookup_host(host: str) -> list:
    """Resolve host → list of IP strings (like Go net.LookupHost). Empty on failure."""
    try:
        return list({info[4][0] for info in socket.getaddrinfo(host, None)})
    except Exception:
        return []


# Resolver indirection — tests monkeypatch this single var / call site.
LOOKUP_HOST = _lookup_host


def _local_interface_ips() -> set:
    """IPs bound to this machine's network interfaces (the operator's own host)."""
    ips: set = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(info[4][0])
    except Exception:
        pass
    # primary outbound IP (covers the case where gethostname() doesn't enumerate it)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ips.add(s.getsockname()[0])
        finally:
            s.close()
    except Exception:
        pass
    return ips


def _split_host_port(target: str):
    """Extract (host, port_str) from a bare host, host:port, scheme://host[:port][/path],
    or [ipv6][:port]. port_str is '' when absent."""
    t = (target or "").strip()
    if "://" in t:
        u = urlparse(t)
        if u.hostname:
            return u.hostname, (str(u.port) if u.port else "")
    # [ipv6]:port  /  [ipv6]
    if t.startswith("["):
        end = t.find("]")
        if end != -1:
            host = t[1:end]
            rest = t[end + 1:]
            port = rest[1:] if rest.startswith(":") else ""
            return host, port
    # host:port (single colon, not bare ipv6)
    if t.count(":") == 1:
        h, p = t.rsplit(":", 1)
        if p.isdigit():
            return h, p
    return t, ""


def is_local_or_listener(target: str, cfg: Config = None) -> bool:
    """True when `target` points at the operator's own machine or listener."""
    cfg = cfg or Config.from_env()
    host, port = _split_host_port(target)
    host = (host or "").strip()
    lower = host.lower()

    # Self-listener textual fast-path: same port as our listener AND host textually
    # matches our bind addr (or 0.0.0.0 / ::). Fires before DNS.
    if port and port.isdigit() and cfg.port and int(port) == cfg.port:
        bind = (cfg.bind_addr or "127.0.0.1").strip().lower()
        if lower in (bind, "0.0.0.0", "::"):
            return True

    # Explicit textual self-matches.
    if lower in ("localhost", "0.0.0.0", "::1", "[::1]"):
        return True

    # Resolve host → IPs (literal IPs skip DNS).
    try:
        ips = [ipaddress.ip_address(host)]
    except ValueError:
        addrs = LOOKUP_HOST(host)
        if not addrs:
            return False  # unresolvable → allow; it will fail naturally downstream
        ips = []
        for a in addrs:
            try:
                ips.append(ipaddress.ip_address(a))
            except ValueError:
                pass
        if not ips:
            return False

    # Block loopback / unspecified always.
    for ip in ips:
        if ip.is_loopback or ip.is_unspecified:
            return True

    # Block any IP that is one of THIS machine's interfaces (operator's own services),
    # even when it's an otherwise-allowed RFC1918 address.
    local = _local_interface_ips()
    if local and any(str(ip) in local for ip in ips):
        return True

    return False


import re as _re

# URLs, and bare IPv4 / localhost tokens an LLM-written command might target.
_TARGET_RE = _re.compile(
    r"""(?:https?://[^\s'"|;)>]+)"""          # http(s) URLs
    r"""|(?:\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b)"""  # bare IPv4[:port]
    r"""|(?:\blocalhost(?::\d+)?\b)""",        # localhost[:port]
    _re.IGNORECASE,
)


def scan_command(command: str, cfg: Config = None) -> str:
    """Scan an LLM-authored shell command for a self-target (operator machine/listener).

    Returns the first offending target token, or None if the command is clean. Used to
    gate brain_scanner.execute_script and agent tool dispatch so the agent cannot curl /
    sqlmap / nc the operator's own box or listener.
    """
    cfg = cfg or Config.from_env()
    for m in _TARGET_RE.finditer(command or ""):
        tok = m.group(0)
        if is_local_or_listener(tok, cfg):
            return tok
    return None


def assert_in_scope(target: str, cfg: Config = None) -> None:
    """Raise OutOfScopeError if `target` is the operator's own machine/listener."""
    if is_local_or_listener(target, cfg):
        raise OutOfScopeError(
            f"blocked self-target {target!r}: points at the operator's own machine/listener "
            f"(loopback/unspecified/local-interface). Set OPERATOR_BIND_ADDR/OPERATOR_PORT "
            f"to identify the listener. RFC1918/cloud-metadata SSRF targets are NOT blocked."
        )
