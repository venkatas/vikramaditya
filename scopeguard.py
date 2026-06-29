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
    #
    # TOCTOU NOTE: this gate resolves the target ONCE at scan time; the executing
    # client (curl/nc/sqlmap) re-resolves independently. A short-TTL / DNS-rebinding
    # name that returns a non-loopback A here and 127.0.0.1 at run time can still slip
    # through — this is inherent to any pre-flight DNS check. Callers MUST treat this
    # as a best-effort self-target guard, not an authorization boundary.
    try:
        ips = [ipaddress.ip_address(host)]
    except ValueError:
        addrs = LOOKUP_HOST(host)
        if not addrs:
            # Fail-CLOSED only for a token that DECODES to loopback/unspecified when
            # read as a packed/short-form IPv4 literal — the encoded-loopback
            # evasion: decimal 2130706433 / hex 0x7f000001 / short-form 127.1, all
            # == 127.0.0.1. Block those even when the resolver declines the encoding
            # at check time, so they can't pivot onto our loopback at run time.
            # A bare port / timeout / count integer (4444, 86400, 3600) is NOT swept
            # up: it decodes to a NON-loopback address and stays allowed — narrowing
            # the prior over-broad "any all-digit/0x token" rule that false-positive
            # blocked legitimate commands whose only numeric token was a port. A
            # normal DNS name that simply doesn't resolve also stays allowed.
            _decoded = None
            try:
                _n = int(host, 0)
                if 0 <= _n <= 0xFFFFFFFF:
                    _decoded = ipaddress.ip_address(_n)
            except (ValueError, TypeError):
                pass
            if _decoded is None:
                try:
                    _decoded = ipaddress.ip_address(socket.inet_aton(host))
                except (OSError, ValueError):
                    _decoded = None
            if _decoded is not None and (_decoded.is_loopback or _decoded.is_unspecified):
                return True
            return False  # unresolvable name / non-loopback literal → allow
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

    # Self-listener by RESOLVED IP: a hostname that resolves to our bind IP on our
    # listener port must be blocked too (the textual fast-path above only catches the
    # literal bind-addr string). Honors the documented "bind addr + port" contract
    # regardless of whether the target was given as an IP literal or a name.
    if port and port.isdigit() and cfg.port and int(port) == cfg.port:
        bind = (cfg.bind_addr or "").strip()
        if bind:
            bind_ips = set()
            try:
                bind_ips.add(str(ipaddress.ip_address(bind)))
            except ValueError:
                for a in LOOKUP_HOST(bind):
                    try:
                        bind_ips.add(str(ipaddress.ip_address(a)))
                    except ValueError:
                        pass
            if bind_ips and any(str(ip) in bind_ips for ip in ips):
                return True

    # Block any IP that is one of THIS machine's interfaces (operator's own services),
    # even when it's an otherwise-allowed RFC1918 address.
    local = _local_interface_ips()
    if local and any(str(ip) in local for ip in ips):
        return True

    return False


import re as _re
import shlex as _shlex

# URLs an LLM-written command might target (used as a fallback for tokens that glue a
# URL to surrounding shell syntax so shlex keeps them in one word).
_URL_RE = _re.compile(r"""https?://[^\s'"|;)>]+""", _re.IGNORECASE)

# A token (or colon-field) plausibly references a host/IP if it contains a dot
# (dotted-quad / FQDN / short-form), looks like a decimal integer >=256 (packed IPv4
# such as 2130706433), or is a 0x-hex literal (0x7f000001). Plain alpha flags / option
# words / small port-like ints are skipped so we don't fire getaddrinfo on every word.
_HOSTISH_RE = _re.compile(
    r"""^(?:
        \[[0-9A-Fa-f:.]+\]                  # [::1] bracketed IPv6
      | [0-9A-Fa-f]*:[0-9A-Fa-f:.]+         # ::1 / fe80::1 — IPv6 (MUST contain a colon)
      | 0x[0-9A-Fa-f]+                       # 0x7f000001 hex-packed IPv4
      | [A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+      # dotted: FQDN / IPv4 / short-form 127.1
      | localhost
    )$""",
    _re.VERBOSE,
)
# NOTE: a bare hex-only word (dd, beef, cafe) is deliberately NOT host-ish — the
# old `[0-9A-Fa-f:.]+` alternation matched it and fired getaddrinfo on benign
# command args (`dd bs=...`). Encoded loopback stays covered: decimal-packed
# (2130706433) via _hostish's isdigit branch, 0x-hex (0x7f000001) via the 0x
# alternation, and short-form (127.1) via the dotted alternation.


def _hostish(s: str) -> bool:
    s = (s or "").strip()
    if not s:
        return False
    if s.lower() == "localhost":
        return True
    if s.startswith("0x") and len(s) > 2:
        return True
    if s.isdigit():
        # packed-integer IPv4 candidate; bare small ints (ports/counts) are not hosts.
        return int(s) >= 256
    return bool(_HOSTISH_RE.match(s))


def _candidate_hosts(token: str):
    """Yield host-ish substrings of a single shell token to feed is_local_or_listener.

    Covers bare hosts/IPs, host:port, scheme://host, and connector forms like
    socat's `TCP:host:port` / `UDP4:host:port` / `OPENSSL:host:port`. Encoded IP
    literals (decimal `2130706433`, hex `0x7f000001`, short-form `127.1`) are passed
    through verbatim — is_local_or_listener resolves them via getaddrinfo.
    """
    if not token:
        return
    # URL glued to other shell text → pull the URL out and hand it over whole.
    has_url = False
    for m in _URL_RE.finditer(token):
        has_url = True
        yield m.group(0)
    # Whole token if it already looks host-ish (bare host[:port] or dotted/encoded IP).
    bare = token
    if bare.count(":") == 1 and bare.rsplit(":", 1)[1].isdigit():
        bare = bare.rsplit(":", 1)[0]
    if _hostish(bare):
        yield token
    # connector / prefixed forms: socat TCP:host:port, foo=host:port, etc.
    # Peel a leading PROTO: / key= prefix and a trailing :port so the host literal
    # (decimal/hex/short-form included) is tested on its own.
    if not has_url and (":" in token or "=" in token):
        parts = [p for p in token.replace("=", ":").split(":") if p]
        for p in parts:
            if _hostish(p):
                yield p


def scan_command(command: str, cfg: Config = None) -> str:
    """Scan an LLM-authored shell command for a self-target (operator machine/listener).

    Returns the first offending target token, or None if the command is clean. Used to
    gate brain_scanner.execute_script and agent tool dispatch so the agent cannot curl /
    sqlmap / nc the operator's own box or listener.

    Tokenizes the command with shlex and feeds every word (and its host substrings) to
    is_local_or_listener, which already resolves dotted-quad, decimal, hex, short-form,
    and DNS hosts via getaddrinfo. This closes the prior fail-OPEN gap where encoded
    loopback literals (e.g. `nc 2130706433 4444`, `nc 0x7f000001 9000`,
    `socat - TCP:2130706433:9000`, `nc 127.1 4444`) were never extracted and so ran.
    """
    cfg = cfg or Config.from_env()
    cmd = command or ""
    try:
        tokens = _shlex.split(cmd, posix=True)
    except ValueError:
        # Unbalanced quotes etc. — fall back to whitespace splitting so we still scan.
        tokens = cmd.split()
    for tok in tokens:
        for cand in _candidate_hosts(tok):
            if is_local_or_listener(cand, cfg):
                # Return the offending whole token for a readable block message.
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
