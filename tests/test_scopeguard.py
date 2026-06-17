"""Block the LLM-driven agent / brain_scanner from attacking the OPERATOR'S OWN machine.

Adapted from xalgorix (MIT) internal/scopeguard. The gate is SMART: it blocks loopback,
unspecified, the operator's own listener (bind+port), and this machine's interface IPs —
but deliberately ALLOWS RFC1918 / link-local / cloud-metadata, which are legitimate SSRF and
internal targets in an authorized engagement. The point is "don't let the agent pivot into
the operator's box / listener", NOT "restrict pentesting".
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import scopeguard  # noqa: E402


@pytest.fixture
def cfg():
    return scopeguard.Config(bind_addr="127.0.0.1", port=9000)


@pytest.fixture(autouse=True)
def _no_real_interfaces(monkeypatch):
    # default: nothing matches a local interface unless a test stubs it
    monkeypatch.setattr(scopeguard, "_local_interface_ips", lambda: set())


# ── always-self literals → BLOCKED ────────────────────────────────────────────

@pytest.mark.parametrize("target", [
    "http://127.0.0.1/admin",
    "http://127.0.0.1:9000/x",
    "http://localhost/x",
    "http://[::1]:8080/",
    "http://0.0.0.0/",
    "127.0.0.1",
    "localhost",
])
def test_loopback_and_unspecified_blocked(cfg, target):
    assert scopeguard.is_local_or_listener(target, cfg) is True


# ── operator's own listener (bind+port) → BLOCKED ─────────────────────────────

@pytest.mark.parametrize("target", [
    "http://0.0.0.0:9000/",
    "http://[::]:9000/",
    "http://127.0.0.1:9000/",
])
def test_self_listener_blocked(cfg, target):
    assert scopeguard.is_local_or_listener(target, cfg) is True


def test_empty_bind_defaults_to_loopback(monkeypatch):
    c = scopeguard.Config(bind_addr="", port=9000)
    assert scopeguard.is_local_or_listener("http://127.0.0.1:9000/", c) is True


# ── RFC1918 / link-local / cloud-metadata → ALLOWED (legit SSRF targets) ──────

@pytest.mark.parametrize("target", [
    "http://10.0.0.1/",
    "http://192.168.1.1/",
    "http://172.16.5.4/",
    "http://169.254.169.254/latest/meta-data/",   # cloud metadata — MUST be testable
    "http://93.184.216.34/",                        # public IP
    "https://example.com/",
])
def test_private_and_public_allowed(cfg, target, monkeypatch):
    # these resolve to themselves (IP literals) or a public IP; none are our interface
    monkeypatch.setattr(scopeguard, "LOOKUP_HOST", lambda h: ["93.184.216.34"])
    assert scopeguard.is_local_or_listener(target, cfg) is False


# ── hostname that RESOLVES to loopback → BLOCKED (DNS-rebind self-probe) ───────

def test_hostname_resolving_to_loopback_blocked(cfg, monkeypatch):
    monkeypatch.setattr(scopeguard, "LOOKUP_HOST", lambda h: ["127.0.0.1"])
    assert scopeguard.is_local_or_listener("http://sneaky.evil.test/", cfg) is True


def test_unresolvable_host_allowed(cfg, monkeypatch):
    monkeypatch.setattr(scopeguard, "LOOKUP_HOST", lambda h: [])
    assert scopeguard.is_local_or_listener("http://nope.invalid/", cfg) is False


# ── target matching a local interface IP → BLOCKED (operator's own services) ──

def test_local_interface_ip_blocked(cfg, monkeypatch):
    monkeypatch.setattr(scopeguard, "_local_interface_ips", lambda: {"192.168.1.50"})
    # 192.168.1.50 is RFC1918 (normally allowed) BUT it's THIS machine → block
    assert scopeguard.is_local_or_listener("http://192.168.1.50:22/", cfg) is True
    # a different RFC1918 host is still allowed
    assert scopeguard.is_local_or_listener("http://192.168.1.99/", cfg) is False


# ── Config.from_env wiring ────────────────────────────────────────────────────

def test_config_from_env(monkeypatch):
    monkeypatch.setenv("OPERATOR_BIND_ADDR", "10.1.2.3")
    monkeypatch.setenv("OPERATOR_PORT", "8137")
    c = scopeguard.Config.from_env()
    assert c.bind_addr == "10.1.2.3" and c.port == 8137


# ── assert_in_scope raises for blocked, passes for allowed ────────────────────

def test_assert_in_scope_raises(cfg, monkeypatch):
    monkeypatch.setattr(scopeguard, "LOOKUP_HOST", lambda h: ["1.2.3.4"])
    with pytest.raises(scopeguard.OutOfScopeError):
        scopeguard.assert_in_scope("http://127.0.0.1/x", cfg)
    scopeguard.assert_in_scope("http://1.2.3.4/x", cfg)  # no raise


# ── scan_command: find a self-target inside an LLM-authored shell command ─────

def test_scan_command_flags_loopback_curl(cfg):
    assert scopeguard.scan_command("curl -s http://127.0.0.1:8137/admin", cfg) is not None
    assert scopeguard.scan_command("sqlmap -u http://localhost/login --batch", cfg) is not None
    assert scopeguard.scan_command("nc 0.0.0.0 9000", cfg) is not None


def test_scan_command_allows_external_and_ssrf(cfg, monkeypatch):
    monkeypatch.setattr(scopeguard, "LOOKUP_HOST", lambda h: ["93.184.216.34"])
    assert scopeguard.scan_command("curl https://example.com/api", cfg) is None
    # cloud-metadata SSRF probe is allowed (legit test)
    assert scopeguard.scan_command("curl http://169.254.169.254/latest/meta-data/", cfg) is None
    assert scopeguard.scan_command("nuclei -u http://10.0.0.5/ -t cves/", cfg) is None


def test_scan_command_returns_the_offending_target(cfg):
    hit = scopeguard.scan_command("echo hi && curl http://localhost/x", cfg)
    assert hit and "localhost" in hit
