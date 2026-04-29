from __future__ import annotations
from urllib.parse import urlparse
from whitebox.models import Asset


def _normalize(host: str) -> str:
    """Lowercase, strip scheme/port, strip trailing dots. Returns empty for falsy input."""
    if not host:
        return ""
    h = host.strip()
    # Strip URL scheme if present
    if "://" in h:
        try:
            parsed = urlparse(h)
            h = parsed.hostname or h
        except Exception:
            pass
    # Strip default ports / any explicit port
    if ":" in h and not h.startswith("["):  # not IPv6 bracketed
        # Only strip if it looks like host:port (port is digits)
        host_part, _, port_part = h.rpartition(":")
        if port_part.isdigit() and host_part:
            h = host_part
    # Lowercase and strip trailing dots
    return h.lower().rstrip(".")


def join_blackbox_to_cloud(blackbox_hosts: list[str], cloud_assets: list[Asset]) -> dict[str, Asset | None]:
    """Map each blackbox host (DNS or IP) to a cloud Asset (or None).

    Both sides are normalized: lowercase, scheme/port stripped, trailing dots removed.
    Original host string is preserved as the result key for caller traceability.
    """
    by_dns = {_normalize(a.public_dns): a for a in cloud_assets if a.public_dns}
    by_ip = {a.public_ip: a for a in cloud_assets if a.public_ip}
    result: dict[str, Asset | None] = {}
    for host in blackbox_hosts:
        norm = _normalize(host)
        result[host] = by_dns.get(norm) or by_ip.get(norm) or by_ip.get(host)
    return result
