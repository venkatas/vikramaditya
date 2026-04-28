from __future__ import annotations
from whitebox.models import Asset


def join_blackbox_to_cloud(blackbox_hosts: list[str], cloud_assets: list[Asset]) -> dict[str, Asset | None]:
    """Map each blackbox host (DNS or IP) to a cloud Asset (or None)."""
    by_dns = {a.public_dns: a for a in cloud_assets if a.public_dns}
    by_ip = {a.public_ip: a for a in cloud_assets if a.public_ip}
    return {host: by_dns.get(host) or by_ip.get(host) for host in blackbox_hosts}
