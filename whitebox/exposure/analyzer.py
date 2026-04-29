from __future__ import annotations


def is_public_to_internet(sg: dict) -> bool:
    for perm in sg.get("IpPermissions", []):
        for r in perm.get("IpRanges", []):
            if r.get("CidrIp") == "0.0.0.0/0":
                return True
        for r in perm.get("Ipv6Ranges", []):
            if r.get("CidrIpv6") == "::/0":
                return True
    return False


def analyze_security_groups(sgs: list[dict]) -> dict[str, dict]:
    """Return {sg_id: {public, exposed_ports, exposed_cidrs}}."""
    result: dict[str, dict] = {}
    for sg in sgs:
        sgid = sg.get("GroupId", "")
        ports: set[int] = set()
        cidrs: set[str] = set()
        public = False
        for perm in sg.get("IpPermissions", []):
            proto = perm.get("IpProtocol")
            fp, tp = perm.get("FromPort"), perm.get("ToPort")
            # IpProtocol "-1" means all traffic — represents the full port range
            if proto == "-1" or proto == -1:
                ports.update(range(0, 65536))
            elif fp is not None and tp is not None:
                ports.update(range(fp, tp + 1))
            for r in perm.get("IpRanges", []):
                cidr = r.get("CidrIp", "")
                if cidr:
                    cidrs.add(cidr)
                    if cidr == "0.0.0.0/0":
                        public = True
            for r in perm.get("Ipv6Ranges", []):
                cidr6 = r.get("CidrIpv6", "")
                if cidr6:
                    cidrs.add(cidr6)
                    if cidr6 == "::/0":
                        public = True
        result[sgid] = {
            "public": public,
            "exposed_ports": sorted(ports),
            "exposed_cidrs": sorted(cidrs),
        }
    return result
