from whitebox.exposure.analyzer import analyze_security_groups, is_public_to_internet
from whitebox.exposure.tagger import tag_assets
from whitebox.models import Asset


def test_is_public_to_internet_detects_open_cidr():
    sg = {"IpPermissions": [{
        "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }]}
    assert is_public_to_internet(sg)


def test_is_public_to_internet_false_for_private_cidr():
    sg = {"IpPermissions": [{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
    }]}
    assert not is_public_to_internet(sg)


def test_analyze_security_groups_extracts_ports_and_cidrs():
    sg = {"GroupId": "sg-1", "IpPermissions": [{
        "IpProtocol": "tcp", "FromPort": 80, "ToPort": 443,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}, {"CidrIp": "1.2.3.4/32"}],
    }]}
    result = analyze_security_groups([sg])
    assert result["sg-1"]["public"] is True
    assert 80 in result["sg-1"]["exposed_ports"]
    assert 443 in result["sg-1"]["exposed_ports"]
    assert "0.0.0.0/0" in result["sg-1"]["exposed_cidrs"]


def test_tag_assets_marks_internet_reachable():
    asset = Asset(arn="arn:ec2:i-1", service="ec2", account_id="1",
                  region="us-east-1", name="i-1", tags={},
                  public_ip="1.2.3.4")
    instance_sg_map = {"i-1": ["sg-1"]}
    sg_analysis = {"sg-1": {"public": True, "exposed_ports": [443], "exposed_cidrs": ["0.0.0.0/0"]}}

    tagged = tag_assets([asset], instance_sg_map, sg_analysis, waf_protected_arns=set())
    assert tagged[0].tags["internet_reachable"] is True
    assert tagged[0].tags["exposed_ports"] == [443]
    assert tagged[0].tags["behind_waf"] is False


def test_analyze_security_groups_detects_ipv6_open():
    sg = {"GroupId": "sg-2", "IpPermissions": [{
        "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
    }]}
    result = analyze_security_groups([sg])
    assert result["sg-2"]["public"] is True
    assert "::/0" in result["sg-2"]["exposed_cidrs"]


def test_analyze_security_groups_all_traffic_protocol_minus_one():
    sg = {"GroupId": "sg-3", "IpPermissions": [{
        "IpProtocol": "-1",  # No FromPort/ToPort
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }]}
    result = analyze_security_groups([sg])
    assert result["sg-3"]["public"] is True
    # All ports 0-65535 should be in exposed_ports
    assert 0 in result["sg-3"]["exposed_ports"]
    assert 65535 in result["sg-3"]["exposed_ports"]
    assert len(result["sg-3"]["exposed_ports"]) == 65536


def test_analyze_security_groups_captures_descriptions_v9_p22():
    """v9.0 P22: operator-tagged Description field on a public ingress rule
    must round-trip into the analyzer output so the report can quote
    operator intent ("Mongo DB" was the canonical example from the
    engagement that motivated this)."""
    sg = {"GroupId": "sg-mongo", "IpPermissions": [{
        "IpProtocol": "tcp", "FromPort": 27017, "ToPort": 27017,
        "IpRanges": [
            {"CidrIp": "0.0.0.0/0", "Description": "Mongo DB"},
            {"CidrIp": "10.0.0.0/8", "Description": "vpn-only"},  # private; should NOT be captured
        ],
    }]}
    result = analyze_security_groups([sg])
    descs = result["sg-mongo"]["descriptions"]
    assert len(descs) == 1, "only the public-CIDR description should round-trip"
    assert descs[0]["cidr"] == "0.0.0.0/0"
    assert descs[0]["description"] == "Mongo DB"
    assert descs[0]["from_port"] == 27017
    assert descs[0]["proto"] == "tcp"


def test_analyze_security_groups_no_descriptions_when_blank():
    """Most operators leave Description blank — return an empty list, not None."""
    sg = {"GroupId": "sg-blank", "IpPermissions": [{
        "IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }]}
    result = analyze_security_groups([sg])
    assert result["sg-blank"]["descriptions"] == []


def test_analyze_security_groups_captures_ipv6_descriptions():
    """IPv6 :: /0 ingress descriptions should also round-trip."""
    sg = {"GroupId": "sg-v6", "IpPermissions": [{
        "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
        "Ipv6Ranges": [{"CidrIpv6": "::/0", "Description": "world-https"}],
    }]}
    result = analyze_security_groups([sg])
    descs = result["sg-v6"]["descriptions"]
    assert descs == [{"cidr": "::/0", "proto": "tcp", "from_port": 443, "to_port": 443, "description": "world-https"}]
