from whitebox.correlator.asset_join import join_blackbox_to_cloud
from whitebox.models import Asset


def test_join_matches_by_public_dns():
    cloud = [Asset(arn="arn:ec2:i-1", service="ec2", account_id="1",
                   region="us-east-1", name="i-1", tags={},
                   public_dns="ec2-1-2-3-4.compute.amazonaws.com",
                   public_ip="1.2.3.4")]
    blackbox_hosts = ["ec2-1-2-3-4.compute.amazonaws.com"]
    result = join_blackbox_to_cloud(blackbox_hosts, cloud)
    assert result["ec2-1-2-3-4.compute.amazonaws.com"].arn == "arn:ec2:i-1"


def test_join_matches_by_public_ip():
    cloud = [Asset(arn="arn:ec2:i-1", service="ec2", account_id="1",
                   region="us-east-1", name="i-1", tags={},
                   public_ip="1.2.3.4")]
    result = join_blackbox_to_cloud(["1.2.3.4"], cloud)
    assert result["1.2.3.4"].name == "i-1"


def test_join_no_match_returns_none():
    cloud = [Asset(arn="arn:ec2:i-1", service="ec2", account_id="1",
                   region="us-east-1", name="i-1", tags={}, public_ip="9.9.9.9")]
    result = join_blackbox_to_cloud(["1.2.3.4"], cloud)
    assert result["1.2.3.4"] is None


def test_join_normalizes_url_scheme_and_port():
    cloud = [Asset(arn="arn:ec2:i-1", service="ec2", account_id="1",
                   region="us-east-1", name="i-1", tags={},
                   public_dns="ec2-1-2-3-4.compute.amazonaws.com")]
    result = join_blackbox_to_cloud(
        ["https://ec2-1-2-3-4.compute.amazonaws.com:443/path"], cloud)
    assert result["https://ec2-1-2-3-4.compute.amazonaws.com:443/path"].arn == "arn:ec2:i-1"


def test_join_normalizes_case_and_trailing_dot():
    cloud = [Asset(arn="arn:ec2:i-1", service="ec2", account_id="1",
                   region="us-east-1", name="i-1", tags={},
                   public_dns="host.example.com")]
    result = join_blackbox_to_cloud(["HOST.EXAMPLE.COM."], cloud)
    assert result["HOST.EXAMPLE.COM."].arn == "arn:ec2:i-1"
