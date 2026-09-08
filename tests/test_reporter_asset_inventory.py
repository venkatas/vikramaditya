"""Asset Inventory chapter — subdomain / DNS / httpx status surfaces.

Locks the collector + HTML/MD renderers to read session recon artefacts
(subfinder/amass/alterx, resolved hosts, httpx status buckets, ports)
rather than inventing new scan steps. Huge alterx/merged dumps must be
count-only; long lists truncate with an "... and N more" note.
"""
from pathlib import Path

import reporter


def _write_full_recon(tmp_path: Path) -> str:
    recon = tmp_path / "recon" / "t.example" / "sessions" / "s1"
    subs = recon / "subdomains"
    live = recon / "live"
    ports = recon / "ports"
    for d in (subs, live, ports):
        d.mkdir(parents=True)

    (subs / "subfinder.txt").write_text(
        "\n".join(f"h{i}.t.example" for i in range(1, 12)) + "\n")
    (subs / "amass.txt").write_text("a1.t.example\na2.t.example\n")
    (subs / "assetfinder.txt").write_text("af.t.example\n")
    # Huge alterx dump — must be count-only in the report.
    (subs / "alterx.txt").write_text(
        "\n".join(f"perm{i}.t.example" for i in range(500)) + "\n")
    (subs / "all.txt").write_text(
        "\n".join(f"all{i}.t.example" for i in range(300)) + "\n")
    (subs / "resolved.txt").write_text(
        "t.example\napi.t.example\nmssql.t.example\n")

    (live / "httpx_full.txt").write_text(
        "https://t.example [200] [100] [Home] [1.2.3.4] [nginx]\n"
        "https://api.t.example [301] [10] [Moved] [1.2.3.5] [cloudflare]\n"
        "http://mssql.t.example [404] [20] [Nope] [1.2.3.4] [IIS]\n"
    )
    (live / "urls.txt").write_text(
        "https://t.example\nhttps://api.t.example\nhttp://mssql.t.example\n")
    (live / "status_200.txt").write_text(
        "https://t.example [200] [100] [Home] [1.2.3.4] [nginx]\n")
    (live / "status_3xx.txt").write_text(
        "https://api.t.example [301] [10] [Moved] [1.2.3.5] [cloudflare]\n")
    (live / "ips.txt").write_text("1.2.3.4\n1.2.3.5\n")
    (ports / "open_ports.txt").write_text("443/open\n8443/open\n")
    (ports / "nmap_greppable.txt").write_text(
        "Host: 1.2.3.4 ()\tPorts: 443/open/tcp//https///, "
        "8443/open/tcp//ssl|https-alt?///\n")
    return str(recon)


def test_collect_asset_inventory_counts(tmp_path):
    recon = _write_full_recon(tmp_path)
    inv = reporter._collect_asset_inventory(recon)
    assert inv["has_data"]
    by_tool = {s["tool"]: s for s in inv["sources"]}
    assert by_tool["subfinder"]["count"] == 11
    assert "h1.t.example" in by_tool["subfinder"]["sample"]
    assert by_tool["amass"]["count"] == 2
    assert by_tool["alterx"]["count_only"] is True
    assert by_tool["alterx"]["count"] == 500
    assert by_tool["alterx"]["sample"] == []
    assert by_tool["merged (all.txt)"]["count_only"] is True
    assert len(inv["resolved"]) == 3
    assert len(inv["live_hosts"]) == 3
    status = {s["label"]: s["count"] for s in inv["status_breakdown"]}
    assert status.get("HTTP 200") == 1
    assert status.get("HTTP 3xx") == 1
    assert any(p["port"] == "8443/open" for p in inv["ports"])


def test_asset_inventory_html_surfaces_subfinder_and_http200(tmp_path):
    recon = _write_full_recon(tmp_path)
    out = reporter._render_recon_inventory_html(recon, "t.example")
    assert "Asset Inventory" in out
    assert "Subdomain Discovery" in out
    assert "subfinder" in out
    assert "h1.t.example" in out
    assert "DNS Resolved Hosts" in out
    assert "mssql.t.example" in out
    assert "HTTP Status Breakdown" in out
    assert "HTTP 200" in out
    assert "count only" in out  # alterx / merged
    assert "perm0.t.example" not in out  # must not dump alterx
    assert "8443/open" in out
    # No absolute path leaks
    assert str(tmp_path) not in out


def test_asset_inventory_md_twin(tmp_path):
    recon = _write_full_recon(tmp_path)
    md = reporter._render_recon_inventory_md(recon, "t.example")
    assert "## Asset Inventory" in md
    assert "### Subdomain Discovery" in md
    assert "subfinder" in md
    assert "### DNS Resolved Hosts" in md
    assert "### HTTP Status Breakdown" in md
    assert "HTTP 200" in md
    assert "count only" in md
    assert "perm0.t.example" not in md


def test_asset_inventory_in_full_markdown_report(tmp_path):
    recon = _write_full_recon(tmp_path)
    md = reporter.render_markdown_report([], "t.example", recon, "", "", "VAPT")
    assert "## Asset Inventory" in md
    assert "subfinder" in md
    assert "HTTP 200" in md


def test_asset_inventory_empty_still_silent(tmp_path):
    empty = tmp_path / "recon" / "t.example" / "sessions" / "empty"
    empty.mkdir(parents=True)
    assert reporter._render_recon_inventory_html(str(empty), "t.example") == ""
    assert reporter._render_recon_inventory_md(str(empty), "t.example") == ""


def test_asset_inventory_from_reports_layout(tmp_path):
    """report_dir under reports/ must resolve sibling recon/ artefacts."""
    recon = tmp_path / "recon" / "t.example" / "sessions" / "s1"
    reports = tmp_path / "reports" / "t.example" / "sessions" / "s1"
    (recon / "subdomains").mkdir(parents=True)
    reports.mkdir(parents=True)
    (recon / "subdomains" / "subfinder.txt").write_text("only.t.example\n")
    (recon / "subdomains" / "resolved.txt").write_text("only.t.example\n")
    out = reporter._render_recon_inventory_html(str(reports), "t.example")
    assert "Asset Inventory" in out
    assert "only.t.example" in out
    assert "subfinder" in out
