from pathlib import Path

import hunt


def test_status_does_not_label_priority_hosts_as_findings(tmp_path, monkeypatch, capsys):
    recon_root = tmp_path / "recon"
    target_root = recon_root / "example.com"
    priority = target_root / "priority"
    priority.mkdir(parents=True)
    (priority / "critical_hosts.txt").write_text("critical.example.com\n")
    (priority / "high_hosts.txt").write_text("one.example.com\ntwo.example.com\n")

    targets_root = tmp_path / "targets"
    targets_root.mkdir()
    monkeypatch.setattr(hunt, "RECON_DIR", str(recon_root))
    monkeypatch.setattr(hunt, "TARGETS_DIR", str(targets_root))
    monkeypatch.setattr(hunt, "FINDINGS_DIR", str(tmp_path / "findings"))
    monkeypatch.setattr(hunt, "REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setattr(hunt, "check_tools", lambda: ([], []))
    monkeypatch.setattr(hunt, "check_tool_readiness", lambda _installed: [])
    monkeypatch.setattr(hunt, "_resolve_recon_dir", lambda _domain: str(target_root))
    monkeypatch.setattr(hunt, "_active_recon_session_id", lambda _domain: None)

    hunt.show_status()
    output = capsys.readouterr().out

    assert "reconnaissance priorities, not vulnerability severities" in output
    assert "P-CRIT-HOSTS=1" in output
    assert "P-HIGH-HOSTS=2" in output


def test_status_distinguishes_binary_presence_from_operational_readiness(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
    monkeypatch.setattr(hunt, "TARGETS_DIR", str(tmp_path / "targets"))
    monkeypatch.setattr(hunt, "FINDINGS_DIR", str(tmp_path / "findings"))
    monkeypatch.setattr(hunt, "REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setattr(hunt, "TOOL_REGISTRY", [
        ("git-hound", "git-hound", "install"),
        ("nmap", "nmap", "install"),
    ])
    monkeypatch.setattr(hunt, "check_tools", lambda: (["git-hound", "nmap"], []))
    monkeypatch.setattr(hunt, "check_tool_readiness", lambda _installed: [{
        "tool": "git-hound",
        "reason": "no usable config",
    }])

    hunt.show_status()
    output = capsys.readouterr().out

    assert "Binary presence:" in output and "2/2" in output
    assert "Operational tools: 1/2 (NOT READY)" in output
    assert "git-hound: no usable config" in output
