import importlib, sys

def test_import_graceful_without_deps():
    """Module must import cleanly even if browser-use is not installed."""
    for key in list(sys.modules.keys()):
        if "browser_use" in key:
            del sys.modules[key]
    mod = importlib.import_module("browser_agent")
    assert hasattr(mod, "BrowserAgent")
    assert hasattr(mod, "init_browser_llm")

def test_browser_agent_missing_deps_returns_none():
    """_force_missing=True simulates the missing-dep guard path."""
    import browser_agent
    llm = browser_agent.init_browser_llm(model_override=None, _force_missing=True)
    assert llm is None

def test_browser_agent_init(tmp_path):
    import browser_agent
    agent = browser_agent.BrowserAgent(
        target="https://example.com",
        findings_dir=tmp_path / "findings",
        headed=False,
        model_override=None,
        session_id=None,
    )
    assert agent.target == "https://example.com"
    assert agent.findings_dir == tmp_path / "findings"

def test_findings_dir_created_on_init(tmp_path):
    import browser_agent
    agent = browser_agent.BrowserAgent(
        target="https://x.com",
        findings_dir=tmp_path / "findings",
        session_id=None,
    )
    assert (agent.findings_dir / "browser" / "screenshots").is_dir()

def test_write_finding_returns_int(tmp_path):
    import browser_agent
    agent = browser_agent.BrowserAgent(
        target="https://example.com",
        findings_dir=tmp_path,
        session_id=None,
    )
    task = browser_agent.XSSDOMTask("https://example.com", str(tmp_path))
    result_text = (
        "https://example.com/search?q=x [xss_dom] [high] DOM XSS via innerHTML\n"
        "Some other non-finding line\n"
        "https://example.com/page [xss_dom] [high] Another finding\n"
    )
    count = agent._write_finding(task, result_text)
    assert isinstance(count, int)
    assert count == 2

def test_all_task_classes_exist():
    import browser_agent
    for cls in [
        "XSSDOMTask", "XSSReflectedBrowserTask", "CSRFTask",
        "AuthBypassTask", "OpenRedirectTask", "FormDiscoveryTask"
    ]:
        assert hasattr(browser_agent, cls), f"Missing: {cls}"

def test_task_has_required_attrs():
    import browser_agent
    task = browser_agent.XSSDOMTask("https://example.com", "/tmp/findings")
    assert hasattr(task, "prompt")
    assert hasattr(task, "vtype")
    assert hasattr(task, "severity")
    assert "example.com" in task.prompt
    assert task.output_file().endswith("browser/xss_dom/xss_dom.txt")

def test_xss_reflected_task_accepts_candidates():
    import browser_agent
    candidates = ["https://example.com/search?q=test", "https://example.com/q=x"]
    task = browser_agent.XSSReflectedBrowserTask(
        "https://example.com", "/tmp/findings", candidates=candidates
    )
    assert "search?q=test" in task.prompt

def test_form_discovery_output_file_differs():
    import browser_agent
    task = browser_agent.FormDiscoveryTask("https://example.com", "/tmp/findings")
    assert task.output_file().endswith("form_discovery.txt")
    assert "browser/xss" not in task.output_file()

def test_reporter_has_browser_subdirs():
    import reporter
    assert reporter.SUBDIR_VTYPE["browser/xss_dom"] == "xss_dom"
    assert reporter.SUBDIR_VTYPE["browser/csrf"] == "csrf"
    assert reporter.SUBDIR_VTYPE["browser/auth_bypass"] == "auth_bypass"
    assert reporter.SUBDIR_VTYPE["browser/open_redirect"] == "open_redirect"

def test_reporter_has_browser_vuln_templates():
    import reporter
    assert "xss_dom" in reporter.VULN_TEMPLATES
    assert "csrf" in reporter.VULN_TEMPLATES
    assert "auth_bypass" in reporter.VULN_TEMPLATES
    assert "open_redirect" in reporter.VULN_TEMPLATES

def test_reporter_parses_lowercase_bracket_severity():
    import reporter
    finding = reporter.parse_custom_line(
        "https://example.com/search?q=x [xss_dom] [high] DOM XSS via innerHTML",
        "xss_dom",
    )
    assert finding["severity"] == "high"
