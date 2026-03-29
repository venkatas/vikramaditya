import importlib, os, sys

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
