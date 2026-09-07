import importlib.util
from pathlib import Path


def test_helper_module_loads():
    path = Path(__file__).resolve().parent.parent / "markitdown_helper.py"
    spec = importlib.util.spec_from_file_location("markitdown_helper", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert hasattr(mod, "convert_one")
