import sys
import pathlib
import importlib.util

# Ensure repo root is first on sys.path so `whitebox.models` (and other
# submodules) resolve to the top-level source package.
_root = str(pathlib.Path(__file__).parent.parent.parent)
if _root not in sys.path:
    sys.path.insert(0, _root)

# pytest's prepend import mode registers tests/whitebox as the 'whitebox'
# package in sys.modules. Pre-load all source submodules we need so that
# 'from whitebox.models import ...' in test files gets the source versions.
_src_whitebox = _root + "/whitebox"
for _sub in ["models"]:
    _key = f"whitebox.{_sub}"
    if _key not in sys.modules:
        _spec = importlib.util.spec_from_file_location(
            _key, f"{_src_whitebox}/{_sub}.py"
        )
        if _spec:
            _mod = importlib.util.module_from_spec(_spec)
            sys.modules[_key] = _mod
            _spec.loader.exec_module(_mod)
