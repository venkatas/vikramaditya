"""atomic_red_team — parse the open ART YAML format + link to technique_kb. Synthetic fixture
(no ART vendored)."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import atomic_red_team as art  # noqa: E402

_YAML = """\
attack_technique: T1558.003
display_name: Kerberoasting
atomic_tests:
  - name: Request all SPN tickets via PowerShell
    description: Requests TGS for every SPN.
    supported_platforms: [windows]
    executor:
      name: powershell
      command: Add-Type -AssemblyName System.IdentityModel
  - name: Rubeus kerberoast
    description: Kerberoast with Rubeus.
    supported_platforms: [windows]
    executor:
      name: command_prompt
      command: Rubeus.exe kerberoast
"""

def _art_checkout(tmp_path):
    d = tmp_path / "atomics" / "T1558.003"
    d.mkdir(parents=True)
    (d / "T1558.003.yaml").write_text(_YAML)
    return str(tmp_path)

def test_load_and_index(tmp_path):
    idx = art.load_atomics(_art_checkout(tmp_path))
    assert "T1558.003" in idx and len(idx["T1558.003"]) == 2
    assert art.summarize(idx) == {"techniques": 1, "tests": 2}
    assert idx["T1558.003"][1]["command"].startswith("Rubeus")

def test_subtechnique_falls_back_to_parent(tmp_path):
    idx = art.load_atomics(_art_checkout(tmp_path))
    # a finding mapped to the parent T1558 still surfaces the .003 atomics
    assert art.tests_for_mitre_id(idx, "T1558") == idx["T1558.003"]

def test_tests_for_vtype_via_technique_kb(tmp_path):
    idx = art.load_atomics(_art_checkout(tmp_path))
    # kerberoasting vtype -> technique_kb maps to T1558.003 -> these atomics
    tests = art.tests_for_vtype(idx, "kerberoasting")
    assert tests and any("Rubeus" in t["command"] for t in tests)

def test_missing_path_is_empty():
    assert art.load_atomics("/no/such/dir") == {}
