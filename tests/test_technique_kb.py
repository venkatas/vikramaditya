"""technique_kb — attack-technique KB + attack-chaining. Clean-room content; tests assert
structure, chain-graph integrity, and the reporter-facing helpers."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import technique_kb as kb  # noqa: E402


def test_core_vtypes_covered():
    for v in ("sqli", "idor", "auth_bypass", "exposure", "rce", "xss"):
        t = kb.get(v)
        assert t is not None and t.vtype == v


def test_aliases_resolve_to_base():
    assert kb.get("sqli_sqlmap_confirmed").vtype == "sqli"
    assert kb.get("xss_dom").vtype == "xss"
    assert kb.get("exposed_credentials").vtype == "exposure"
    assert kb.get("refresh_token_bypass").vtype == "oauth"


def test_unknown_vtype_returns_none():
    assert kb.get("totally_unknown") is None
    assert kb.get("") is None


def test_every_technique_is_well_formed():
    for v in kb.techniques():
        t = kb.get(v)
        assert t.mitre_id.startswith("T"), v
        assert t.cwe.startswith("CWE-"), v
        assert t.mitre_tactic and t.summary and t.remediation, v
        assert all(r.startswith("https://") for r in t.references), v


def test_chain_graph_has_no_dangling_edges():
    # every chains_to target must itself be a known base technique (no typos)
    known = set(kb.techniques())
    for v in known:
        for nxt in kb.get(v).chains_to:
            assert nxt in known, f"{v} chains_to unknown '{nxt}'"


def test_chain_path_is_cycle_safe_and_capped():
    p = kb.chain_path("sqli", depth=4)
    assert p[0] == "sqli" and len(p) == len(set(p)) and len(p) <= 4
    # auth_bypass <-> idor could cycle; path must still terminate without repeats
    p2 = kb.chain_path("auth_bypass", depth=6)
    assert len(p2) == len(set(p2))


def test_idor_chains_toward_exposure():
    # the engagement's real chain: IDOR -> data/credential exposure
    assert "exposure" in kb.get("idor").chains_to


def test_enrich_adds_technique_without_mutating_input():
    f = {"vtype": "idor", "title": "x"}
    out = kb.enrich(f)
    assert "technique" not in f                      # input untouched
    assert out["technique"]["mitre_id"] == "T1078"
    assert out["technique"]["cwe"] == "CWE-639"
    assert out["technique"]["attack_path"][0] == "idor"


def test_enrich_unknown_vtype_passthrough():
    f = {"vtype": "nope"}
    assert kb.enrich(f) == f


def test_markdown_block_known_and_unknown():
    md = kb.markdown_block("sqli")
    assert "MITRE ATT&CK:" in md and "T1190" in md and "Remediation:" in md
    assert kb.markdown_block("totally_unknown") == ""


# ── reporter integration: the chain helper is wired into reporter.py ──
def test_reporter_attack_chain_helper_integrates_kb():
    import reporter
    s = reporter._attack_chain_str("idor")
    assert "→" in s and "IDOR" in s            # multi-step chain string
    assert reporter._attack_chain_row_html("idor").startswith("<tr>")
    # variant vtype resolves via the KB alias, and unknown is empty (safe to append)
    assert reporter._attack_chain_str("sqli_sqlmap_confirmed")
    assert reporter._attack_chain_str("totally_unknown") == ""
