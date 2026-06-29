"""brain lazy-loads technique_kb: free-text finding -> single technique context (no LLM)."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import brain  # noqa: E402

def test_resolve_vtype_from_freetext():
    assert brain._resolve_vtype("Confirmed IDOR / BOLA on /ClientDetails") == "idor"
    assert brain._resolve_vtype("SQL injection via sqlmap") == "sqli"
    assert brain._resolve_vtype("low-priv maker reached approver page (BFLA)") == "auth_bypass"
    assert brain._resolve_vtype("Kerberoasting of svc_sql account") == "kerberoasting"
    assert brain._resolve_vtype("just a friendly note") is None

def test_technique_hint_is_lazy_single_technique():
    hint = brain._technique_hint("IDOR lets a maker read any client record")
    assert "MITRE ATT&CK:" in hint and "T1078" in hint
    # only the matched technique, not the whole KB (no unrelated technique titles)
    assert "SQL Injection" not in hint
    assert brain._technique_hint("nothing matches here") == ""
