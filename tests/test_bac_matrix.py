"""bac_matrix — multi-user BAC/IDOR matrix. Clean-room (TokenTwin-inspired). Synthetic data."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import bac_matrix as bm  # noqa: E402

SHELL = "<html><head>App</head><body><nav>Home About Logout</nav><div id=main>"
def _r(status, body="", loc=""): return (status, body, loc)

def test_normalize_strips_dynamic_content():
    body = (SHELL + '<input name="__VIEWSTATE" value="abc123XYZ==" />'
            '<input name="__RequestVerificationToken" value="tok987" />'
            'id 3f2504e0-4f89-41d3-9a0c-0305e82c3301 at 12/31/2020 13:45:01 ts 1782705310619</div>')
    n = bm.normalize(body)
    assert "abc123XYZ" not in n and "tok987" not in n          # tokens stripped
    assert "3f2504e0" not in n and "1782705310619" not in n    # GUID + epoch stripped
    assert "App" in n and "Home About Logout" in n             # structure kept

def test_similarity_ignores_dynamic_tokens():
    a = SHELL + '<input name="__VIEWSTATE" value="AAAA" /><p>Client: ACME</p></div>'
    b = SHELL + '<input name="__VIEWSTATE" value="ZZZZ" /><p>Client: ACME</p></div>'
    assert bm.similarity(a, b) >= 0.99            # differ only in viewstate -> ~identical
    c = SHELL + "<p>totally different content here, a denial page</p></div>"
    assert bm.similarity(a, c) < 0.9

def test_compare_bac_when_other_gets_owner_sensitive_page():
    owner = _r(200, SHELL + '<input name="__VIEWSTATE" value="X1"/><td>PAN ABCDE1234F</td></div>')
    other = _r(200, SHELL + '<input name="__VIEWSTATE" value="X2"/><td>PAN ABCDE1234F</td></div>')
    res = bm.compare(owner, other)
    assert res["verdict"] == "bac" and res["severity"] == "high" and res["sensitive"] is True

def test_compare_safe_when_other_gated():
    owner = _r(200, SHELL + "<td>PAN ABCDE1234F</td></div>")
    other = _r(302, "", "/Home.aspx")            # auth gate (bfla_scanner.classify -> gated)
    assert bm.compare(owner, other)["verdict"] == "safe"

def test_compare_safe_when_other_gets_different_page():
    owner = _r(200, SHELL + "<td>PAN ABCDE1234F account details</td></div>")
    other = _r(200, SHELL + "<h2>You are not authorized</h2></div>")  # soft-deny 200 -> gated
    assert bm.compare(owner, other)["verdict"] == "safe"

def test_compare_na_when_baseline_not_owner_200():
    assert bm.compare(_r(404, ""), _r(200, "x"))["verdict"] == "na"

def test_run_matrix_flags_only_the_bac_context():
    OWN = SHELL + '<input name="__VIEWSTATE" value="A"/><td>PAN ABCDE9999Z</td></div>'
    data = {
        "owner":  {"/Rec?id=7": _r(200, OWN)},
        "other":  {"/Rec?id=7": _r(200, SHELL + '<input name="__VIEWSTATE" value="B"/><td>PAN ABCDE9999Z</td></div>')},
        "unauth": {"/Rec?id=7": _r(302, "", "/login")},
    }
    contexts = [
        {"label": "owner",  "is_baseline": True,  "get": lambda p: data["owner"][p]},
        {"label": "other",  "is_baseline": False, "get": lambda p: data["other"][p]},
        {"label": "unauth", "is_baseline": False, "get": lambda p: data["unauth"][p]},
    ]
    fs = bm.run_matrix(contexts, ["/Rec?id=7"])
    assert len(fs) == 1
    assert fs[0]["context"] == "other" and fs[0]["severity"] == "high"
    assert fs[0]["vuln_class"].startswith("Broken Access Control")

def test_run_matrix_empty_inputs():
    assert bm.run_matrix([], ["/x"]) == [] and bm.run_matrix([{"label":"a","get":lambda p:(200,"")}], []) == []
