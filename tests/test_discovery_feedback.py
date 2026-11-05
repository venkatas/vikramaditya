"""Local-only discovery handoff fixtures: no requests, models, or scanners."""
from __future__ import annotations

import json

import pytest

import discovery_feedback as feedback


@pytest.fixture(autouse=True)
def isolated_scope_environment(monkeypatch):
    monkeypatch.delenv("SCOPE_ALLOW_FILE", raising=False)
    monkeypatch.delenv("SCOPE_LOCK", raising=False)


def _response(url, *, mime="text/html", status=200, **extra):
    return {"type": "response", "url": url, "status": status, "method": "GET",
            "headers": {"content-type": mime}, "wildcard": False, **extra}


def _session(tmp_path, rows, *, hosts="example.invalid\n"):
    recon = tmp_path / "recon" / "example.invalid" / "sessions" / "test"
    (recon / "api").mkdir(parents=True)
    (recon / "urls").mkdir()
    if hosts is not None:
        (recon / "scope").mkdir()
        (recon / "scope/allow.txt").write_text(hosts)
    (recon / "api/feroxbuster.json").write_text(
        "\n".join(json.dumps(row) for row in rows) + ("\n" if rows else ""))
    return recon


def _lines(recon, name):
    path = recon / "urls" / name
    return path.read_text().splitlines() if path.exists() else []


def test_successful_discoveries_reach_every_dependent_corpus_idempotently(tmp_path):
    root = "https://example.invalid/"
    html = "https://example.invalid/app/contact.html"
    script = "https://example.invalid/app/custom.js?v=2"
    query = "https://example.invalid/search?q=one&sort=two"
    api = "https://example.invalid/api/v1/users"
    recon = _session(tmp_path, [
        {"type": "configuration", "url": "https://outside.invalid/"},
        _response(root), _response(html), _response(html + "#footer"),
        _response(script, mime="application/javascript"),
        _response(query), _response(api, mime="application/json"),
        {"type": "statistics", "responses": 5},
    ])
    (recon / "urls/all.txt").write_text("https://example.invalid\nhttps://example.invalid/old\n")
    result = feedback.merge_ferox_discoveries(recon, target="example.invalid")
    assert not result["errors"]
    assert result["added_urls"] == [html, script, query, api]
    assert result["added_html_urls"] == [root, html, query]
    assert result["added_js_urls"] == [script]
    assert result["added_parameter_urls"] == [script, query]
    assert result["added_api_urls"] == [api]
    assert _lines(recon, "all.txt") == ["https://example.invalid", "https://example.invalid/old", html, script, query, api]
    assert _lines(recon, "discovered_html.txt") == [root, html, query]
    assert _lines(recon, "js_files.txt") == [script]
    assert _lines(recon, "with_params.txt") == [script, query]
    assert _lines(recon, "api_endpoints.txt") == [api]
    before = {path: path.read_bytes() for path in (recon / "urls").iterdir()}
    again = feedback.merge_ferox_discoveries(recon, target="example.invalid")
    assert again["changed"] is False
    assert not any(again[key] for key in again if key.startswith("added_"))
    assert before == {path: path.read_bytes() for path in (recon / "urls").iterdir()}


@pytest.mark.parametrize("row", [
    _response("https://example.invalid/api/anything", status=401),
    _response("https://example.invalid/admin", status=403),
    _response("https://example.invalid/redirect", status=302),
    _response("https://example.invalid/wildcard", wildcard=True),
    _response("https://example.invalid/logo.png", mime="image/png"),
    _response("https://example.invalid/download.pdf?download=1", mime="application/pdf"),
    _response("https://example.invalid/main.css", mime="text/css"),
    _response("https://example.invalid/upload", method="POST"),
    _response("https://example.invalid/blob", mime="application/octet-stream"),
    {"type": "configuration", "url": "https://example.invalid/", "status": 200},
    {"type": "statistics", "url": "https://example.invalid/", "status": 200},
])
def test_non_pages_catchalls_auth_errors_and_metadata_do_not_become_seeds(tmp_path, row):
    recon = _session(tmp_path, [row])
    result = feedback.merge_ferox_discoveries(recon, target="example.invalid")
    assert result["accepted_urls"] == []
    assert result["changed"] is False
    assert list((recon / "urls").iterdir()) == []


@pytest.mark.parametrize("url", [
    "https://www.example.invalid/page", "https://sub.example.invalid/page",
    "https://example.invalid.evil.test/page", "https://evil-example.invalid/page",
    "https://example.invalid:8443/page", "https://user@example.invalid/page",
    "https://example.invalid@outside.invalid/page", "https://@example.invalid/page",
    "https://example.invalid\\@outside.invalid/page", "https://example.invalid/page\n",
    "https://example.invalid:/page", "https://example.invalid:bad/page",
    "https://example.invalid:65536/page", "https://%65xample.invalid/page",
    "file:///tmp/page", "javascript:alert(1)", "//example.invalid/page",
    "https://example.invalid<bad>/page", "https://example.invalid /page",
])
def test_exact_scope_rejects_host_port_and_parser_ambiguities(tmp_path, url):
    recon = _session(tmp_path, [_response(url)])
    result = feedback.merge_ferox_discoveries(recon, target="example.invalid")
    assert result["accepted_urls"] == []
    assert result["rejected_count"] == 1
    assert result["errors"] == []


def test_explicit_nondefault_port_and_normalized_default_port_are_scoped(tmp_path):
    recon = _session(tmp_path, [
        _response("HTTPS://EXAMPLE.INVALID.:443/index.html#anchor"),
        _response("https://api.example.invalid:8443/search?q=one", mime="application/json"),
        _response("https://api.example.invalid:8444/search?q=one", mime="application/json"),
    ], hosts="example.invalid\napi.example.invalid:8443\n")
    result = feedback.merge_ferox_discoveries(recon, target="session-label.invalid")
    assert result["accepted_urls"] == [
        "https://example.invalid/index.html", "https://api.example.invalid:8443/search?q=one"]
    assert result["rejected_count"] == 1


@pytest.mark.parametrize("authority", [None, "", "# comments only\n", "*.example.invalid\n",
                                        "https://example.invalid/\n", "example.invalid/path\n"])
def test_missing_empty_or_malformed_locked_authority_never_updates_corpus(tmp_path, authority):
    recon = _session(tmp_path, [_response("https://example.invalid/new.html")], hosts=authority)
    (recon / "urls/all.txt").write_text("https://example.invalid/existing\n")
    before = {path: path.read_bytes() for path in (recon / "urls").iterdir()}
    result = feedback.merge_ferox_discoveries(recon, target="example.invalid", scope_lock=True)
    assert result["errors"] and result["changed"] is False
    assert before == {path: path.read_bytes() for path in (recon / "urls").iterdir()}


def test_explicit_missing_scope_file_and_scope_environment_fail_closed(tmp_path, monkeypatch):
    recon = _session(tmp_path, [_response("https://example.invalid/new")], hosts=None)
    monkeypatch.setenv("SCOPE_ALLOW_FILE", str(tmp_path / "missing-allow.txt"))
    result = feedback.merge_ferox_discoveries(recon, target="example.invalid")
    assert result["errors"] and not result["changed"]


@pytest.mark.parametrize("field", ["original_url", "final_url"])
def test_off_scope_redirect_response_cannot_seed_allowed_source_url(tmp_path, field):
    recon = _session(tmp_path, [_response("https://example.invalid/new", **{field: "https://outside.invalid/new"})])
    result = feedback.merge_ferox_discoveries(recon, target="example.invalid")
    assert not result["accepted_urls"]


def test_unlocked_domain_stays_in_target_tree_and_ip_scope_stays_exact(tmp_path):
    recon = _session(tmp_path, [
        _response("https://example.invalid/a"), _response("https://app.example.invalid/b"),
        _response("https://example.invalid.evil.test/c"),
    ], hosts=None)
    result = feedback.merge_ferox_discoveries(recon, target="example.invalid")
    assert result["accepted_urls"] == ["https://example.invalid/a", "https://app.example.invalid/b"]
    other = _session(tmp_path / "other", [
        _response("https://192.0.2.1/a"), _response("https://sub.192.0.2.1/b"),
    ], hosts=None)
    assert feedback.merge_ferox_discoveries(other, target="192.0.2.1")["accepted_urls"] == ["https://192.0.2.1/a"]


def test_html_catchall_at_js_path_is_not_a_javascript_source(tmp_path):
    recon = _session(tmp_path, [_response("https://example.invalid/missing.js")])
    result = feedback.merge_ferox_discoveries(recon, target="example.invalid")
    assert result["added_js_urls"] == []
    assert result["added_html_urls"] == ["https://example.invalid/missing.js"]


def test_partial_json_and_error_records_retain_valid_candidates_and_surface_errors(tmp_path):
    recon = _session(tmp_path, [
        _response("https://example.invalid/good.html"), {"type": "error", "message": "request failed"}, []])
    with (recon / "api/feroxbuster.json").open("a") as source:
        source.write('{"type":"response"\n')
    result = feedback.merge_ferox_discoveries(recon, target="example.invalid")
    assert result["added_urls"] == ["https://example.invalid/good.html"]
    assert len(result["errors"]) == 3


def test_missing_response_artifact_reports_failure_without_creating_corpus(tmp_path):
    recon = _session(tmp_path, [])
    (recon / "api/feroxbuster.json").unlink()
    result = feedback.merge_ferox_discoveries(recon, target="example.invalid")
    assert result["errors"] and not result["changed"]
    assert list((recon / "urls").iterdir()) == []


def test_existing_all_url_can_gain_missing_html_or_js_classification(tmp_path):
    script = "https://example.invalid/custom.js"
    html = "https://example.invalid/form.html"
    recon = _session(tmp_path, [_response(script, mime="application/javascript"), _response(html)])
    (recon / "urls/all.txt").write_text(script + "\n" + html + "\n")
    result = feedback.merge_ferox_discoveries(recon, target="example.invalid")
    assert result["added_urls"] == []
    assert result["added_js_urls"] == [script]
    assert result["added_html_urls"] == [html]
    assert result["changed"]


def test_failed_corpus_write_keeps_existing_evidence_and_reports_partial_feedback(tmp_path, monkeypatch):
    script = "https://example.invalid/custom.js"
    recon = _session(tmp_path, [_response(script, mime="application/javascript")])
    original = feedback.atomic_write_text

    def fail_script_file(path, text):
        if path.endswith("js_files.txt"):
            raise OSError("fixture disk full")
        return original(path, text)

    monkeypatch.setattr(feedback, "atomic_write_text", fail_script_file)
    result = feedback.merge_ferox_discoveries(recon, target="example.invalid")
    assert result["errors"] and result["added_urls"] == [script]
    assert _lines(recon, "all.txt") == [script]
    assert _lines(recon, "js_files.txt") == []
    monkeypatch.setattr(feedback, "atomic_write_text", original)
    retried = feedback.merge_ferox_discoveries(recon, target="example.invalid")
    assert not retried["errors"] and retried["added_urls"] == []
    assert retried["added_js_urls"] == [script]


def test_successful_empty_discovery_is_not_an_error(tmp_path):
    recon = _session(tmp_path, [])
    result = feedback.merge_ferox_discoveries(recon, target="example.invalid")
    assert result["errors"] == [] and result["accepted_urls"] == []
    assert result["changed"] is False
