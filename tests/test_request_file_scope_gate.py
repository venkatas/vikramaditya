import hunt


def test_request_file_host_must_match_authorized_target(tmp_path, monkeypatch):
    req = tmp_path / "request.txt"
    req.write_text("GET /?id=1 HTTP/1.1\nHost: other.example.invalid\n\n")
    monkeypatch.setattr(
        hunt,
        "_which",
        lambda _name: (_ for _ in ()).throw(AssertionError("sqlmap lookup must not run")),
    )

    assert hunt.run_sqlmap_request_file(
        str(req), domain="allowed.example.invalid"
    ) is False


def test_absolute_request_uri_must_match_host_header(tmp_path, monkeypatch):
    req = tmp_path / "request.txt"
    req.write_text(
        "GET https://other.example.invalid/?id=1 HTTP/1.1\n"
        "Host: allowed.example.invalid\n\n"
    )
    monkeypatch.setattr(
        hunt,
        "_which",
        lambda _name: (_ for _ in ()).throw(AssertionError("sqlmap lookup must not run")),
    )

    assert hunt.run_sqlmap_request_file(
        str(req), domain="allowed.example.invalid"
    ) is False
