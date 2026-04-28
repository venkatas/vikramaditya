from whitebox.secrets.detectors import scan_text, DETECTORS


def test_scan_finds_aws_access_key():
    txt = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    hits = scan_text(txt, source="env")
    names = [h["detector"] for h in hits]
    assert "aws_access_key_id" in names


def test_scan_finds_aws_secret_key():
    txt = "secret = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    hits = scan_text(txt, source="env")
    assert any(h["detector"] == "aws_secret_access_key" for h in hits)


def test_scan_finds_jwt():
    txt = "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.aBcDeFgHiJkLmNoPqRsTuVwXyZ"
    hits = scan_text(txt, source="env")
    assert any(h["detector"] == "jwt" for h in hits)


def test_scan_finds_private_key():
    txt = "-----BEGIN RSA PRIVATE KEY-----\nABCD\n-----END RSA PRIVATE KEY-----"
    hits = scan_text(txt, source="env")
    assert any(h["detector"] == "rsa_private_key" for h in hits)


def test_scan_high_entropy_string_flagged():
    # 40-char base64-like high-entropy string
    txt = "key=8s9d7f6g7h8j9k0l1m2n3b4v5c6x7z8q9w0e1r2t"
    hits = scan_text(txt, source="env")
    assert any(h["detector"] == "high_entropy" for h in hits)


def test_each_hit_has_offset_and_redacted_preview():
    txt = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    hits = scan_text(txt, source="env")
    h = hits[0]
    assert "offset" in h
    assert "preview" in h
    assert "EXAMPLE" not in h["preview"]  # full value redacted
