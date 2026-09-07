from findings_dedupe import fingerprint, dedupe


def test_fingerprint_stable():
    a = fingerprint("SQLi on /x", "https://x.example.invalid/a", "sqli")
    b = fingerprint("sqli on /x", "https://x.example.invalid/a/", "SQLi")
    assert a == b


def test_dedupe_keeps_first():
    items = [
        {"title": "A", "url": "https://x.example.invalid/1", "vtype": "xss"},
        {"title": "A", "url": "https://x.example.invalid/1", "vtype": "xss"},
        {"title": "B", "url": "https://x.example.invalid/2", "vtype": "xss"},
    ]
    kept, dupes = dedupe(items)
    assert len(kept) == 2
    assert len(dupes) == 1
    assert dupes[0]["duplicate_of"] == kept[0]["fingerprint"]
