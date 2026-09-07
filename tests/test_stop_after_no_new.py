from stop_after_no_new import StopAfterNoNew


def test_saturates_after_limit():
    s = StopAfterNoNew(limit=2)
    assert s.observe({"a"}) is False
    assert s.observe({"a"}) is False  # no novel → consecutive=1
    assert s.observe({"a"}) is True   # consecutive=2 → stop
    assert s.saturated is True


def test_novel_resets():
    s = StopAfterNoNew(limit=2)
    assert s.observe({"a"}) is False
    assert s.observe({"a"}) is False
    assert s.observe({"b"}) is False  # novel resets
    assert s.consecutive == 0
