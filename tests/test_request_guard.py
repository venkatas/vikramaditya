from request_guard import CircuitBreaker, RateLimiter, SafeMethodPolicy


def test_safe_method_policy_defaults():
    policy = SafeMethodPolicy()
    assert policy.is_safe("GET") is True
    assert policy.is_safe("HEAD") is True
    assert policy.is_safe("OPTIONS") is True
    assert policy.is_safe("POST") is False


def test_safe_method_policy_check_for_unsafe_method():
    policy = SafeMethodPolicy()
    result = policy.check("DELETE", "https://example.com/api")
    assert result["decision"] == "require_approval"
    assert result["method"] == "DELETE"


def test_rate_limiter_tracks_waits():
    limiter = RateLimiter(recon_rps=1000.0, test_rps=1000.0)
    first = limiter.wait("example.com")
    second = limiter.wait("example.com")
    assert first >= 0.0
    assert second >= 0.0


def test_circuit_breaker_trips_and_recovers():
    breaker = CircuitBreaker(threshold=2, cooldown=0.0)
    assert breaker.record_failure("example.com") is False
    assert breaker.record_failure("example.com") is True
    assert breaker.is_tripped("example.com") is False
