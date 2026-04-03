"""Low-noise request safety primitives borrowed from claude-bug-bounty."""

from __future__ import annotations

import time


class RateLimiter:
    """Per-host rate limiter for recon and testing actions."""

    def __init__(self, recon_rps: float = 10.0, test_rps: float = 1.0):
        self._last_request: dict[str, float] = {}
        self.recon_interval = 1.0 / recon_rps
        self.test_interval = 1.0 / test_rps

    def wait(self, host: str, is_recon: bool = False) -> float:
        interval = self.recon_interval if is_recon else self.test_interval
        now = time.monotonic()
        last = self._last_request.get(host, 0.0)
        elapsed = now - last
        wait_time = max(0.0, interval - elapsed)
        if wait_time > 0:
            time.sleep(wait_time)
        self._last_request[host] = time.monotonic()
        return wait_time


class CircuitBreaker:
    """Stop hammering hosts that appear unhealthy or blocked."""

    def __init__(self, threshold: int = 5, cooldown: float = 60.0):
        self.threshold = threshold
        self.cooldown = cooldown
        self._failures: dict[str, int] = {}
        self._tripped_at: dict[str, float] = {}

    def record_success(self, host: str) -> None:
        self._failures[host] = 0
        self._tripped_at.pop(host, None)

    def record_failure(self, host: str) -> bool:
        self._failures[host] = self._failures.get(host, 0) + 1
        if self._failures[host] >= self.threshold:
            self._tripped_at[host] = time.monotonic()
            return True
        return False

    def is_tripped(self, host: str) -> bool:
        if host not in self._tripped_at:
            return False
        elapsed = time.monotonic() - self._tripped_at[host]
        if elapsed >= self.cooldown:
            self._failures[host] = self.threshold - 1
            del self._tripped_at[host]
            return False
        return True


class SafeMethodPolicy:
    """Allow safe HTTP methods by default and require opt-in for others."""

    DEFAULT_SAFE = {"GET", "HEAD", "OPTIONS"}

    def __init__(self, safe_methods: set[str] | None = None, enabled: bool = True):
        self._safe = {
            method.upper()
            for method in (safe_methods if safe_methods is not None else self.DEFAULT_SAFE)
        }
        self._enabled = enabled

    def is_safe(self, method: str) -> bool:
        if not self._enabled:
            return True
        return method.upper() in self._safe

    def check(self, method: str, url: str) -> dict:
        method_upper = method.upper()
        if self.is_safe(method_upper):
            return {"decision": "allow", "method": method_upper, "url": url}
        return {
            "decision": "require_approval",
            "method": method_upper,
            "url": url,
            "reason": f"Unsafe method {method_upper} requires explicit approval",
        }
