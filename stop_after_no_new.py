#!/usr/bin/env python3
"""stop_after_no_new.py — saturate discovery when N rounds yield nothing new.

Inspired by openai/codex-security deep-scan `stopAfterNoNew` (Apache-2.0 idea;
clean-room Python). Tracks fingerprints seen across rounds.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class StopAfterNoNew:
    limit: int = 3
    consecutive: int = 0
    seen: set[str] = field(default_factory=set)

    def observe(self, fingerprints: list[str] | set[str]) -> bool:
        """Record this round. Return True if we should STOP (saturated)."""
        fps = {f for f in fingerprints if f}
        novel = fps - self.seen
        self.seen |= fps
        if novel:
            self.consecutive = 0
            return False
        self.consecutive += 1
        return self.consecutive >= max(1, int(self.limit))

    @property
    def saturated(self) -> bool:
        return self.consecutive >= max(1, int(self.limit))
