"""High-level anonymize / deanonymize orchestration.

Pipeline
--------
1. :class:`RegexDetector` produces non-overlapping :class:`Detection` objects.
2. For each detection, :class:`Vault` is consulted — if a surrogate already
   exists for this ``(engagement, original)`` it's reused; otherwise the
   :class:`SurrogateGenerator` creates one and the vault persists it.
3. The original text is rebuilt with surrogates substituted in, preserving
   whitespace and offsets outside the matched spans.

Deanonymisation is a straightforward reverse substitution driven by the
vault — we walk the mappings longest-surrogate-first to avoid partial
replacement (a surrogate IP like ``203.0.113.5`` must not clobber the
middle of another surrogate IP like ``203.0.113.52``).
"""

from __future__ import annotations

from .regex_detector import Detection, RegexDetector
from .surrogates import SurrogateGenerator
from .vault import Vault


class Anonymizer:
    """Facade combining detection + vault-backed surrogate substitution."""

    def __init__(
        self,
        vault: Vault,
        detector: RegexDetector | None = None,
        generator: SurrogateGenerator | None = None,
    ) -> None:
        self._vault = vault
        self._detector = detector or RegexDetector()
        self._generator = generator or SurrogateGenerator()

    # --------------------------------------------------------------- encode

    def anonymize(self, text: str) -> str:
        """Return a copy of ``text`` with all detected entities surrogated."""
        detections = self._detector.detect(text)
        if not detections:
            return text

        # Walk detections in source order, reuse existing surrogates, append
        # new ones atomically so concurrent anonymise calls against the same
        # engagement converge on identical mappings.
        out: list[str] = []
        cursor = 0
        for d in detections:
            surrogate = self._vault.get_surrogate(d.entity, d.value)
            if surrogate is None:
                surrogate = self._generator.generate(d.entity, d.value)
                self._vault.put(d.entity, d.value, surrogate)
            out.append(text[cursor:d.start])
            out.append(surrogate)
            cursor = d.end
        out.append(text[cursor:])
        return "".join(out)

    # --------------------------------------------------------------- decode

    def deanonymize(self, text: str) -> str:
        """Replace surrogates in ``text`` with their stored originals.

        Implementation note: naive ``str.replace`` in a loop is fine because
        we iterate longest-first; collisions would have been detected at
        ``put`` time anyway (``INSERT OR IGNORE`` on primary key).
        """
        mappings = self._vault.all_mappings()
        # Longer surrogates first: prevents a short surrogate from clobbering
        # a substring of a longer one.
        mappings.sort(key=lambda row: -len(row[2]))
        for _entity, original, surrogate in mappings:
            if surrogate and surrogate in text:
                text = text.replace(surrogate, original)
        return text

    # ---------------------------------------------------------- diagnostics

    def stats(self) -> dict[str, int]:
        """Entity histogram for the active engagement. Mirrors Vault.stats()."""
        return self._vault.stats()
