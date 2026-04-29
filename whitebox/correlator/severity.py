from __future__ import annotations
from whitebox.models import Severity


def promote(base: Severity, has_imds: bool, reaches_admin: bool) -> Severity:
    if has_imds and reaches_admin:
        return Severity.CRITICAL
    if reaches_admin:
        return Severity.HIGH if base < Severity.HIGH else base
    return base
