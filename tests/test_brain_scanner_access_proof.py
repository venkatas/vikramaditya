"""Regression tests for the brain-scanner stdout-claim corroboration guard.

A generated PoC can DECLARE success without it being true — the real-world case
that prompted this guard was a shell PoC ending with

    echo "[CRITICAL] Shadow file also accessible!" || echo "[-] Only passwd"

`echo` always exits 0, so the `||` fallback never runs and the CRITICAL line
prints UNCONDITIONALLY — even though the server returned `404 Not Found`. The
grounding layer trusts script stdout over model prose (the anti-hallucination
rule), so that buggy echo would otherwise become a CONFIRMED critical finding.

`brain_scanner._access_claim_unproven()` rejects a file-access / path-traversal
claim unless the script output actually contains the file's CONTENT as proof —
and a passwd-shaped string embedded in a shell error message does NOT count.
"""
import pytest

from brain_scanner import _access_claim_unproven


@pytest.mark.parametrize("line,stdout,expect_reject", [
    # The exact field false-positive: unconditional echo + a 404 page, no content.
    ("[CRITICAL] Shadow file also accessible!",
     "[CRITICAL] Shadow file also accessible!\n<head><title>404 Not Found</title></head>",
     True),
    # A passwd-shaped string inside a SHELL ERROR is NOT proof the file was read.
    ("[CRITICAL] Shadow file also accessible!",
     "bash: line 3: root:x:0:0:root:/root:/bin/bash: No such file or directory",
     True),
    # "[CRITICAL] Windows file accessible!" with only the 403/146-byte catchall.
    ("[CRITICAL] Windows file accessible!",
     "[-] HTTP 403, Size: 146 bytes\n[CRITICAL] Windows file accessible!",
     True),
    # A real /etc/passwd read prints account LINES at line-start → accept.
    ("[CRITICAL] Path traversal confirmed!",
     "[CRITICAL] Path traversal confirmed!\n"
     "root:x:0:0:root:/root:/bin/bash\n"
     "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
     False),
    # A real shadow read (hash field) → accept.
    ("[CRITICAL] /etc/shadow readable via LFI",
     "[CRITICAL] /etc/shadow readable via LFI\nroot:$6$abc$def:19000:0:99999:7:::",
     False),
    # A real web.config disclosure → accept.
    ("[CRITICAL] LFI: web.config readable",
     "[CRITICAL] LFI: web.config readable\n"
     "<configuration><connectionStrings>x</connectionStrings></configuration>",
     False),
    # A real boot.ini/win.ini read → accept.
    ("[CRITICAL] boot.ini accessible via traversal",
     "[CRITICAL] boot.ini accessible via traversal\n[boot loader]\ntimeout=30",
     False),
    # Non-access findings must be UNAFFECTED (no over-suppression / false negatives).
    ("[CRITICAL] SQL injection confirmed via sqlmap (MySQL, 3 cols)",
     "[CRITICAL] SQL injection confirmed via sqlmap (MySQL, 3 cols)",
     False),
    ("[HIGH] EXPLOITABLE: stored XSS fires in admin context",
     "[HIGH] EXPLOITABLE: stored XSS fires in admin context",
     False),
])
def test_access_claim_corroboration(line, stdout, expect_reject):
    assert _access_claim_unproven(line, stdout) is expect_reject
