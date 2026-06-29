"""recon.sh fixes surfaced by a large government-scale wildcard-estate engagement (1700+ live hosts):

1. waybackurls had NO timeout (unlike gau/waymore) → hung on the Wayback API and
   stalled URL collection (observed live). Now timeout-bounded.
2. Visual recon (gowitness) screenshotted EVERY live URL at 12s/URL → ~40min of
   zero-finding-value work on a 1700-host estate, with no cap and no skip flag.
   Now: SCREENSHOT_MAX cap (priority-ordered) + SKIP_SCREENSHOTS env skip.
3. The exposed-config check flagged [EXPOSED] paths with NO status/content, so a
   confirmed exposure wasn't reportable evidence. Now persists status+type+size+snippet.
"""
import os
import re

RECON = os.path.join(os.path.dirname(__file__), "..", "recon.sh")


def _t():
    return open(RECON, encoding="utf-8", errors="replace").read()


def test_waybackurls_is_timeout_bounded():
    t = _t()
    assert "WAYBACK_TIMEOUT" in t, "no WAYBACK_TIMEOUT var"
    assert re.search(r'timeout -k 15 "\$WAYBACK_TIMEOUT" waybackurls', t), \
        "waybackurls still runs without a timeout wrapper"


def test_gowitness_capped_and_skippable():
    t = _t()
    assert "SCREENSHOT_MAX" in t, "no SCREENSHOT_MAX cap var"
    assert "SKIP_SCREENSHOTS" in t, "no SKIP_SCREENSHOTS skip var"
    # the cap actually limits the gowitness input (head -n SCREENSHOT_MAX)
    assert re.search(r'head -n "\$SCREENSHOT_MAX"', t), "SCREENSHOT_MAX is not applied to the screenshot input"
    # SKIP_SCREENSHOTS short-circuits the phase and marks it done
    assert re.search(r'if \[ -n "\$SKIP_SCREENSHOTS" \]', t), "SKIP_SCREENSHOTS does not gate the phase"


def test_exposed_config_persists_proof_content():
    t = _t()
    # the [EXPOSED] line now carries grounded proof, not a bare URL
    assert re.search(r'\[EXPOSED\][^\n]*status=\$\{STATUS\}[^\n]*snippet=', t), \
        "exposed-config hits no longer persist status/snippet proof"


def test_recon_sh_still_parses():
    import subprocess
    r = subprocess.run(["bash", "-n", RECON], capture_output=True, text=True)
    assert r.returncode == 0, f"recon.sh syntax error: {r.stderr}"
