"""Under wildcard DNS the live apex must STILL be probed (gap #4).

BUG (live engagement, 2026-06-17): `*.target` wildcard made every permutation candidate
"resolve". With >20k candidates dnsx was skipped (DNSX_CAP) so resolved.txt == all.txt, and
the LARGE_TARGET path capped the httpx probe list at 1500 keyword-priority hosts. The bare
apex has no priority keyword, so it was crowded out by permutation noise and never probed —
a live target (HTTP 200) was reported as "0 live hosts" and never assessed.

FIX: recon.sh force-includes the apex (+ www.apex) at the TOP of the httpx probe set,
unconditionally, for domain targets — so the real site is always tested.
"""
import os
import subprocess
import sys

REPO = os.path.join(os.path.dirname(__file__), "..")
RECON_SH = os.path.join(REPO, "recon.sh")


def _recon_src():
    with open(RECON_SH) as f:
        return f.read()


# ── script-assertion: the apex-forcing logic exists and guards on domain targets ──

def test_recon_forces_apex_into_probe_set():
    s = _recon_src()
    # apex + www are seeded into the probe file
    assert 'echo "$TARGET"' in s and 'echo "www.$TARGET"' in s, \
        "apex (+www) must be force-added to the httpx probe set"
    # marked as the gap-#4 fix so it isn't silently removed
    assert "gap #4" in s or "always be probed" in s.lower() or "force the apex" in s.lower()


# ── functional: the prepend+dedup pipeline keeps the apex even when buried in noise ──

def test_apex_survives_probe_list_dedup(tmp_path):
    """Replicates recon.sh's apex-forcing pipeline: apex buried under 2000 noise hosts
    must end up present (and first) in the probe list."""
    apex = "example.com"
    probe = tmp_path / "probe.txt"
    # 2000 permutation-noise hosts, apex NOT among them (worst case: crowded out)
    probe.write_text("\n".join(f"{i}-noise.example.com" for i in range(2000)) + "\n")

    # the exact pipeline recon.sh uses to force the apex in
    script = (
        f'{{ echo "{apex}"; echo "www.{apex}"; cat "{probe}"; }} '
        f"| awk 'NF && !seen[$0]++'"
    )
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True).stdout
    lines = out.splitlines()
    assert lines[0] == apex, "apex must be first in the probe set"
    assert f"www.{apex}" in lines[:2]
    assert apex in lines and out.count(apex + "\n") >= 1
    # noise still present (we add the apex, we don't drop the rest)
    assert "0-noise.example.com" in lines


def test_apex_forcing_dedups_when_apex_already_present(tmp_path):
    apex = "example.com"
    probe = tmp_path / "probe.txt"
    probe.write_text(f"{apex}\nsub1.example.com\n{apex}\n")
    script = (
        f'{{ echo "{apex}"; echo "www.{apex}"; cat "{probe}"; }} '
        f"| awk 'NF && !seen[$0]++'"
    )
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True).stdout
    assert out.splitlines().count(apex) == 1, "apex must appear exactly once after dedup"


# ── PROBE_CAP env-control (v10.6.0): large-target liveness probe is no longer hardcoded 1500 ──

def test_probe_cap_is_env_controllable():
    s = _recon_src()
    assert 'PROBE_CAP="${PROBE_CAP:-1500}"' in s, "probe cap must default to 1500 but be overridable"
    # the keyword/fill splits derive from PROBE_CAP, not a hardcoded 1000/500.
    # v10.6.0 — truncation is now a RANDOM sample (_rand_head), not an alphabetical
    # `head` that silently dropped the tail of the alphabet on a capped estate.
    assert '_rand_head "$_KW_CAP"' in s and '_rand_head "$_FILL_CAP"' in s
    assert "head -1000" not in s and "head -500" not in s, "old hardcoded caps must be gone"


def test_probe_cap_zero_means_uncapped():
    s = _recon_src()
    # a PROBE_CAP=0 branch probes ALL resolved hosts (no priority_probe truncation)
    assert '[ "$PROBE_CAP" -gt 0 ]' in s
    assert "PROBE_CAP=0" in s and "uncapped" in s.lower()
