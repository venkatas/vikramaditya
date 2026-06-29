"""agent.HuntMemory — the in-run dedup key space (_classified_keys) must be
rehydrated from the persisted findings_log on --resume, so a re-walked byte-identical
observation line is NOT re-counted (count inflation) across a resume boundary.

Offline test. Synthetic data only.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import agent  # noqa: E402


def test_classified_keys_rehydrated_on_resume(tmp_path):
    session_file = str(tmp_path / "agent_session.json")

    # First run: record one finding via add_finding and register its dedup key,
    # exactly as _classify_obs does (key on the stripped/sliced text).
    m1 = agent.HuntMemory(session_file)
    text = "critical SQL injection at /login.php param=id"
    m1.add_finding("sqlmap", "critical", text)
    m1._classified_keys.add(("sqlmap", "critical", text[:300]))
    m1.save()

    # Sanity: persisted file carries the finding.
    data = json.loads((tmp_path / "agent_session.json").read_text())
    assert len(data["findings_log"]) == 1

    # Resume: a fresh AgentMemory over the same file must rebuild the dedup set.
    m2 = agent.HuntMemory(session_file)
    assert len(m2.findings_log) == 1
    key = ("sqlmap", "critical", text[:300])
    assert key in m2._classified_keys, (
        "dedup key must be rehydrated from findings_log on resume so the same "
        "finding is not re-counted"
    )


def test_resume_does_not_duplicate_on_rewalk(tmp_path):
    session_file = str(tmp_path / "agent_session.json")
    m1 = agent.HuntMemory(session_file)
    text = "high exposed .git directory found"
    m1.add_finding("nuclei", "high", text)
    m1._classified_keys.add(("nuclei", "high", text[:300]))
    m1.save()

    m2 = agent.HuntMemory(session_file)
    key = ("nuclei", "high", text[:300])
    # Simulate the _classify_obs guard: key already present -> skip re-add.
    before = len(m2.findings_log)
    if key not in m2._classified_keys:
        m2.add_finding("nuclei", "high", text)
    assert len(m2.findings_log) == before, "re-walked finding must not be duplicated after resume"
