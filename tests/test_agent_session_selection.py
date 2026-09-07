from pathlib import Path


def test_agent_session_state_is_stored_in_selected_recon_session():
    source = (Path(__file__).resolve().parent.parent / "agent.py").read_text()
    assert "requested_session_id=resume_session_id," in source
    assert "requested_session_id=None," in source
    assert "create=False," in source
    assert 'session_file = os.path.join(recon_dir, "agent_session.json")' in source
    assert 'requested_session_id=resume_session_id or "latest"' not in source
