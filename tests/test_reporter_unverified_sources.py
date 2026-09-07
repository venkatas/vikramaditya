import json

import reporter


def test_flat_finding_never_invents_poc_and_unverified_high_is_gated(tmp_path):
    (tmp_path / "finding_001.json").write_text(json.dumps({
        "type": "idor",
        "severity": "high",
        "url": "https://example.invalid/profile?id=2",
        "detail": "candidate only; no second-account proof",
        "evidence": "response shape changed",
    }))

    loaded = reporter.load_findings(str(tmp_path))
    assert len(loaded) == 1
    assert "Alice" not in loaded[0]["poc"]
    assert "ACTUAL BEHAVIOR" not in loaded[0]["poc"]
    assert reporter._apply_verification_gating(loaded) == []


def test_flat_finding_with_recognized_verification_can_pass(tmp_path):
    (tmp_path / "finding_001.json").write_text(json.dumps({
        "type": "idor",
        "severity": "high",
        "url": "https://example.invalid/profile?id=2",
        "detail": "cross-account response reproduced",
        "evidence": "two-account differential transcript",
        "verification_method": "manual_verified",
        "poc": "Exact operator-supplied reproduction transcript.",
    }))

    loaded = reporter.load_findings(str(tmp_path))
    kept = reporter._apply_verification_gating(loaded)
    assert len(kept) == 1
    assert "Exact operator-supplied" in kept[0]["poc"]


def test_har_high_without_verification_is_gated(tmp_path):
    (tmp_path / "har_vapt_001.json").write_text(json.dumps({
        "vulnerabilities": [{
            "type": "ssrf",
            "severity": "high",
            "endpoint": "https://example.invalid/fetch",
            "evidence": "candidate",
        }]
    }))

    assert reporter._apply_verification_gating(
        reporter.load_findings(str(tmp_path))
    ) == []


def test_candidate_authz_high_without_verification_is_gated(tmp_path):
    authz = tmp_path / "authz"
    authz.mkdir()
    (authz / "findings.json").write_text(json.dumps([{
        "type": "idor",
        "severity": "high",
        "confidence": "candidate",
        "url": "https://example.invalid/object/2",
        "detail": "candidate",
    }]))

    assert reporter._apply_verification_gating(
        reporter.load_findings(str(tmp_path))
    ) == []
