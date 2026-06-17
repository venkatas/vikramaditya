"""Skills playbook library — read_playbook loader, alias resolution, tech-suggest.

Playbooks adapted from xalgorix (MIT) internal/tools/skills. Gives the brain on-demand
tactical knowledge without baking it into the system prompt.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import skills_lib  # noqa: E402

EXPECTED = {"idor", "sqli", "xss", "ssti", "ssrf", "lfi", "file-upload-rce",
            "auth-bypass", "jwt", "cors", "open-redirect", "subdomain-takeover"}


def test_list_playbooks_has_the_core_set():
    names = set(skills_lib.list_playbooks())
    assert len(names) >= 12
    missing = EXPECTED - names
    assert not missing, f"missing core playbooks: {missing}"


def test_read_playbook_literal():
    md = skills_lib.read_playbook("idor")
    assert len(md) > 200
    assert "idor" in md.lower()


def test_read_playbook_via_alias():
    # shorthand aliases resolve to canonical playbooks
    for alias in ("sql", "xss", "ssrf", "rce", "redirect", "takeover"):
        md = skills_lib.read_playbook(alias)
        assert len(md) > 200, f"alias {alias!r} did not resolve to a real playbook"


def test_read_playbook_miss_is_friendly():
    out = skills_lib.read_playbook("does-not-exist-xyz")
    assert "not found" in out.lower()
    assert "available" in out.lower()  # lists what IS available


def test_every_playbook_is_nontrivial_with_frontmatter():
    for name in skills_lib.list_playbooks():
        md = skills_lib.read_playbook(name)
        assert len(md) > 200, f"{name} too short"
        assert md.lstrip().startswith("---"), f"{name} missing YAML frontmatter"
        assert "xalgorix" in md.lower(), f"{name} missing MIT attribution"


def test_suggest_for_tech_maps_stacks():
    php = skills_lib.suggest_for_tech(["php"])
    assert "sqli" in php
    node = skills_lib.suggest_for_tech(["nodejs"])
    assert any(p in node for p in ("ssti", "xss"))
    # unknown tech → no crash, returns a list
    assert isinstance(skills_lib.suggest_for_tech(["cobol-fortran"]), list)


def test_playbooks_dir_exists_on_disk():
    assert os.path.isdir(skills_lib.PLAYBOOKS_DIR)
    assert len([f for f in os.listdir(skills_lib.PLAYBOOKS_DIR) if f.endswith(".md")]) >= 12
