"""Expanded knowledge provenance, full install path and Kali inventory contracts."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts import opencode_security
from scripts import secra_skill_sources
from scripts import secra_kali_tools


def test_seventy_three_curated_skill_ids_have_distinct_safe_sources():
    entries = list(opencode_security.FIRST_PARTY)
    externals = list(opencode_security.EXTERNAL)
    assert len(entries) == 35
    assert len(externals) == 38
    names = [x[1] for x in entries] + [x[2] for x in externals]
    assert len(set(names)) == 73
    assert all(x[1].startswith("secra-") for x in entries)
    assert all(x[2].startswith("secra-") for x in externals)
    assert {x[0] for x in externals} == {
        "claude-red", "ctf-skills", "trailofbits-skills", "secskills"
    }
    for path, skill_id, description in entries:
        assert (opencode_security.ROOT / path / "SKILL.md").is_file()
        assert description


def test_21_previous_first_party_skills_now_have_evidence_v2_contract():
    old = opencode_security.FIRST_PARTY[:21]
    assert len(old) == 21
    for path, name, description in old:
        body = (opencode_security.ROOT / path / "SKILL.md").read_text()
        assert "## v2.0 SECRA operator decision workflow" in body
        assert "False-positive" in body or "False-positive gate" in body
        assert "Required output" in body


def test_all_38_external_refs_load_from_reviewed_fake_checkouts(tmp_path):
    source_root = tmp_path / "sources"
    for repo_name, relative, skill_name, description in opencode_security.EXTERNAL:
        directory = source_root / repo_name / relative
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "SKILL.md").write_text(
            "---\nname: original\n---\n\n# Reviewed source reference\n",
            encoding="utf-8",
        )
        (directory / "danger.sh").write_text("echo DO_NOT_EXECUTE", encoding="utf-8")
    destination = tmp_path / "skills"
    cmd = [
        sys.executable, str(opencode_security.ROOT / "scripts" / "opencode_security.py"),
        "install", "--destination", str(destination),
        "--with-external", "--external-root", str(source_root),
        "--reviewed-external"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    receipt = json.loads(
        (destination / opencode_security.MANIFEST_NAME).read_text()
    )
    assert len(receipt["skills"]) == 73
    assert (destination / "secra-ext-research-orchestration" / "SKILL.md").is_file()
    assert (destination / "secra-tob-differential-review" / "SKILL.md").is_file()
    for name in receipt["skills"]:
        assert not (destination / name / "danger.sh").exists()
    assert opencode_security.verify(destination) == 0


def test_sources_bootstrap_dry_run_never_clones(tmp_path):
    root = tmp_path / "source-root"
    result = secra_skill_sources.prepare(root, apply=False)
    assert len(result) == 4
    assert all(item["status"] == "dry_run_missing" for item in result)
    assert not root.exists()


def test_curated_kali_inventory_has_no_implicit_execution_or_install(tmp_path):
    data = secra_kali_tools.inventory(("recon", "reverse", "forensics", "web"))
    assert len(data["categories"]) == 4
    assert data["network_scans_performed"] == 0
    assert data["mcp_execution_authorized"] is False
    assert "nmap" in {x["tool"] for x in data["categories"]["recon"]}
    result = subprocess.run([
        sys.executable, str(opencode_security.ROOT / "scripts" / "secra_kali_tools.py"),
        "--category", "reverse",
    ], cwd="/tmp", capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["network_scans_performed"] == 0
    assert payload["apt_install_plan"] == sorted(payload["apt_install_plan"])
