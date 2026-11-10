"""No-network and no-secret compatibility checkpoint regression."""
import json
import os
import stat

import pytest

from scripts.secra_upgrade_checkpoint import (
    capture, compare, file_sha, snapshot, SCHEMA,
)


def fixture_install(tmp_path):
    repo = tmp_path / "repo"
    config = tmp_path / "config"
    data = tmp_path / "data"
    launcher = tmp_path / "bin" / "secra"
    (repo / "app/mcp").mkdir(parents=True)
    (repo / ".venv/bin").mkdir(parents=True)
    (repo / ".venv/bin/python").write_text("fixture")
    (repo / "app/mcp/manifest.json").write_text(json.dumps({
        "schema": 1, "tools": [{"name": "inventory.read", "risk": "R0"}],
    }))
    (config / "agents").mkdir(parents=True)
    (config / "skills/secra-core").mkdir(parents=True)
    (config / "agents/secra.md").write_text("safe agent")
    (config / "opencode.json").write_text('{"provider":{"example":"not-a-secret"}}')
    (data / "evidence").mkdir(parents=True)
    (data / "agent-events.sqlite3").write_bytes(b"synthetic")
    launcher.parent.mkdir()
    launcher.write_text("#!/bin/sh\necho test\n")
    return repo, config, data, launcher


def test_checkpoint_additive_upgrade_preserves_metadata(tmp_path):
    repo, config, data, launcher = fixture_install(tmp_path)
    old = snapshot(repo, config, data, launcher)
    assert old["schema"] == SCHEMA
    assert old["task_database_present"]
    assert old["vault_directory_present"]
    assert "example" not in json.dumps(old)
    assert "not-a-secret" not in json.dumps(old)
    # New reviewed tool, new first-party agent and skill are additive.
    (repo / "app/mcp/manifest.json").write_text(json.dumps({
        "schema": 1, "tools": [
            {"name": "inventory.read", "risk": "R0"},
            {"name": "workflow.plan_preview", "risk": "R0"},
        ],
    }))
    (config / "agents/secra-recon.md").write_text("additional agent")
    (config / "skills/secra-upgrade").mkdir()
    new = snapshot(repo, config, data, launcher)
    check = compare(old, new)
    assert check["compatible"]
    assert check["previous_tool_count"] == 1
    assert check["current_tool_count"] == 2
    assert check["checks_failed"] == []


@pytest.mark.parametrize("drift,expected", [
    ("config", "OPENCODE_CONFIG_CHANGED_OPENCODE_JSON"),
    ("tool", "MCP_CONTRACT_CHANGED_inventory.read"),
    ("database", "TASK_DATABASE_PRESENT_LOST"),
    ("vault", "VAULT_DIRECTORY_PRESENT_LOST"),
    ("agent", "AGENTS_REMOVED"),
    ("skill", "SKILLS_REMOVED"),
    ("launcher", "LAUNCHER_REMOVED"),
])
def test_checkpoint_fail_closed_on_critical_drift(tmp_path, drift, expected):
    repo, config, data, launcher = fixture_install(tmp_path)
    baseline = snapshot(repo, config, data, launcher)
    if drift == "config":
        (config / "opencode.json").write_text('{"provider":"changed"}')
    elif drift == "tool":
        (repo / "app/mcp/manifest.json").write_text(json.dumps({
            "schema": 1, "tools": [{"name": "inventory.read", "risk": "R4"}],
        }))
    elif drift == "database":
        (data / "agent-events.sqlite3").unlink()
    elif drift == "vault":
        (data / "evidence").rmdir()
    elif drift == "agent":
        (config / "agents/secra.md").unlink()
    elif drift == "skill":
        (config / "skills/secra-core").rmdir()
    elif drift == "launcher":
        launcher.unlink()
    assert expected in compare(baseline, snapshot(repo, config, data, launcher))["checks_failed"]


def test_checkpoint_file_is_owner_only_and_not_overwritten(tmp_path):
    repo, config, data, launcher = fixture_install(tmp_path)
    state = snapshot(repo, config, data, launcher)
    output = tmp_path / "private" / "before.json"
    capture(output, state)
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert json.loads(output.read_text()) == state
    with pytest.raises(ValueError, match="ALREADY_EXISTS"):
        capture(output, {"invalid": True})
    assert json.loads(output.read_text()) == state


def test_checkpoint_symlinks_denied(tmp_path):
    repo, config, data, launcher = fixture_install(tmp_path)
    link = tmp_path / "out"
    link.symlink_to(config, target_is_directory=True)
    with pytest.raises(ValueError, match="SYMLINK"):
        snapshot(repo, link, data, launcher)
    backup = tmp_path / "private" / "checkpoint.json"
    backup.parent.mkdir()
    backup.symlink_to(config / "opencode.json")
    with pytest.raises(ValueError, match="SYMLINK"):
        capture(backup, {"schema": SCHEMA})


def test_missing_baseline_schema_rejected():
    with pytest.raises(ValueError, match="SCHEMA"):
        compare({"schema": "wrong"}, {"schema": SCHEMA})
