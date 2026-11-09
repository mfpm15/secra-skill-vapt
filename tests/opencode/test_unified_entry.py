"""Single SECRA entry point: global v2 agent, safe launcher and legacy coexistence."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from scripts import opencode_global, secra_launcher

ROOT = Path(__file__).resolve().parents[2]


def installer(*args, cwd="/tmp"):
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "opencode_global.py"), *map(str, args)],
        cwd=cwd, capture_output=True, text=True,
    )


def test_single_primary_entry_routes_every_specialist_without_unrestricted_shell():
    source = opencode_global.agent_text("secra", 2)
    front = source.split("\n---\n", 1)[0][len("---\n"):]
    settings = yaml.safe_load(front)
    assert settings["mode"] == "primary"
    rules = settings["permissions"]
    delegated = {item["resource"] for item in rules
                 if item["action"] == "subagent" and item["effect"] == "allow"}
    assert len(delegated) == 24
    assert "secra-verifier" in delegated
    assert "secra-bounty-scope" in delegated
    assert "secra-ctf-mobile" in delegated
    assert not any(item["action"] == "shell" and item["effect"] == "allow"
                   for item in rules)
    assert any(item["action"] == "secra_*" and item["effect"] == "ask"
               for item in rules)
    assert "Sapper-v2" in source
    assert "do not have a predefined target" not in source or "scope" in source
    assert "kernel fence" in source
    assert "never" in source.lower()


def test_global_launcher_install_verify_and_invokes_opencode_with_secra(tmp_path):
    config = tmp_path / "config"
    learning = tmp_path / "learning"
    user_bin = tmp_path / "user-bin"
    args = ("--major", "2", "--config-dir", config,
            "--learning-dir", learning, "--launcher-dir", user_bin,
            "--with-launcher")
    installation = installer("install", *args)
    assert installation.returncode == 0, installation.stderr
    assert (config / "agents" / "secra.md").is_file()
    assert (user_bin / "secra").is_file()
    assert installer("verify", *args).returncode == 0
    fake_bin = tmp_path / "fake-system-bin"
    fake_bin.mkdir()
    opencode = fake_bin / "opencode"
    opencode.write_text("#!/bin/sh\nprintf 'ARGS=%s\\n' \"$*\"\n")
    opencode.chmod(0o700)
    executed = subprocess.run(
        [str(user_bin / "secra"), "--version"],
        env={**os.environ, "PATH": str(fake_bin) + os.pathsep + os.environ["PATH"]},
        capture_output=True, text=True, cwd="/tmp"
    )
    assert executed.returncode == 0
    assert executed.stdout == "ARGS=--agent secra --version\n"
    assert len(list((config / "agents").glob("*.md"))) == 28


def test_launcher_dry_run_does_not_create_files(tmp_path):
    config = tmp_path / "config"
    learning = tmp_path / "learning"
    user_bin = tmp_path / "bin"
    result = installer(
        "install", "--major", "2",
        "--config-dir", config, "--learning-dir", learning,
        "--launcher-dir", user_bin, "--with-launcher", "--dry-run"
    )
    assert result.returncode == 0, result.stderr
    assert not (user_bin / "secra").exists()
    assert not config.exists()
    assert not learning.exists()


def test_launcher_refuses_overwriting_unmanaged_commands(tmp_path):
    path = tmp_path / "secra"
    path.write_text("#!/bin/sh\necho operator-owned\n")
    with pytest.raises(secra_launcher.LauncherError):
        secra_launcher.install(path, replace=True)
    assert "operator-owned" in path.read_text()


def test_agent_old_primaries_remain_compatible_but_not_required():
    assert {"secra", "secra-vapt", "secra-bounty", "secra-ctf"}.issubset(
        set(opencode_global.AGENTS))
    assert opencode_global.AGENTS[0] == "secra"
