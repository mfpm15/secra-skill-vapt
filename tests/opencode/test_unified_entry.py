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
    assert executed.stdout == "ARGS=--version\\n"
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


def test_unmanaged_global_secra_profile_cannot_receive_managed_launcher(tmp_path):
    config = tmp_path / "config"
    (config / "agents").mkdir(parents=True)
    existing = config / "agents" / "secra.md"
    existing.write_text("---\nmode: primary\n---\n\n# operator-owned\n")
    launcher = tmp_path / "bin"
    run = installer(
        "install", "--major", "2", "--config-dir", config,
        "--learning-dir", tmp_path / "learning",
        "--launcher-dir", launcher, "--with-launcher", "--replace"
    )
    assert run.returncode != 0
    assert "not installed and verified" in run.stderr
    assert "operator-owned" in existing.read_text()
    assert not (launcher / "secra").exists()


@pytest.mark.parametrize("variant", ["v1", "mini"])
def test_migrates_old_managed_launcher_to_full_tui(tmp_path, variant):
    """Old managed SECRA scripts can upgrade while preserving original backup."""
    script = tmp_path / "bin" / "secra"
    script.parent.mkdir(parents=True)
    old_script = (secra_launcher.LEGACY_V1_SCRIPT if variant == "v1"
                  else secra_launcher.LEGACY_MINI_SCRIPT)
    script.write_text(old_script)
    script.chmod(0o700)
    assert secra_launcher.MARKER in old_script
    assert old_script != secra_launcher.SCRIPT
    with pytest.raises(secra_launcher.LauncherError):
        secra_launcher.install(script, replace=False)
    result = secra_launcher.install(script, replace=True)
    assert result.startswith("INSTALLED")
    secra_launcher.verify(script)
    saved = script.parent / "secra.secra-previous"
    assert saved.read_text() == old_script
    assert saved.stat().st_mode & 0o777 == 0o600


def test_launcher_starts_full_screen_tui_with_scoped_secra_default(tmp_path):
    """The V2 root command succeeds, but rejects the unsupported --agent flag."""
    script = tmp_path / "bin" / "secra"
    secra_launcher.install(script)
    system = tmp_path / "fake-bin"
    system.mkdir()
    opencode = system / "opencode"
    opencode.write_text(
        "#!/bin/sh\\n"
        'if [ "$1" = "--agent" ]; then echo "Unrecognized flag" >&2; exit 2; fi\\n'
        'if [ "$1" = "mini" ]; then exit 3; fi\\n'
        'python3 -c "import json,os; c=json.loads(os.environ[\\\"OPENCODE_CONFIG_CONTENT\\\"]); assert c[\\\"default_agent\\\"]==\\\"secra\\\"" || exit 4\\n'
        "exit 0\\n"
    )
    opencode.chmod(0o700)
    env = {**os.environ, "PATH": str(system) + os.pathsep + os.environ["PATH"]}
    env.pop("OPENCODE_CONFIG_CONTENT", None)
    assert subprocess.run([str(script)], env=env, capture_output=True).returncode == 0
    assert subprocess.run([str(opencode), "--agent", "secra"],
                          env=env, capture_output=True).returncode == 2


def test_launcher_preserves_inline_model_and_provider_config(tmp_path):
    script = tmp_path / "bin" / "secra"
    secra_launcher.install(script)
    system = tmp_path / "fake-bin"
    system.mkdir()
    opencode = system / "opencode"
    opencode.write_text(
        '#!/bin/sh\\n'
        "python3 -c 'import json,os; c=json.loads(os.environ[\"OPENCODE_CONFIG_CONTENT\"]); "
        'assert c["default_agent"]=="secra"; '
        'assert c["model"]=="9router/current-model"; '
        'assert c["provider"]["9router"]["timeout"]==123' "\\n"
    )
    opencode.chmod(0o700)
    env = {**os.environ, "PATH": str(system) + os.pathsep + os.environ["PATH"],
           "OPENCODE_CONFIG_CONTENT": '{"model":"9router/current-model","provider":{"9router":{"timeout":123}},"default_agent":"build"}'}
    execution = subprocess.run([str(script)], env=env, capture_output=True)
    assert execution.returncode == 0, execution.stderr
    assert "OPENCODE_CONFIG_CONTENT" in env
    # Parent process unchanged: launcher config is scoped to the child.
    assert json.loads(env["OPENCODE_CONFIG_CONTENT"])["default_agent"] == "build"


def test_launcher_rejects_malformed_inline_config_without_falling_back(tmp_path):
    script = tmp_path / "bin" / "secra"
    secra_launcher.install(script)
    system = tmp_path / "fake-bin"
    system.mkdir()
    opencode = system / "opencode"
    opencode.write_text("#!/bin/sh\\nexit 0\\n")
    opencode.chmod(0o700)
    env = {**os.environ, "PATH": str(system) + os.pathsep + os.environ["PATH"],
           "OPENCODE_CONFIG_CONTENT": "{bad-json"}
    assert subprocess.run([str(script)], env=env, capture_output=True).returncode != 0
