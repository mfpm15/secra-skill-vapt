"""OpenCode v2 global user installation and agent permission contracts."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml

from scripts import opencode_global

ROOT = Path(__file__).resolve().parents[2]


def invoke(*args):
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "opencode_global.py"), *map(str, args)],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )


def test_all_v2_native_agent_profiles_exist():
    assert len(opencode_global.AGENTS) == 28
    for name in opencode_global.AGENTS:
        content = opencode_global.agent_text(name, 2)
        assert content.startswith("---\n")
        assert "permissions:\n" in content
        assert '  - action: "*"\n    resource: "*"\n    effect: deny' in content
        assert "  - action: skill\n    resource: \"*\"\n    effect: allow" in content
        assert "    effect: ask" in content or name.startswith("secra-")
        if name == "secra-vapt":
            assert '  - action: secra_*\n    resource: "*"\n    effect: ask' in content
            assert "  - action: shell" not in content
            assert "  - action: execute" not in content
        if name == "secra-ctf":
            assert '  - action: shell\n    resource: "*"\n    effect: ask' in content
            assert '  - action: secra_artifact_*\n    resource: "*"\n    effect: ask' in content
            assert '  - action: secra_workflow_capabilities\n    resource: "*"\n    effect: allow' in content


def test_global_install_from_arbitrary_directory(tmp_path):
    config = tmp_path / "config"
    learning = tmp_path / "learning"
    result = invoke("install", "--major", "2", "--config-dir", config, "--learning-dir", learning)
    assert result.returncode == 0, result.stderr
    assert len(list((config / "agents").glob("*.md"))) == 28
    assert len(list((config / "skills").glob("*/SKILL.md"))) == 35
    assert (learning / "inbox").is_dir()
    assert (learning / "reviewed").is_dir()
    assert invoke("verify", "--major", "2", "--config-dir", config, "--learning-dir", learning).returncode == 0
    assert not (config / "opencode.json").exists()  # MCP requires explicit opt-in


def test_global_dry_run_is_non_mutating(tmp_path):
    config = tmp_path / "config"
    learning = tmp_path / "learning"
    result = invoke("install", "--major", "2", "--config-dir", config, "--learning-dir", learning, "--dry-run")
    assert result.returncode == 0, result.stderr
    assert not config.exists()
    assert not learning.exists()


def test_global_mcp_direct_tools_for_v2():
    obj = opencode_global.global_mcp_preview(2)
    assert obj["servers"]["secra"]["type"] == "local"
    assert obj["servers"]["secra"]["disabled"] is False
    assert obj["servers"]["secra"]["codemode"] is False
    assert Path(obj["servers"]["secra"]["cwd"]).is_absolute()


def test_global_agent_permission_is_tamper_detected(tmp_path):
    config = tmp_path / "config"
    args = ("--major", "2", "--config-dir", config, "--learning-dir", tmp_path / "learning")
    assert invoke("install", *args).returncode == 0
    tampered = config / "agents" / "secra-vapt.md"
    tampered.write_text(tampered.read_text(encoding="utf-8") + "\nUntrusted tampering\n", encoding="utf-8")
    result = invoke("verify", *args)
    assert result.returncode != 0
    assert "Tampered" in result.stderr


def test_global_works_alongside_existing_config_without_overwrite(tmp_path):
    config = tmp_path / "config"
    config.mkdir()
    settings = {"model": "example/model", "provider": {"example": {"options": {}}}}
    (config / "opencode.json").write_text(json.dumps(settings), encoding="utf-8")
    result = invoke("install", "--major", "2", "--config-dir", config, "--learning-dir", tmp_path / "learning")
    assert result.returncode == 0, result.stderr
    assert json.loads((config / "opencode.json").read_text()) == settings


def test_global_external_review_required_before_install(tmp_path):
    config = tmp_path / "config"
    result = invoke("install", "--major", "2", "--config-dir", config,
                    "--with-external", "--external-root", tmp_path / "source")
    assert result.returncode != 0
    assert not config.exists()


def test_global_v2_launch_plan_has_no_fixed_scope():
    agent = opencode_global.agent_text("secra-vapt", 2)
    assert "Ask the operator" in agent
    assert "approved IP/CIDR" in agent
    assert "do not have a predefined target" in agent
    assert "kernel egress attestation" in agent

def test_offline_toolcheck_does_not_execute_security_tools():
    from scripts import opencode_toolcheck
    report = opencode_toolcheck.report()
    assert isinstance(report["groups"], dict)
    assert "recon" in report["groups"]
    assert "available" in report["groups"]["recon"]
    assert "missing" in report["groups"]["recon"]
    assert len(report["manifest"]) >= 5
    assert "not execution authorization" in report["disclaimer"]


def test_all_global_agents_parse_as_valid_native_v2_frontmatter():
    for name in opencode_global.AGENTS:
        content = opencode_global.agent_text(name, 2)
        assert content.startswith("---\n")
        separator = "\n---\n"
        _, _, body = content.partition(separator)
        assert body, name
        frontmatter = content[len("---\n"):content.index(separator)]
        metadata = yaml.safe_load(frontmatter)
        assert metadata["mode"] in {"primary", "subagent"}
        assert isinstance(metadata["permissions"], list)
        for rule in metadata["permissions"]:
            assert set(rule) == {"action", "resource", "effect"}
            assert rule["effect"] in {"allow", "ask", "deny"}
            assert isinstance(rule["action"], str)
            assert isinstance(rule["resource"], str)
        assert metadata["permissions"][0] == {"action": "*", "resource": "*", "effect": "deny"}


def test_sensitive_paths_never_silently_allowed_in_v2_agents():
    import fnmatch

    def result(rules, action, resource):
        effect = "ask"
        for rule in rules:
            if fnmatch.fnmatchcase(action, rule["action"]) and fnmatch.fnmatchcase(resource, rule["resource"]):
                effect = rule["effect"]
        return effect

    for name in opencode_global.AGENTS:
        document = opencode_global.agent_text(name, 2)
        frontmatter = document.split("\n---\n", 1)[0][len("---\n"):]
        rules = yaml.safe_load(frontmatter)["permissions"]
        assert result(rules, "read", "project/src/main.py") == "allow", name
        assert result(rules, "read", "project/.env") == "ask", name
        assert result(rules, "read", "project/.env.staging") == "ask", name
        assert result(rules, "read", "project/.env.example") == "allow", name
        for sensitive in (
            "/home/kali/.ssh/id_ed25519",
            "/home/kali/.aws/credentials",
            "/home/kali/.kube/config",
            "project/private.key",
            "project/server.pem",
            "project/client.p12",
            "project/client.pfx",
            "/home/kali/.ssh/id_rsa",
            "/home/kali/.git-credentials",
            "/home/kali/.npmrc",
            "/home/kali/.netrc",
            "/home/kali/.pypirc",
            "/home/kali/.docker/config.json",
        ):
            assert result(rules, "read", sensitive) == "deny", (name, sensitive)
        assert result(rules, "read", "/home/kali/.config/opencode/opencode.json") == "ask", name
        assert result(rules, "grep", "password") == "ask", name
        if name != "secra-ctf":
            assert result(rules, "shell", "cat .env") == "deny", name
