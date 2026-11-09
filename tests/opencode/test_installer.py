"""Offline tests for installing OpenCode knowledge without executing upstream code."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts import opencode_security as installer
from scripts import opencode_mcp_config

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "scripts" / "opencode_security.py"


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(CLI), *map(str, args)],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )


def test_project_install_and_verify_in_scratch_directory(tmp_path):
    destination = tmp_path / "skills"
    result = run_cli("install", "--destination", str(destination))
    assert result.returncode == 0, result.stderr
    receipt = json.loads((destination / installer.MANIFEST_NAME).read_text())
    assert len(receipt["skills"]) == 20
    for skill_id in receipt["skills"]:
        path = destination / skill_id / "SKILL.md"
        assert path.is_file()
        body = path.read_text()
        assert body.startswith("---\nname: " + skill_id + "\n")
        assert "description:" in body
    assert run_cli("verify", "--destination", str(destination)).returncode == 0


def test_dry_run_does_not_modify_destination(tmp_path):
    destination = tmp_path / "skills"
    result = run_cli("install", "--destination", str(destination), "--dry-run")
    assert result.returncode == 0, result.stderr
    assert not destination.exists()


def test_external_requires_manual_review(tmp_path):
    result = run_cli(
        "install", "--destination", str(tmp_path / "skills"),
        "--with-external", "--external-root", str(tmp_path),
    )
    assert result.returncode != 0
    assert "review" in result.stderr.lower()
    assert not (tmp_path / "skills").exists()


def test_importer_keeps_only_documents(tmp_path):
    source = tmp_path / "source"
    (source / "references").mkdir(parents=True)
    (source / "SKILL.md").write_text("---\nname: something\n---\n\n# Notes\n", encoding="utf-8")
    (source / "references" / "notes.md").write_text("Useful note.", encoding="utf-8")
    (source / "install.sh").write_text("echo SHOULD_NOT_EXECUTE\n", encoding="utf-8")
    (source / "script.py").write_text("print('NO')\n", encoding="utf-8")
    files = installer.build_skill(source, "secra-test-docs", "Test reference.", "test:source", True)
    assert "references/notes.md" in files
    assert "install.sh" not in files
    assert "script.py" not in files
    assert files["SKILL.md"].startswith(b"---\nname: secra-test-docs\n")


def test_symlink_source_skill_denied(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    external = tmp_path / "external.md"
    external.write_text("# Do not trust\n", encoding="utf-8")
    (source / "SKILL.md").symlink_to(external)
    try:
        installer.build_skill(source, "secra-test-link", "Test.", "test:link", True)
    except ValueError as exc:
        assert "unsafe" in str(exc).lower()
    else:
        raise AssertionError("Symlink source should be refused")


def test_existing_unmanaged_skill_is_not_overwritten(tmp_path):
    destination = tmp_path / "skills"
    target = destination / "secra-test-existing"
    target.mkdir(parents=True)
    (target / "SKILL.md").write_text("Operator content", encoding="utf-8")
    status = installer.install_one(
        destination, "secra-test-existing",
        {"SKILL.md": b"REPLACEMENT", ".secra-origin.json": b"{}"}, True, False,
    )
    assert status.startswith("SKIP unmanaged")
    assert (target / "SKILL.md").read_text() == "Operator content"


def test_receipt_detects_tampering(tmp_path):
    destination = tmp_path / "skills"
    assert run_cli("install", "--destination", str(destination)).returncode == 0
    target = destination / "secra-scope-and-engagement" / "SKILL.md"
    target.write_text(target.read_text() + "\nCHANGED", encoding="utf-8")
    assert run_cli("verify", "--destination", str(destination)).returncode != 0


def test_v1_v2_mcp_config_differ_and_are_opt_in():
    v1 = opencode_mcp_config.build_config(1)
    v2 = opencode_mcp_config.build_config(2)
    assert "secra" in v1["mcp"]
    assert v1["mcp"]["secra"]["enabled"] is True
    assert "secra" in v2["mcp"]["servers"]
    assert v2["mcp"]["servers"]["secra"]["disabled"] is False
    assert v1 != v2


def test_reference_tampering_detected(tmp_path):
    source = tmp_path / "src"
    (source / "references").mkdir(parents=True)
    (source / "SKILL.md").write_text("# Triage\n", encoding="utf-8")
    (source / "references" / "triage.md").write_text("Reviewed", encoding="utf-8")
    files = installer.build_skill(source, "secra-test-ref", "Test.", "test:ref", True)
    destination = tmp_path / "skills"
    assert installer.install_one(destination, "secra-test-ref", files, False, False).startswith("INSTALLED")
    receipt = {"schema": 1, "skills": {"secra-test-ref": json.loads(files[".secra-origin.json"])}}
    (destination / installer.MANIFEST_NAME).write_text(json.dumps(receipt), encoding="utf-8")
    assert installer.verify(destination) == 0
    (destination / "secra-test-ref" / "references" / "triage.md").write_text("TAMPERED", encoding="utf-8")
    assert installer.verify(destination) != 0


def test_trailofbits_semgrep_allowlist_matches_upstream_layout():
    entries = [
        entry for entry in installer.EXTERNAL
        if entry[2] == "secra-tob-static-analysis"
    ]
    assert len(entries) == 1
    source_dir, relative, skill_id, description = entries[0]
    assert source_dir == "trailofbits-skills"
    assert relative == "plugins/static-analysis/skills/semgrep"
    assert "reference" in description.lower()
    assert "script" in description.lower()


def test_semgrep_reference_does_not_import_executable_sidecar(tmp_path):
    source = tmp_path / "trailofbits-skills" / "plugins" / "static-analysis" / "skills" / "semgrep"
    source.mkdir(parents=True)
    (source / "SKILL.md").write_text("---\nname: semgrep\n---\n# Semgrep\n", encoding="utf-8")
    (source / "scripts").mkdir()
    (source / "scripts" / "run-scans.sh").write_text("echo NOPE\n", encoding="utf-8")
    files = installer.build_skill(
        source, "secra-tob-static-analysis", "Semgrep static analysis reference.",
        "trailofbits-skills:plugins/static-analysis/skills/semgrep", True
    )
    assert "SKILL.md" in files
    assert "scripts/run-scans.sh" not in files
