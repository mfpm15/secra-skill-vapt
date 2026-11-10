"""SECRA v0.7 baseline compatibility gate for optional ARES-style planning.

The canonical first 20 MCP entries are pinned to the reviewed main tree
at 302be31d0db6de717883bd3583e466232b7af106. New append-only tools
must never silently mutate the existing MCP tool contracts.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from app.mcp.manifest import ToolManifest

BASELINE_MAIN = "302be31d0db6de717883bd3583e466232b7af106"
BASELINE_MANIFEST_GIT_BLOB_SHA1 = "5c79ed120f4a82d06d0506f13e79f487128f4d98"
BASELINE_TOOL_COUNT = 20
EXPECTED_CORE_FILES = (
    "app/sapper_integration.py",
    "app/gateway/fence.py",
    "app/masking/redact.py",
    "app/masking/rehydrate.py",
    "app/evidence_vault.py",
    "app/tool_gateway.py",
    "app/loop/store.py",
    "scripts/opencode_global.py",
    "scripts/secra_launcher.py",
)
ROOT = Path(__file__).resolve().parents[2]


def _git_blob_sha1(data: bytes) -> str:
    """Use Git's normal content-addressed object hashing with no network."""
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def test_first_20_mcp_tool_schemas_byte_equivalent_to_verified_main():
    raw = json.loads((ROOT / "app/mcp/manifest.json").read_text(encoding="utf-8"))
    assert raw["schema"] == 1
    assert len(raw["tools"]) >= BASELINE_TOOL_COUNT
    old = {"schema": 1, "tools": raw["tools"][:BASELINE_TOOL_COUNT]}
    original_bytes = (json.dumps(old, indent=2) + "\n").encode("utf-8")
    assert _git_blob_sha1(original_bytes) == BASELINE_MANIFEST_GIT_BLOB_SHA1
    assert raw["tools"][BASELINE_TOOL_COUNT]["name"] == "workflow.plan_preview"
    manifest = ToolManifest()
    assert list(manifest.tools)[:BASELINE_TOOL_COUNT] == [
        item["name"] for item in old["tools"]
    ]


def test_only_additive_planning_adapter_over_existing_registry():
    manifest = ToolManifest()
    tool = manifest.get("workflow.plan_preview")
    assert len(manifest.tools) == 21
    assert tool.risk == "R0"
    assert tool.adapter == "plan_preview"
    assert tool.mode == "both"
    assert tool.input_schema["additionalProperties"] is False
    assert sorted(tool.input_schema["required"]) == ["task_id"]
    assert len(tool.input_schema["oneOf"]) == 2
    assert not any("argv" in x for x in tool.input_schema["properties"])


def test_legacy_critical_source_files_still_present():
    for relative in EXPECTED_CORE_FILES:
        assert (ROOT / relative).is_file(), relative


def test_one_entrypoint_kept_and_not_replaced():
    from scripts.secra_launcher import SCRIPT
    from scripts.opencode_global import AGENTS
    assert 'exec opencode --agent secra "$@"' in SCRIPT
    assert len(AGENTS) == 28
    assert AGENTS[0] == "secra"
