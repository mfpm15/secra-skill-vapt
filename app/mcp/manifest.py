"""Single source of truth for exposed MCP tool schemas.

Adding a tool requires a reviewed manifest entry and a named adapter stub.
The generic MCP server never needs a source change.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from jsonschema import Draft202012Validator

DEFAULT_MANIFEST = Path(__file__).with_name("manifest.json")
ADAPTERS = frozenset({"inventory_read", "demo_nmap", "demo_httpx",
                      "report_summary", "gateway_nmap", "gateway_curl",
                      "approval_only", "deny", "loopback_head",
                      "continuity_handoff", "lead_proposal", "capability_readiness",
                      "local_artifact"})
RISKS = {"R0": 0, "R1": 1, "R2": 2, "R3": 3, "R4": 4}
OUTPUT_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "status": {"type": "string"},
        "exit_code": {"type": ["integer", "null"]},
        "summary": {"type": "string"},
        "output_ref": {"type": ["string", "null"]},
        "masked": {"type": "boolean"},
    },
    "required": ["status", "exit_code", "summary", "output_ref", "masked"],
}


class ManifestError(ValueError):
    pass


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    description: str
    risk: str
    adapter: str
    mode: str
    input_schema: dict

    def validate(self, arguments: object) -> dict:
        if not isinstance(arguments, dict):
            raise ManifestError("TOOL_ARGUMENTS_OBJECT_REQUIRED")
        errors = list(Draft202012Validator(self.input_schema).iter_errors(arguments))
        if errors:
            raise ManifestError("TOOL_ARGUMENTS_SCHEMA_DENIED")
        return arguments


class ToolManifest:
    def __init__(self, path: str | Path = DEFAULT_MANIFEST):
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if set(raw) != {"schema", "tools"} or raw["schema"] != 1 or not isinstance(raw["tools"], list):
            raise ManifestError("MANIFEST_SCHEMA_INVALID")
        if len(raw["tools"]) > 64:
            raise ManifestError("MANIFEST_LIMIT_EXCEEDED")
        self.tools: dict[str, ToolDefinition] = {}
        for item in raw["tools"]:
            if set(item) != {"name", "description", "risk", "adapter", "mode", "inputSchema"}:
                raise ManifestError("MANIFEST_TOOL_FIELDS_INVALID")
            name = item["name"]
            if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", name)
                    or name in self.tools or item["risk"] not in RISKS
                    or item["adapter"] not in ADAPTERS or item["mode"] not in {"demo", "live", "local", "both"}
                    or not isinstance(item["description"], str)
                    or not 1 <= len(item["description"]) <= 240):
                raise ManifestError("MANIFEST_ENTRY_DENIED")
            schema = item["inputSchema"]
            if not isinstance(schema, dict) or schema.get("type") != "object" or schema.get("additionalProperties") is not False:
                raise ManifestError("MANIFEST_ARGUMENTS_NOT_CLOSED")
            Draft202012Validator.check_schema(schema)
            if "task_id" not in schema.get("required", []):
                raise ManifestError("MANIFEST_TASK_ID_REQUIRED")
            self.tools[name] = ToolDefinition(name, item["description"],
                                               item["risk"], item["adapter"],
                                               item["mode"], schema)

    def get(self, name: str) -> ToolDefinition:
        if not isinstance(name, str) or name not in self.tools:
            raise ManifestError("TOOL_NOT_IN_MANIFEST")
        return self.tools[name]

    def visible(self, mode: str | None = None) -> list[ToolDefinition]:
        return [x for x in self.tools.values()
                if mode is None or x.mode in {mode, "both"}]
