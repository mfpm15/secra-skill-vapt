"""Reviewed, immutable Phase-2 adapter registry; no user-provided argv."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Mapping
from uuid import UUID

Risk = Literal["R0", "R1", "R2", "R3", "R4"]
TOP20_TCP = (21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
             143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080)
HTTP_PORTS = frozenset({80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 3000, 5000, 9443})


class ToolDenied(ValueError):
    pass


@dataclass(frozen=True)
class StructuredToolIntent:
    engagement_id: UUID
    request_id: UUID
    agent_id: str
    action_id: str
    target_ref: str
    parameters: Mapping[str, object]
    reason_code: str = "authorized_observation"


@dataclass(frozen=True)
class ToolPolicy:
    action_id: str
    risk: Risk
    timeout_seconds: int
    max_stdout_bytes: int
    max_stderr_bytes: int
    network_enabled: bool
    allowed_parameters: frozenset[str]
    policy_version: str = "phase2-v1"
    max_parallel_by_asset: int = 1


# Any future adapter must be added here in reviewed code; never load from LLM JSON.
REGISTRY: Mapping[str, ToolPolicy] = {
    "asset_inventory.read": ToolPolicy("asset_inventory.read", "R0", 5, 0, 0, False, frozenset()),
    "zap.passive_import": ToolPolicy("zap.passive_import", "R1", 20, 0, 0, False, frozenset()),
    "nmap.tcp_top20": ToolPolicy("nmap.tcp_top20", "R2", 60, 524288, 65536, True, frozenset()),
    "curl.http_head": ToolPolicy("curl.http_head", "R2", 10, 131072, 32768, True, frozenset({"port"})),
    "http.authenticated_test": ToolPolicy("http.authenticated_test", "R3", 30, 0, 0, True, frozenset()),
    "prohibited.r4": ToolPolicy("prohibited.r4", "R4", 0, 0, 0, False, frozenset()),
}


def validate_tool_intent(intent: StructuredToolIntent) -> ToolPolicy:
    if not isinstance(intent, StructuredToolIntent):
        raise ToolDenied("INTENT_TYPE_INVALID")
    if (not isinstance(intent.engagement_id, UUID) or not isinstance(intent.request_id, UUID)
            or not isinstance(intent.agent_id, str)
            or not 1 <= len(intent.agent_id) <= 64
            or not intent.agent_id.isascii()
            or not all(c.isalnum() or c in "_-" for c in intent.agent_id)
            or not isinstance(intent.reason_code, str)
            or intent.reason_code != "authorized_observation"
            or not isinstance(intent.parameters, Mapping)):
        raise ToolDenied("INTENT_SCHEMA_INVALID")
    spec = REGISTRY.get(intent.action_id)
    if spec is None:
        raise ToolDenied("UNKNOWN_ACTION")
    if set(intent.parameters) != spec.allowed_parameters:
        raise ToolDenied("PARAMETERS_NOT_ALLOWED")
    if intent.action_id == "curl.http_head":
        port = intent.parameters["port"]
        if type(port) is not int or port not in HTTP_PORTS:
            raise ToolDenied("PORT_NOT_REVIEWED")
    # R0/R1 pending adapters, R3 pending approval store, R4 always prohibited.
    if intent.action_id not in {"nmap.tcp_top20", "curl.http_head"}:
        raise ToolDenied("ADAPTER_UNAVAILABLE_OR_PROHIBITED")
    return spec
