"""Narrow 9Router planner: tool IDs and PUBLIC sanitized metadata only.

Unlike existing Phase-1 advisory chat, this is a separate *reviewed* tool-choice
schema; it cannot transmit a target, unmask a placeholder, send raw tool output,
or carry arbitrary messages. Only returned manifest tool IDs are actionable.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass

from app.masking import MemoryVault, guard_mask
from app.security import (EMAIL, IPV4, BEARER, SECRET, DOMAIN, JWT,
                          assert_no_sensitive_payload, llm_safe_payload,
                          safe_gateway, safe_model)
from app.mcp.manifest import ToolDefinition


class ModelError(RuntimeError):
    pass


class ModelRefused(ModelError):
    pass


@dataclass(frozen=True)
class Choice:
    tool: str
    arguments: dict


def _model_schema(definition: ToolDefinition) -> dict:
    schema = definition.input_schema
    # task_id and real target are supplied ONLY locally by the dispatcher.
    properties = {k: v for k, v in schema["properties"].items() if k != "task_id"}
    return {"type": "object", "properties": properties,
            "required": [x for x in schema.get("required", []) if x != "task_id"],
            "additionalProperties": False}


def _safe_summary(value: str) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= 240
            or not re.fullmatch(r"[A-Za-z0-9 .,;:_-]+", value)
            or EMAIL.search(value) or IPV4.search(value)
            or DOMAIN.search(value) or JWT.search(value)
            or BEARER.search(value) or SECRET.search(value)):
        raise ModelError("MODEL_RESULT_NOT_SANITIZED")
    return value


class NineRouterPlanner:
    def __init__(self, model: str, *, gateway: str | None = None,
                 key: str | None = None):
        self.model = safe_model(model)
        self.gateway = safe_gateway(gateway or os.environ.get(
            "SECRA_9ROUTER_BASE_URL", "http://127.0.0.1:20128/v1"))
        self.key = key if key is not None else os.environ.get("SECRA_9ROUTER_API_KEY", "")
        if not self.key:
            raise ModelError("NINEROUTER_KEY_MISSING")

    def choose(self, *, public_prompt: str, skills: str,
               tools: list[ToolDefinition], prior: tuple[str, str] | None,
               services: list[dict]) -> Choice | None:
        if not tools or len(tools) > 16:
            raise ModelError("MODEL_TOOL_LIST_DENIED")
        if (not isinstance(public_prompt, str) or len(public_prompt) > 750
                or not isinstance(skills, str) or len(skills) > 2500):
            raise ModelError("MODEL_STATIC_CONTEXT_INVALID")
        metadata = llm_safe_payload(services)
        assert_no_sensitive_payload(metadata)
        encoded = json.dumps(metadata, separators=(",", ":"))
        checked, _ = guard_mask(encoded, vault=MemoryVault(), for_llm=True)
        if checked != encoded:
            raise ModelError("MODEL_CANONICAL_METADATA_CHANGED")
        aliases = {item.name.replace(".", "__"): item.name for item in tools}
        if len(aliases) != len(tools):
            raise ModelError("MODEL_TOOL_ALIAS_COLLISION")
        public_tools = [
            {"type": "function", "function": {
                "name": name, "description": next(t.description for t in tools if t.name == value),
                "parameters": _model_schema(next(t for t in tools if t.name == value)),
            }} for name, value in aliases.items()
        ]
        messages = [
            {"role": "system", "content": public_prompt + "\n" + skills +
             "\nSelect at most one reviewed tool per step. No raw targets or arbitrary commands. "
             "Conclude when enough bounded observations exist; never infer vulnerabilities."},
            {"role": "user", "content": checked},
        ]
        if prior:
            name, summary = prior
            if name not in {x.name for x in tools} and not re.fullmatch(
                    r"[A-Za-z0-9_.-]{1,100}", name):
                raise ModelError("MODEL_PREVIOUS_TOOL_INVALID")
            messages.append({"role": "assistant", "content": (
                "Previous reviewed tool: " + name + ". " + _safe_summary(summary))})
        request_body = {
            "model": self.model, "temperature": 0.1, "max_tokens": 512,
            "tool_choice": "auto", "messages": messages, "tools": public_tools,
        }
        request = urllib.request.Request(
            self.gateway + "/chat/completions",
            data=json.dumps(request_body, separators=(",", ":")).encode(),
            headers={"Accept": "application/json", "Content-Type": "application/json",
                     "Authorization": "Bearer " + self.key}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=25) as response:
                result = json.loads(response.read(200000))
        except (OSError, TimeoutError, ValueError) as exc:
            raise ModelError("MODEL_TRANSPORT_FAILED") from exc
        try:
            message = result["choices"][0]["message"]
            if message.get("refusal"):
                raise ModelRefused("MODEL_SAFETY_REFUSAL")
            calls = message.get("tool_calls") or []
            if not calls:
                return None
            if not isinstance(calls, list) or len(calls) != 1:
                raise ModelError("MODEL_TOOL_CALL_COUNT_INVALID")
            item = calls[0]["function"]
            chosen = aliases.get(item["name"])
            if not chosen:
                raise ModelError("MODEL_UNREVIEWED_TOOL")
            params = json.loads(item["arguments"])
            if not isinstance(params, dict) or "task_id" in params or "target" in params:
                raise ModelError("MODEL_TOOL_ARGUMENTS_DENIED")
            from jsonschema import Draft202012Validator
            selected = next(t for t in tools if t.name == chosen)
            if list(Draft202012Validator(_model_schema(selected)).iter_errors(params)):
                raise ModelError("MODEL_TOOL_ARGUMENTS_DENIED")
            return Choice(chosen, params)
        except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ModelError("MODEL_RESPONSE_INVALID") from exc
