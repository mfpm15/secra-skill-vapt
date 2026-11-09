"""Deterministic, read-only capability preflight for a scoped SECRA task.

This is *not* a kernel fence attestation and never executes tools, opens a
socket, or promotes a finding. All target and customer data stay local.
"""
from __future__ import annotations

from collections import Counter

from app.loop.store import TaskStore
from app.mcp.manifest import ToolManifest

NO_EXECUTE = frozenset({"stopped", "failed", "completed", "exhausted", "refused"})
READ_ONLY = frozenset({"continuity_handoff", "capability_readiness"})


def inspect_capabilities(store: TaskStore, manifest: ToolManifest, task_id: str) -> dict:
    task = store.require(task_id)
    state = task["status"]
    mode = task["mode"]
    items = []
    for tool in manifest.visible():
        reason = None
        capability = "unknown"
        if tool.adapter == "deny" or tool.risk == "R4":
            capability, reason = "blocked", "prohibited_by_policy"
        elif tool.mode not in {"both", mode}:
            capability, reason = "blocked", "unavailable_in_task_mode"
        elif tool.adapter == "approval_only" or tool.risk == "R3":
            capability, reason = "operator_review", "no_executable_adapter"
        elif tool.adapter in {"gateway_nmap", "gateway_curl"}:
            # Never report live readiness without independently attesting the
            # actual kernel fence, binary digest, and operator scope at call time.
            capability, reason = "gated", "kernel_fence_scope_binary_attestation_required"
        elif tool.adapter == "loopback_head":
            if mode != "local":
                capability, reason = "blocked", "loopback_only"
            elif state != "running" or task["stop"]:
                capability, reason = "blocked", "task_not_running"
            else:
                capability, reason = "local_only", "loopback_permission_required"
        elif tool.adapter in READ_ONLY:
            capability = "read_only"
        elif state != "running" or task["stop"]:
            capability, reason = "blocked", "task_not_running"
        elif tool.mode == "demo":
            capability, reason = "simulated", "offline_fixture_only"
        elif tool.adapter == "lead_proposal":
            capability = "proposal_only"
        else:
            capability = "local_metadata"

        items.append({
            "name": tool.name, "mode": tool.mode, "risk": tool.risk,
            "classification": capability, "reason": reason
        })
    counts = Counter(item["classification"] for item in items)
    return {
        "schema": "secra-capability-preflight-v1",
        "asset": "ASSET_001",
        "mode": mode,
        "task_status": state,
        "scope_attested": False,
        "live_execution_ready": False,
        "note": ("Readiness is a non-executing inventory; individual tool calls "
                 "must re-check authorization, fence and policy."),
        "counts": {k: counts[k] for k in sorted(counts)},
        "tools": items,
    }


def short_capabilities(report: dict) -> str:
    """Model-visible, bounded, no target, no local path, no readiness bluff."""
    runnable = [item["name"] for item in report["tools"] if item["classification"]
                in {"read_only", "local_metadata", "simulated", "proposal_only", "local_only"}]
    guarded = [item["name"] for item in report["tools"] if item["classification"]
               in {"gated", "operator_review", "blocked"}]
    return (
        "SECRA " + report["mode"] + "/" + report["task_status"]
        + " offline tool preflight (not approval). Eligible by mode: "
        + (", ".join(runnable) or "none") + ". "
        + "Restricted: " + (", ".join(guarded) or "none")
        + ". Live fence/scope are NOT attested."
    )[:490]
