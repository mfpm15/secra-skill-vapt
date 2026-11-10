"""ARES-inspired reviewed-tool chain preflight, strictly preview-only.

This is a read-only description of *current* task/tool metadata, not a plan
scheduler, an authorization grant, an approval token or a fence attestation.
It never imports execution adapters or invokes the Sapper graph.
"""
from __future__ import annotations

import re

from app.loop.readiness import inspect_capabilities
from app.loop.store import TaskStore
from app.mcp.manifest import ToolManifest

MAX_STEPS = 8
# Fixed offline goal templates: reviewed names only, with no target data,
# LLM commands, tool parameters, dynamic discovery or execution side effects.
GOAL_TEMPLATES = {
    "engagement_overview": (
        "inventory.read", "workflow.capabilities", "workflow.handoff",
    ),
    "demo_web_baseline": (
        "inventory.read", "demo.nmap_scan", "demo.httpx_probe", "report.summary",
    ),
    "artifact_triage": (
        "inventory.read", "artifact.sha256", "artifact.file_type",
        "artifact.strings",
    ),
    "sapper_graph_review": (
        "workflow.capabilities", "workflow.graph_frontier", "workflow.handoff",
    ),
    "live_recon_review": (
        "inventory.read", "workflow.capabilities",
        "nmap.tcp_top20", "curl.http_head",
    ),
}


def goal_steps(goal: str) -> list[str]:
    """Resolve one first-party fixed sequence; never generate a live action."""
    if not isinstance(goal, str) or goal not in GOAL_TEMPLATES:
        raise PlanError("PLAN_GOAL_UNREVIEWED")
    return list(GOAL_TEMPLATES[goal])

_STEP = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
# No user-supplied targets, argv, URLs, credentials, network destinations,
# parameters or LLM output are accepted. Every selected ID must be reviewed.
EXPOSURE = {
    "gateway_nmap": "network_gateway",
    "gateway_curl": "network_gateway",
    "loopback_head": "loopback_only",
    "local_artifact": "local_artifact",
    "approval_only": "approval_queue_only",
    "deny": "prohibited",
    "demo_nmap": "simulation",
    "demo_httpx": "simulation",
    "report_summary": "simulation",
}
VERDICTS = {
    "read_only": "read_only_candidate",
    "local_metadata": "metadata_candidate",
    "proposal_only": "proposal_candidate",
    "simulated": "simulation_candidate",
    "local_only": "local_candidate",
    "gated": "blocked",
    "operator_review": "blocked",
    "blocked": "blocked",
}


class PlanError(ValueError):
    """Invalid preview contract: never interpreted as dispatch authority."""


def preview_plan(store: TaskStore, manifest: ToolManifest,
                 task_id: str, steps: list[str]) -> dict:
    """Return bounded, sanitized static verdicts with zero target execution."""
    if (not isinstance(steps, list) or not 1 <= len(steps) <= MAX_STEPS
            or any(not isinstance(x, str) or not _STEP.fullmatch(x) for x in steps)
            or len(steps) != len(set(steps))):
        raise PlanError("PLAN_STEPS_INVALID")

    # Task authority is loaded from the local store; no caller-selected mode,
    # attestation, role, approval, timeout or scope facts are accepted.
    readiness = inspect_capabilities(store, manifest, task_id)
    capabilities = {x["name"]: x for x in readiness["tools"]}
    analyzed = []
    for index, name in enumerate(steps, 1):
        tool = manifest.tools.get(name)
        if tool is None or name == "workflow.plan_preview":
            analyzed.append({
                "step": index, "tool": name, "risk": None,
                "exposure": "unreviewed", "classification": "unknown",
                "verdict": "rejected", "reason": "tool_not_reviewed",
            })
            continue
        classification = capabilities[name]["classification"]
        verdict = VERDICTS.get(classification, "blocked")
        # These are never eligible for auto-execution even if a later
        # capability inventory or task status changes.
        if tool.risk in {"R3", "R4"} or tool.adapter in {"deny", "approval_only"}:
            verdict = "blocked"
        analyzed.append({
            "step": index, "tool": name, "risk": tool.risk,
            "exposure": EXPOSURE.get(tool.adapter, "local_metadata"),
            "classification": classification, "verdict": verdict,
            "reason": capabilities[name]["reason"],
        })

    blocked = sum(x["verdict"] in {"blocked", "rejected"} for x in analyzed)
    return {
        "schema": "secra-plan-preview-v1",
        "asset": "ASSET_001",
        "task_mode": readiness["mode"],
        "task_status": readiness["task_status"],
        "steps": analyzed,
        "blocked_steps": blocked,
        "plan_verdict": "blocked" if blocked else "preview_only",
        "execution_authorized": False,
        "kernel_fence_attested": False,
        "tool_calls_performed": 0,
        "note": "Offline metadata preview only; no plan dispatch, approval, or live readiness.",
    }


def short_preview(result: dict) -> str:
    """Model-safe, bounded explanation; no user content other than tool IDs."""
    steps = "; ".join(
        f"{x['step']}:{x['tool']}={x['verdict']}" for x in result["steps"]
    )
    return (
        "OFFLINE PREVIEW ONLY; 0 tools executed; fence NOT attested; "
        "no execution authorization. SECRA " + result["plan_verdict"]
        + ": " + steps
    )[:490]
