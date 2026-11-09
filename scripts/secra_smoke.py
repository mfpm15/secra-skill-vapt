#!/usr/bin/env python3
"""One-command, offline-only SECRA agent smoke test for Kali/OpenCode installs.

It uses a fresh temporary directory and built-in FakeDemoModel. Never reads an
existing customer engagement, calls 9Router, opens sockets or runs Kali tools.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.loop.agent import AgentLoop, FakeDemoModel
from app.loop.case_integrity import check_case
from app.loop.store import TaskStore
from app.mcp.dispatcher import ToolDispatcher
from app.workspace import WorkspaceManager


def run_offline_smoke() -> dict:
    with tempfile.TemporaryDirectory(prefix="secra-offline-smoke-") as isolated:
        root = Path(isolated)
        store = TaskStore(root)
        tid = store.create("127.0.0.1", "127.0.0.1/32",
                           mode="demo", authorized=True)
        dispatcher = ToolDispatcher(root, store=store)
        ready = dispatcher.call("workflow.capabilities", {"task_id": tid})
        store.start(tid)
        proposal = dispatcher.call("workflow.lead_propose", {
            "task_id": tid,
            "category": "web",
            "title": "Review synthetic response header",
        })
        result = AgentLoop(store, dispatcher, max_steps=4).run(
            tid, model=FakeDemoModel())
        handoff = dispatcher.call("workflow.handoff", {"task_id": tid})
        WorkspaceManager(root / "engagements").write_manifest(tid)
        case = check_case(store, tid)
        tool_rows = store.tool_runs(tid)
        return {
            "schema": "secra-offline-smoke-v1",
            "simulation_only": True,
            "real_provider_tested": False,
            "kali_kernel_fence_tested": False,
            "real_target_probed": False,
            "preflight_status": ready["status"],
            "lead_proposal_status": proposal["status"],
            "agent_status": result.status,
            "agent_tool_steps": result.steps,
            "handoff_status": handoff["status"],
            "evidence_integrity": case["status"],
            "tool_audit_rows": len(tool_rows),
            "simulated_observations": sum(x["status"] == "simulated"
                                          for x in tool_rows),
            "verified_vulnerabilities": 0,
        }


def main() -> int:
    try:
        result = run_offline_smoke()
    except Exception:
        print("SECRA offline smoke failed: see local test logs.", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if (
        result["preflight_status"] == "completed"
        and result["lead_proposal_status"] == "completed"
        and result["agent_status"] == "completed"
        and result["agent_tool_steps"] == 2
        and result["handoff_status"] == "completed"
        and result["evidence_integrity"] == "integrity_ok"
        and result["simulated_observations"] == 2
    ) else 2


if __name__ == "__main__":
    raise SystemExit(main())
