"""Manifest dispatcher. Raw results seal locally; model sees a short receipt.

The only live adapters call the existing typed Phase-2 ToolGateway, which still
denies networking until the separately attested kernel fence is operational.
"""
from __future__ import annotations

import re
import json
import time
import sqlite3
import threading
import uuid
from pathlib import Path

from app.evidence_vault import EvidenceVault
from app.security import redact
from app.tool_gateway import ToolGateway
from app.tool_registry import StructuredToolIntent
from app.loop.store import TaskError, TaskStore, canonical_id
from .manifest import ManifestError, RISKS, ToolDefinition, ToolManifest
from . import stubs
from .loopback import run_head


def receipt(status: str, code: int | None, summary: str,
            output_ref: str | None = None) -> dict:
    return {"status": status, "exit_code": code,
            "summary": redact(summary)[:500], "output_ref": output_ref,
            "masked": True}


class ToolDispatcher:
    def __init__(self, root: str | Path, *, store: TaskStore | None = None,
                 manifest: ToolManifest | None = None, gateway=None):
        self.root = Path(root)
        self.store = store or TaskStore(self.root)
        self.manifest = manifest or ToolManifest()
        self.gateway = gateway or ToolGateway(self.root / "evidence")
        self.vault = self.gateway.vault

    def call(self, name: str, arguments: dict,
             stop: threading.Event | None = None) -> dict:
        """Audit each valid invocation BEFORE running an adapter.

        Keeps current result and UI event contracts unchanged; new audit
        rows contain only tool, time, outcome and encrypted evidence reference.
        """
        try:
            tool = self.manifest.get(name)
            validated = tool.validate(arguments)
            tid = canonical_id(validated["task_id"])
            self.store.require(tid)
        except (ManifestError, TaskError, KeyError, TypeError):
            return self._call(name, arguments, stop)
        try:
            audit_id = self.store.begin_tool_run(tid, tool.name)
        except (TaskError, sqlite3.Error, OSError):
            return receipt("blocked", None, "Local audit unavailable; no tool dispatched.")

        started = time.monotonic()
        try:
            response = self._call(name, arguments, stop)
        except BaseException:
            # Do not expose raw exception data or risk another unlogged call.
            response = receipt("blocked", None, "Tool handler failed after audit start.")
        elapsed = min(7_200_000, max(0, int((time.monotonic() - started) * 1000)))
        try:
            self.store.finish_tool_run(
                tid, audit_id, response["status"], response.get("exit_code"),
                elapsed, response.get("output_ref"))
        except (TaskError, sqlite3.Error, OSError):
            # Execution may have happened; do not falsely claim it was blocked.
            return receipt("error", response.get("exit_code"),
                           "Tool audit finalization failed; execution status requires local review.",
                           response.get("output_ref"))
        return response

    def _call(self, name: str, arguments: dict,
              stop: threading.Event | None = None) -> dict:
        try:
            tool = self.manifest.get(name)
            args = tool.validate(arguments)
            task = self.store.require(canonical_id(args["task_id"]))
        except (ManifestError, TaskError, KeyError, TypeError):
            return receipt("denied", None, "Invalid manifest tool, task or tool parameters.")
        tid = task["id"]
        # Read-only checkpoint is explicitly permitted after a task ends.
        is_handoff = tool.adapter in {"continuity_handoff", "capability_readiness", "sapper_frontier"}
        if not is_handoff and (task["status"] != "running" or self.store.is_stopped(tid)):
            return receipt("denied", None, "Task is not running or has been stopped.")
        if is_handoff and task["status"] not in {
                "created", "running", "completed", "stopped", "exhausted",
                "failed", "refused", "awaiting_approval"}:
            return receipt("denied", None, "Task unavailable for checkpoint.")
        if tool.mode not in {"both", task["mode"]}:
            self.store.append(tid, "tool", tool.name, "denied", "Tool unavailable in this task mode.")
            return receipt("denied", None, "Tool unavailable in this task mode.")
        if tool.risk in {"R3", "R4"}:
            aid = self.store.request_approval(tid, tool.name, tool.risk)
            if tool.risk == "R4":
                self.store.append(tid, "tool", tool.name, "denied", "R4 is prohibited; no adapter will execute.")
                return receipt("blocked", None, "R4 prohibited; review entry " + aid + " has no execution path.")
            return receipt("approval_required", None, "R3 pending explicit approval " + aid + ".")
        cancelled = stop or threading.Event()
        if cancelled.is_set():
            return receipt("cancelled", None, "Operator stopped the task.")
        try:
            if tool.adapter == "capability_readiness":
                from app.loop.readiness import inspect_capabilities, short_capabilities
                report = inspect_capabilities(self.store, self.manifest, tid)
                result = receipt("completed", 0, short_capabilities(report))
                self.store.append(tid, "tool", name, "done", result["summary"])
                return result
            if tool.adapter == "sapper_frontier":
                from app.sapper_integration import resolve_frontier, public_graph
                frontier = resolve_frontier(tid, self.root)
                if frontier["integrity"] == "uninitialized":
                    summary = "Sapper-v2 task graph not initialized; zero dispatched intents."
                else:
                    graph = public_graph(tid, self.root)
                    summary = (
                        "Sapper-v2 graph integrity " + frontier["integrity"]
                        + "; eligible intent IDs: "
                        + (", ".join(frontier["ready_ids"][:12]) or "none")
                        + "; sampled fact nodes " + str(graph["total_facts"])
                        + "; sampled intent edges " + str(graph["total_intents"])
                        + ". Read-only: no worker dispatched, no target contacted."
                    )
                result = receipt("completed", 0, summary)
                self.store.append(tid, "tool", name, "done", result["summary"])
                return result
            if tool.adapter == "lead_proposal":
                from app.loop.leads import LeadRegistry
                lead = LeadRegistry(self.store).create(
                    tid, args["category"], args["title"])
                # A proposal is metadata only, NOT a vulnerability or evidence.
                safe_summary = ("Unverified hypothesis " + lead["id"] +
                                " registered (" + lead["category"] + ").")
                result = receipt("completed", 0, safe_summary)
                self.store.append(tid, "tool", name, "done", result["summary"])
                return result
            if is_handoff:
                from app.loop.continuity import build_handoff, short_handoff
                snapshot = build_handoff(self.store, tid)
                raw = (json.dumps(snapshot, sort_keys=True, separators=(",", ":")) + "\n").encode()
                if len(raw) > 65536:
                    raise RuntimeError("HANDOFF_TOO_LARGE")
                eid, rid = uuid.UUID(tid), uuid.uuid4()
                writer = self.vault.begin(eid, rid)
                try:
                    writer.append("stdout", raw)
                    writer.finish()
                except BaseException:
                    writer.abort()
                    raise
                reference = "evidence://" + tid + "/" + str(rid)
                result = receipt("completed", 0, short_handoff(snapshot), reference)
                self.store.append(tid, "tool", name, "done", result["summary"], reference)
                return result
            if tool.adapter == "local_artifact":
                from app.mcp.local_artifacts import inspect
                raw, safe_summary = inspect(self.root, tid, name, args["artifact"])
                if not isinstance(raw, bytes) or not 0 < len(raw) <= 6291456:
                    raise RuntimeError("ARTIFACT_OUTPUT_LIMIT")
                eid, rid = uuid.UUID(tid), uuid.uuid4()
                writer = self.vault.begin(eid, rid)
                try:
                    for offset in range(0, len(raw), 65536):
                        writer.append("stdout", raw[offset:offset + 65536])
                    writer.finish()
                except BaseException:
                    writer.abort()
                    raise
                reference = "evidence://" + tid + "/" + str(rid)
                result = receipt("completed", 0, safe_summary, reference)
                self.store.append(tid, "tool", name, "done",
                                  result["summary"], reference)
                return result
            if tool.adapter in {"gateway_nmap", "gateway_curl"}:
                return self._live(task, tool, args, cancelled)
            if tool.adapter == "loopback_head":
                if task["mode"] != "local" or cancelled.is_set():
                    return receipt("denied", None, "Operator has not authorized local loopback.")
                status, summary, reference = run_head(
                    target=task["target"], scope=task["scope"], port=args["port"],
                    vault=self.vault, engagement_id=uuid.UUID(tid))
                result = receipt("completed", 0, summary, reference)
                self.store.append(tid, "tool", name, "done", result["summary"], reference)
                return result
            adapter = getattr(stubs, tool.adapter, None)
            if adapter is None or tool.adapter.startswith("_"):
                raise RuntimeError("ADAPTER_NOT_IMPLEMENTED")
            raw, safe_summary = adapter(task, args, self.store)
            if not isinstance(raw, bytes) or not 0 < len(raw) <= 65536:
                raise RuntimeError("STUB_EVIDENCE_SIZE_INVALID")
            # The AES-GCM writer fsyncs chunks and seals before a receipt exists.
            eid, rid = uuid.UUID(tid), uuid.uuid4()
            writer = self.vault.begin(eid, rid)
            try:
                writer.append("stdout", raw)
                writer.finish()
            except BaseException:
                writer.abort()
                raise
            reference = "evidence://" + tid + "/" + str(rid)
            result = receipt("simulated" if tool.mode == "demo" else "completed",
                             0, safe_summary, reference)
            self.store.append(tid, "tool", name, "done", result["summary"], reference)
            return result
        except BaseException:
            # Do not place an exception or raw subprocess stderr in the model output.
            self.store.append(tid, "tool", name, "error", "Tool adapter failed or was blocked.")
            return receipt("blocked", None, "Tool adapter failed or was blocked by policy.")

    def _live(self, task: dict, tool: ToolDefinition, args: dict,
              stop: threading.Event) -> dict:
        if task["mode"] != "live":
            return receipt("denied", None, "Live adapter requires an approved live engagement.")
        target, scope = task["target"], task["scope"]
        action = ("nmap.tcp_top20" if tool.adapter == "gateway_nmap"
                  else "curl.http_head")
        params = {} if action == "nmap.tcp_top20" else {"port": args["port"]}
        intent = StructuredToolIntent(uuid.UUID(task["id"]), uuid.uuid4(),
                                      "mcp_agent", action, target, params)
        # Fence checks, binary pinning, process-group stop and encrypted spool
        # are ALL inside this existing gateway; never create subprocess here.
        try:
            result = self.gateway.execute(intent, target, scope, stop)
            if result.exit_code != 0:
                raise RuntimeError("TOOL_NONZERO_EXIT")
            if action == "nmap.tcp_top20":
                ports = self.gateway.parse_nmap_receipt(result)
                summary = "Reviewed Nmap: " + str(len(ports)) + " open TCP service ports."
            else:
                status = self.gateway.parse_http_receipt(result)
                summary = "Reviewed HTTP HEAD status " + status + "."
            reference = "evidence://" + task["id"] + "/" + str(result.run_id)
            self.store.append(task["id"], "tool", tool.name, "done", summary, reference)
            return receipt("completed", 0, summary, reference)
        except BaseException:
            self.store.append(task["id"], "tool", tool.name, "error",
                              "Live command denied or failed inside the scoped gateway.")
            return receipt("blocked", None, "Live command denied or failed inside the scoped gateway.")
