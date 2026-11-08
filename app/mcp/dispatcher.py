"""Manifest dispatcher. Raw results seal locally; model sees a short receipt.

The only live adapters call the existing typed Phase-2 ToolGateway, which still
denies networking until the separately attested kernel fence is operational.
"""
from __future__ import annotations

import re
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
        try:
            tool = self.manifest.get(name)
            args = tool.validate(arguments)
            task = self.store.require(canonical_id(args["task_id"]))
        except (ManifestError, TaskError, KeyError, TypeError):
            return receipt("denied", None, "Invalid manifest tool, task or tool parameters.")
        tid = task["id"]
        if task["status"] != "running" or self.store.is_stopped(tid):
            return receipt("denied", None, "Task is not running or has been stopped.")
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
            if tool.adapter in {"gateway_nmap", "gateway_curl"}:
                return self._live(task, tool, args, cancelled)
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
