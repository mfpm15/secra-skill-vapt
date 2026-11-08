"""Bounded model -> reviewed tool -> sealed/masked result -> model feedback loop.

No LLM text becomes a shell command. The model selects a manifest tool with
schema-checked parameters; the independent dispatcher supplies task identity,
scope and the existing typed ToolGateway. The model never receives real IPs.
"""
from __future__ import annotations

import threading
import time
from collections import Counter
from dataclasses import dataclass, field

from app.agents.loader import load_profile, progressive_skills
from app.mcp.dispatcher import ToolDispatcher
from app.mcp.manifest import RISKS, ToolManifest
from .provider import Choice, ModelError, ModelRefused, NineRouterPlanner
from .text_fallback import TextFallbackExhausted
from .store import TaskStore, TaskError


@dataclass
class LoopResult:
    task_id: str
    status: str
    steps: int
    receipts: list[dict] = field(default_factory=list)


class FakeDemoModel:
    """Offline fixture. Not represented as a real inference or network scan."""
    def __init__(self):
        self.context_seen: list[dict] = []

    def choose(self, *, public_prompt: str, skills: str, tools: list,
               prior: tuple[str, str] | None, services: list[dict]) -> Choice | None:
        self.context_seen.append({
            "prior": prior, "tools": [tool.name for tool in tools],
            "skills": skills[:250], "services": list(services),
        })
        if prior is None:
            return Choice("demo.nmap_scan", {})
        if prior[0] == "demo.nmap_scan":
            return Choice("demo.httpx_probe", {"port": 80})
        return None


class AgentLoop:
    def __init__(self, store: TaskStore, dispatcher: ToolDispatcher,
                 *, max_steps: int = 25, max_seconds: int = 1200):
        if (type(max_steps) is not int or not 1 <= max_steps <= 25
                or type(max_seconds) is not int or not 1 <= max_seconds <= 1200):
            raise ValueError("LOOP_BOUNDS_INVALID")
        self.store = store
        self.dispatcher = dispatcher
        self.manifest = dispatcher.manifest
        self.max_steps = max_steps
        self.max_seconds = max_seconds

    def run(self, task_id: str, *, model=None, specialist: str = "recon",
            stop: threading.Event | None = None) -> LoopResult:
        task = self.store.require(task_id)
        if task["status"] == "created":
            self.store.start(task_id)
            task = self.store.require(task_id)
        if task["status"] != "running":
            raise TaskError("LOOP_TASK_NOT_RUNNING")
        profile = load_profile(specialist)
        llm = model or (
            FakeDemoModel() if task["mode"] == "demo" and not task["model"] else
            NineRouterPlanner(task["model"]))
        stopper = stop or threading.Event()
        started = time.monotonic()
        seen = Counter()
        step_count = 0
        receipts = []
        prior = None
        observations: list[dict] = []

        def finish(status: str, message: str) -> LoopResult:
            if self.store.is_stopped(task_id):
                return LoopResult(task_id, "stopped", step_count, receipts)
            self.store.set_status(task_id, status, message)
            return LoopResult(task_id, status, step_count, receipts)

        for index in range(self.max_steps):
            if stopper.is_set() or self.store.is_stopped(task_id):
                self.store.stop(task_id)
                return LoopResult(task_id, "stopped", step_count, receipts)
            if time.monotonic() - started >= self.max_seconds:
                return finish("exhausted", "Task exhausted: wall-clock limit reached.")
            names, skill_context = progressive_skills(profile,
                selected_tool=prior[0] if prior else None,
                step=index, services=observations)
            self.store.append(task_id, "skill", "", "done",
                              "Loaded reviewed skill: " + ",".join(names) + ".")
            candidates = [
                entry for entry in self.manifest.visible(task["mode"])
                if profile.allows(entry.name, entry.risk) and RISKS[entry.risk] <= 2
                and entry.adapter != "catalog_only"
            ]
            try:
                decision = llm.choose(
                    public_prompt=profile.system_prompt,
                    skills=skill_context, tools=candidates,
                    prior=prior, services=observations)
            except ModelRefused:
                return finish("refused", "Model declined the tool request; no action performed.")
            except TextFallbackExhausted:
                return finish("exhausted", "Text-only reviewed command formatting exhausted; no action executed.")
            except (ModelError, ValueError, TypeError):
                return finish("failed", "Model planner could not produce an approved tool decision.")
            if time.monotonic() - started >= self.max_seconds:
                return finish("exhausted", "Task exhausted before another tool could start.")
            if decision is None:
                return finish("completed", "Agent ended after reviewed tool observations.")
            if not isinstance(decision, Choice):
                return finish("failed", "Model decision schema rejected.")
            try:
                tool = self.manifest.get(decision.tool)
            except Exception:
                return finish("failed", "Model requested a tool outside the reviewed manifest.")
            if tool.risk in {"R3", "R4"}:
                request_id = self.store.request_approval(task_id, tool.name, tool.risk)
                if tool.risk == "R4":
                    return finish("failed", "R4 request blocked; recorded for review only.")
                return finish("awaiting_approval", "R3 request queued for operator approval.")
            if (not profile.allows(tool.name, tool.risk)
                    or tool.mode not in {"both", task["mode"]}):
                return finish("failed", "Model requested a tool outside specialist/mode policy.")
            if not isinstance(decision.arguments, dict) or "task_id" in decision.arguments:
                return finish("failed", "Model supplied forbidden task identity.")
            seen[tool.name] += 1
            if seen[tool.name] > 2:
                return finish("exhausted", "Repeated tool action exhausted its allowed budget.")
            supplied = {"task_id": task_id, **decision.arguments}
            try:
                tool.validate(supplied)
            except Exception:
                return finish("failed", "Model arguments did not match the reviewed manifest.")
            if getattr(llm, "text_fallback_used", False):
                self.store.append(task_id, "model", tool.name, "done",
                                  "Text-only fallback matched exact reviewed argv; scope/fence still enforced.")
                llm.text_fallback_used = False
            self.store.append(task_id, "model", tool.name, "requested",
                              "Model selected reviewed tool " + tool.name + ".")
            result = self.dispatcher.call(tool.name, supplied, stopper)
            step_count += 1
            receipts.append(result)
            if result["status"] not in {"simulated", "completed"}:
                return finish("failed", "Gateway rejected or failed the selected tool.")
            prior = (tool.name, result["summary"])
            # Explicitly allowlisted service observations, never parsed raw logs.
            if tool.name == "demo.nmap_scan":
                observations = [{"port": 80, "service": "http"},
                                {"port": 443, "service": "https"}]
            elif tool.name == "nmap.tcp_top20":
                observations = [
                    {"port": x["port"], "service": x["service"]}
                    for x in result.get("observations", [])
                    if isinstance(x, dict) and x.get("state") == "open"
                    and type(x.get("port")) is int
                    and isinstance(x.get("service"), str)
                ][:30]
            if self.store.is_stopped(task_id):
                return LoopResult(task_id, "stopped", step_count, receipts)
        return finish("exhausted", "Task exhausted: maximum " + str(self.max_steps) +
                      " reviewed tool steps reached; no further action dispatched.")
