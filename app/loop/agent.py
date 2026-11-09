"""Bounded model -> reviewed tool -> sealed/masked result -> model feedback loop.

No LLM text becomes a shell command. The model selects a manifest tool with
schema-checked parameters; the independent dispatcher supplies task identity,
scope and the existing typed ToolGateway. The model never receives real IPs.
"""
from __future__ import annotations

import threading
import re
import time
from collections import Counter
from dataclasses import dataclass, field

from app.agents.loader import load_profile, progressive_skills
from app.mcp.dispatcher import ToolDispatcher
from app.mcp.manifest import RISKS, ToolManifest
from .provider import Choice, ModelError, ModelRefused, NineRouterPlanner
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
        # Recover bounded task progress from the committed audit log after a
        # process/model switch. No raw outputs, targets or prompts are restored.
        historical = self.store.tool_runs(task_id, limit=200)
        process_tools = {"workflow.handoff", "workflow.capabilities",
                         "workflow.lead_propose"}
        prior_runs = [r for r in historical if r["tool"] not in process_tools]
        unresolved = [r for r in prior_runs if r["finished_at"] is None]
        seen = Counter(r["tool"] for r in prior_runs)
        historical_steps = len(prior_runs)
        step_count = 0  # Per invocation, not retroactively attributed to this model.
        receipts = []
        prior = None
        observations: list[dict] = []
        if prior_runs and prior_runs[-1]["status"] in {"completed", "simulated"}:
            last_tool = prior_runs[-1]["tool"]
            # Event summaries are already masked by TaskStore.append. Accept
            # only the provider's strict public-summary alphabet.
            with self.store._db() as db:
                event = db.execute(
                    "SELECT summary FROM events WHERE task_id=? AND kind='tool' "
                    "AND tool=? AND status='done' ORDER BY seq DESC LIMIT 1",
                    (task_id, last_tool)).fetchone()
            if event:
                clean = event["summary"][:240]
                if clean and re.fullmatch(r"[A-Za-z0-9 .,;:_-]+", clean):
                    prior = (last_tool, clean)
            if any(r["tool"] == "demo.nmap_scan" and r["status"] == "simulated"
                   for r in prior_runs):
                # Fixed synthetic test fixture, not inferred live services.
                observations = [{"port": 80, "service": "http"},
                                {"port": 443, "service": "https"}]

        def finish(status: str, message: str) -> LoopResult:
            if self.store.is_stopped(task_id):
                return LoopResult(task_id, "stopped", step_count, receipts)
            self.store.set_status(task_id, status, message)
            return LoopResult(task_id, status, step_count, receipts)

        if unresolved or len(historical) >= 200:
            return finish("failed", "Unfinished or truncated historical tool audit; operator review required.")
        if historical_steps >= self.max_steps:
            return finish("exhausted", "Total audited tool budget already exhausted across sessions.")

        for index in range(self.max_steps - historical_steps):
            if stopper.is_set() or self.store.is_stopped(task_id):
                self.store.stop(task_id)
                return LoopResult(task_id, "stopped", step_count, receipts)
            if time.monotonic() - started >= self.max_seconds:
                return finish("exhausted", "Task exhausted: wall-clock limit reached.")
            names, skill_context = progressive_skills(profile,
                selected_tool=prior[0] if prior else None, step=index)
            self.store.append(task_id, "skill", "", "done",
                              "Loaded reviewed skill: " + ",".join(names) + ".")
            candidates = [
                entry for entry in self.manifest.visible(task["mode"])
                if profile.allows(entry.name, entry.risk) and RISKS[entry.risk] <= 2
            ]
            try:
                decision = llm.choose(
                    public_prompt=profile.system_prompt,
                    skills=skill_context, tools=candidates,
                    prior=prior, services=observations)
            except ModelRefused:
                return finish("refused", "Model declined the tool request; no action performed.")
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
            if self.store.is_stopped(task_id):
                return LoopResult(task_id, "stopped", step_count, receipts)
        return finish("exhausted", "Task exhausted: maximum " + str(self.max_steps) +
                      " reviewed tool steps reached; no further action dispatched.")
