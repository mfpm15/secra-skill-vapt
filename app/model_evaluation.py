"""Target-free, reproducible SECRA model tool-selection microbenchmark.

Measures only bounded decision quality and latency against synthetic fixtures,
NOT real vulnerability discovery, payout probability or exploit effectiveness.
No network probes; optional 9Router inference is called with public fake data.
"""
from __future__ import annotations

import statistics
import time
from dataclasses import dataclass

from app.loop.provider import Choice, ModelError
from app.mcp.manifest import ToolManifest

TOOLS = ("demo.nmap_scan", "demo.httpx_probe", "report.summary")
PUBLIC_PROMPT = (
    "You are a synthetic authorized lab planner. Choose a sensible next "
    "reviewed tool, or finish if the workflow already has enough observations."
)
PUBLIC_SKILL = "Review synthetic HTTP service metadata only; never assert a real finding."


@dataclass(frozen=True)
class Scenario:
    name: str
    prior: tuple[str, str] | None
    services: tuple[tuple[int, str], ...]
    expected: str | None
    expected_args: dict


SCENARIOS = (
    Scenario("fresh_discovery", None, (), "demo.nmap_scan", {}),
    Scenario("http_followup",
             ("demo.nmap_scan", "SIMULATED Nmap: HTTP services observed on ports 80 and 443."),
             ((80, "http"), (443, "https")), "demo.httpx_probe", {"port": 80}),
    Scenario("stop_after_http_result",
             ("demo.httpx_probe", "SIMULATED HTTPX: status 200 observed on reviewed service port 80."),
             ((80, "http"), (443, "https")), None, {}),
)


class EvaluationError(ValueError):
    pass


def grade(choice: Choice | None, case: Scenario) -> bool:
    if choice is None:
        return case.expected is None
    return (isinstance(choice, Choice) and choice.tool == case.expected
            and choice.arguments == case.expected_args)


def evaluate_model(model, *, model_label: str, repeat: int = 1,
                   manifest: ToolManifest | None = None) -> dict:
    if type(repeat) is not int or not 1 <= repeat <= 5:
        raise EvaluationError("MODEL_EVAL_REPEAT_INVALID")
    if not isinstance(model_label, str) or not 1 <= len(model_label) <= 110:
        raise EvaluationError("MODEL_EVAL_LABEL_INVALID")
    source = manifest or ToolManifest()
    tools = [source.get(name) for name in TOOLS]
    observations = []
    for case in SCENARIOS:
        for iteration in range(repeat):
            started = time.monotonic()
            error = None
            try:
                response = model.choose(
                    public_prompt=PUBLIC_PROMPT, skills=PUBLIC_SKILL,
                    tools=tools, prior=case.prior,
                    services=[{"port": port, "service": name}
                              for port, name in case.services],
                )
                # Incorrect tool/argument selection is measured as failure.
                success = grade(response, case)
                returned = response.tool if isinstance(response, Choice) else None
            except (ModelError, ValueError, TypeError):
                success, returned, error = False, None, "model_decision_or_transport_error"
            elapsed = round((time.monotonic() - started) * 1000, 2)
            observations.append({
                "scenario": case.name, "iteration": iteration,
                "passed": success, "selected_tool": returned,
                "latency_ms": elapsed, "error": error,
            })
    latencies = [x["latency_ms"] for x in observations]
    scores = sum(x["passed"] for x in observations)
    return {
        "schema": "secra-tool-selection-eval-v1",
        "model": model_label,
        "simulation_only": True,
        "external_target_calls": 0,
        "vulnerabilities_verified": 0,
        "cases": len(observations),
        "passed": scores,
        "pass_rate": round(scores / len(observations), 4),
        "median_latency_ms": round(statistics.median(latencies), 2),
        "token_usage": "not_measured",
        "real_vapt_performance": "not_measured",
        "results": observations,
    }
