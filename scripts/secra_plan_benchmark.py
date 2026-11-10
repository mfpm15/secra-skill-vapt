#!/usr/bin/env python3
"""Offline reproducible planning-overhead benchmark; never scans or calls a model.

These measurements are diagnostic, not proof of Kali or 9Router performance.
Compare results on the SAME machine/CPU/load/Python/manifest before and after.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.loop.store import TaskStore
from app.mcp.manifest import ToolManifest
from app.planning.preview import goal_steps, preview_plan, short_preview


def measure(iterations: int = 250, warmup: int = 20, goal: str = "demo_web_baseline") -> dict:
    if not isinstance(iterations, int) or not 10 <= iterations <= 10000:
        raise ValueError("BENCHMARK_ITERATIONS_INVALID")
    if not isinstance(warmup, int) or not 0 <= warmup <= 1000:
        raise ValueError("BENCHMARK_WARMUP_INVALID")
    steps = goal_steps(goal)
    manifest = ToolManifest()
    with tempfile.TemporaryDirectory(prefix="secra-plan-bench-") as folder:
        store = TaskStore(Path(folder))
        tid = store.create("127.0.0.1", "127.0.0.1/32",
                           mode="demo", authorized=True)
        store.start(tid)
        latency_ns = []
        for index in range(warmup + iterations):
            begin = time.perf_counter_ns()
            result = preview_plan(store, manifest, tid, steps)
            summary = short_preview(result)
            elapsed = time.perf_counter_ns() - begin
            if result["tool_calls_performed"] != 0 or len(summary) > 490:
                raise RuntimeError("BENCHMARK_EXECUTION_OR_CONTRACT_VIOLATION")
            if index >= warmup:
                latency_ns.append(elapsed)
    latency_ms = sorted(x / 1_000_000 for x in latency_ns)
    return {
        "schema": "secra-plan-benchmark-v1",
        "goal": goal,
        "iterations": iterations,
        "warmup": warmup,
        "tool_count": len(manifest.tools),
        "plan_steps": len(steps),
        "p50_ms": round(statistics.median(latency_ms), 3),
        "p95_ms": round(latency_ms[max(0, (95 * len(latency_ms) + 99) // 100 - 1)], 3),
        "max_ms": round(latency_ms[-1], 3),
        "model_calls": 0,
        "network_scans": 0,
        "note": "Only CPU/SQLite policy-preview overhead, no LLM or Kali benchmark.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=250)
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--goal", default="demo_web_baseline",
                        choices=("engagement_overview", "demo_web_baseline",
                                 "artifact_triage", "sapper_graph_review",
                                 "live_recon_review"))
    args = parser.parse_args()
    try:
        print(json.dumps(measure(args.iterations, args.warmup, args.goal),
                         indent=2, sort_keys=True))
        return 0
    except (ValueError, RuntimeError, OSError) as exc:
        print("SECRA_BENCHMARK_ERROR: " + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
