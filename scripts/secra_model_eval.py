#!/usr/bin/env python3
"""Compare SECRA model tool-choice behavior on PUBLIC synthetic fixtures only.

Default uses FakeDemoModel (no API/network). Optional --models calls an
operator-configured 9Router service using the existing narrow privacy gateway.
It never scans targets and must not be interpreted as bug-bounty success.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.loop.agent import FakeDemoModel
from app.loop.provider import NineRouterPlanner, ModelError
from app.model_evaluation import evaluate_model, EvaluationError


def write_new(path: Path, data: str) -> None:
    if path.is_symlink() or path.exists() or not path.parent.is_dir() or path.parent.is_symlink():
        raise EvaluationError("EVALUATION_DESTINATION_UNSAFE")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(data)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--models", help="Comma-separated 9Router model IDs; omit for offline FakeDemoModel")
    p.add_argument("--repeat", type=int, default=1, choices=(1, 2, 3, 4, 5))
    p.add_argument("--output", type=Path, help="New private JSON output file")
    args = p.parse_args()
    try:
        names = [x.strip() for x in args.models.split(",")] if args.models else ["offline-fake-demo"]
        if len(names) > 8 or any(not x for x in names):
            raise EvaluationError("MODEL_EVALUATION_LIST_INVALID")
        results = []
        for name in names:
            model = FakeDemoModel() if name == "offline-fake-demo" and not args.models else NineRouterPlanner(name)
            results.append(evaluate_model(model, model_label=name, repeat=args.repeat))
        summary = {
            "schema": "secra-model-eval-report-v1",
            "benchmark": "synthetic-tool-selection-not-vapt-exploit-success",
            "model_provider_credential_logged": False,
            "results": results,
        }
        rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
        if args.output:
            write_new(args.output.expanduser(), rendered)
            print("Saved private synthetic model evaluation:", args.output)
        else:
            print(rendered, end="")
        return 0 if all(item["passed"] == item["cases"] for item in results) else 2
    except (EvaluationError, ModelError, OSError, ValueError) as exc:
        print("Model evaluation unavailable: " + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
