#!/usr/bin/env python3
"""Operator-controlled SECRA engagement workspace CLI (works from any cwd).

The task must already exist and be authorized in the local TaskStore.
Only workspace metadata and evidence integrity are managed here.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.loop.store import TaskError, TaskStore
from app.workspace import EVENTS, STAGES, WorkspaceError, WorkspaceManager


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path(
        os.environ.get("SECRA_DATA_DIR", str(ROOT / "data"))))
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "status", "preflight", "manifest", "verify", "archive", "phase"):
        p = sub.add_parser(name)
        p.add_argument("--task-id", required=True)
        if name == "phase":
            p.add_argument("--stage", required=True, choices=STAGES)
            p.add_argument("--event", required=True, choices=sorted(EVENTS))
        if name == "archive":
            p.add_argument("--destination", required=True, type=Path)
            p.add_argument("--apply", action="store_true", help="Copy-verify; never delete source")
    args = parser.parse_args()

    try:
        db = args.data_dir / "agent-events.sqlite3"
        if not db.is_file() or db.is_symlink():
            raise TaskError("EXISTING_TASK_DATABASE_REQUIRED")
        store = TaskStore(args.data_dir)
        store.require(args.task_id)  # Opaque task ID is valid and operator authorized.
        workspace = WorkspaceManager(args.data_dir / "engagements")
        if args.command == "init":
            path = workspace.initialize(args.task_id)
            workspace.capture_preflight(args.task_id)
            result = {"status": "initialized", "workspace": str(path)}
        elif args.command == "status":
            directory = workspace.require(args.task_id)
            phases = workspace.phases(args.task_id)
            preflight = directory / "00-preflight/local-readiness.json"
            manifest = directory / "06-ledger/manifest.json"
            result = {
                "schema": 1, "task_id": args.task_id, "asset": "ASSET_001",
                "workspace": str(directory),
                "phase_events": len(phases), "latest_phase": phases[-1] if phases else None,
                "preflight_recorded": preflight.is_file(),
                "manifest_present": manifest.is_file(),
            }
        elif args.command == "preflight":
            result = workspace.capture_preflight(args.task_id)
        elif args.command == "phase":
            result = workspace.record_phase(args.task_id, args.stage, args.event)
        elif args.command == "manifest":
            result = workspace.write_manifest(args.task_id)
        elif args.command == "verify":
            result = workspace.verify_manifest(args.task_id)
        else:
            result = workspace.archive(
                args.task_id, args.destination, dry_run=not args.apply)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("status") != "drift" else 2
    except (OSError, TaskError, WorkspaceError, ValueError, KeyError,
            json.JSONDecodeError) as exc:
        print("SECRA workspace error:", exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
