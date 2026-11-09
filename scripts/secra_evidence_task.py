#!/usr/bin/env python3
"""Create a genuinely offline SECRA case for domain-only bug bounty programs.

No fake IP, CIDR or DNS scope. This task may receive operator-imported
evidence and human-reviewed hypotheses but can NEVER issue live/demonstration
network tool commands via the SECRA MCP manifest.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.loop.store import TaskStore, TaskError


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm-authorization", action="store_true",
                        help="Operator has checked current program rules and scope")
    parser.add_argument("--finish-task-id",
                        help="Close an existing evidence-only case with explicit confirmation")
    parser.add_argument("--confirm-completion", action="store_true",
                        help="Confirm offline case is ready to freeze and archive")
    parser.add_argument("--data-dir", type=Path, default=Path(os.environ.get(
        "SECRA_DATA_DIR", str(ROOT / "data"))))
    args = parser.parse_args()
    try:
        if args.finish_task_id:
            if not args.confirm_completion:
                raise TaskError("OPERATOR_COMPLETION_CONFIRMATION_REQUIRED")
            db = args.data_dir / "agent-events.sqlite3"
            if db.is_symlink() or not db.is_file():
                raise TaskError("EXISTING_TASK_DATABASE_REQUIRED")
            store = TaskStore(args.data_dir)
            task = store.require(args.finish_task_id)
            if task["mode"] != "evidence" or task["status"] != "running":
                raise TaskError("NOT_AN_ACTIVE_EVIDENCE_TASK")
            store.set_status(args.finish_task_id, "completed",
                             "Operator completed offline evidence intake; no network.")
            print(json.dumps({
                "task_id": args.finish_task_id, "mode": "evidence",
                "status": "completed", "network_execution_authorized": False,
            }, sort_keys=True))
        else:
            if not args.confirm_authorization:
                raise TaskError("OPERATOR_PROGRAM_AUTHORIZATION_REQUIRED")
            store = TaskStore(args.data_dir)
            tid = store.create("", "", mode="evidence", authorized=True)
            store.start(tid)  # Workflow metadata only; agent loop is disabled.
            print(json.dumps({
                "task_id": tid, "mode": "evidence", "status": "running",
                "network_scope_configured": False,
                "network_execution_authorized": False,
                "operator_must_supply_approved_hosts_during_import": True,
            }, sort_keys=True))
        return 0
    except (TaskError, OSError, ValueError) as exc:
        print("Evidence task unavailable: " + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
