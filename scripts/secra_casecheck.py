#!/usr/bin/env python3
"""Offline cross-check of SECRA case files, SQLite audit and sealed evidence.

Runs from any directory. Never reads target/scope columns, sends network
requests, executes pentest tools, or exposes decrypted raw evidence.
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
from app.loop.case_integrity import check_case


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--data-dir", type=Path, default=Path(
        os.environ.get("SECRA_DATA_DIR", str(ROOT / "data"))))
    parser.add_argument("--strict", action="store_true",
                        help="Exit 2 when verification is incomplete")
    args = parser.parse_args()

    try:
        database = args.data_dir / "agent-events.sqlite3"
        if args.data_dir.is_symlink() or database.is_symlink() or not database.is_file():
            raise TaskError("EXISTING_TASK_DATABASE_REQUIRED")
        store = TaskStore(args.data_dir)
        report = check_case(store, args.task_id)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 2 if args.strict and report["status"] != "integrity_ok" else 0
    except (TaskError, OSError, ValueError) as exc:
        print("Case audit unavailable: " + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
