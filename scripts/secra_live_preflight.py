#!/usr/bin/env python3
"""Non-invasive SECRA Kali live prerequisites diagnostic; NO network traffic."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.live_preflight import check_live_prerequisites
from app.loop.store import TaskStore, TaskError


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--data-dir", type=Path, default=Path(
        os.environ.get("SECRA_DATA_DIR", str(ROOT / "data"))
    ))
    args = parser.parse_args()
    try:
        db = args.data_dir / "agent-events.sqlite3"
        if args.data_dir.is_symlink() or db.is_symlink() or not db.is_file():
            raise TaskError("EXISTING_TASK_DATABASE_REQUIRED")
        result = check_live_prerequisites(TaskStore(args.data_dir), args.task_id)
        print(json.dumps(result, indent=2, sort_keys=True))
        # Always indicate unverified until a separate Kali privileged test.
        return 2
    except (TaskError, OSError, ValueError) as exc:
        print("Live readiness check unavailable: " + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
