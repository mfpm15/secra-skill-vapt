#!/usr/bin/env python3
"""Import locally captured, in-program HTTP HAR into encrypted SECRA evidence.

No network or scanner execution. Hostnames must be explicitly listed by
the operator from the current program brief; no wildcard acceptance.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.har_import import HARError, MAX_FILE_SIZE, import_har
from app.loop.store import TaskStore, TaskError


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--task-id", required=True)
    p.add_argument("--har", required=True, type=Path)
    p.add_argument("--approved-host", action="append", required=True,
                   help="Exact approved host from program brief; repeat as needed")
    p.add_argument("--confirm-program-scope", action="store_true",
                   help="Affirm supplied hosts are explicitly authorized by current rules")
    p.add_argument("--data-dir", type=Path, default=Path(os.environ.get(
        "SECRA_DATA_DIR", str(ROOT / "data"))))
    args = p.parse_args()
    try:
        path = args.har.expanduser()
        if (path.is_symlink() or not path.is_file()
                or path.stat().st_size > MAX_FILE_SIZE
                or stat.S_IMODE(path.stat().st_mode) & 0o077):
            raise HARError("HAR_PRIVATE_INPUT_REQUIRED")
        db = args.data_dir / "agent-events.sqlite3"
        if db.is_symlink() or not db.is_file():
            raise HARError("HAR_EXISTING_TASK_DATABASE_REQUIRED")
        result = import_har(
            TaskStore(args.data_dir), args.task_id, path.read_bytes(),
            approved_hosts=tuple(args.approved_host),
            operator_scope_confirmed=args.confirm_program_scope,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (TaskError, HARError, ValueError, OSError) as exc:
        print("SECRA HAR importer error: " + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
