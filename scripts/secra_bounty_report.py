#!/usr/bin/env python3
"""Build a PRIVATE bug-bounty report draft from operator-supplied local JSON.

Does not submit reports or send content to an LLM. Use only with written
authorization and the selected program's current rules.
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

from app.bugbounty_report import ReportError, evaluate, render_draft, write_private
from app.loop.store import TaskStore, TaskError


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--task-id", required=True)
    p.add_argument("--lead-id", required=True)
    p.add_argument("--input", type=Path, required=True,
                   help="Owner-only local JSON describing human-validated finding")
    p.add_argument("--output", type=Path, required=True,
                   help="New mode-0600 Markdown report; never overwritten")
    p.add_argument("--data-dir", type=Path, default=Path(os.environ.get(
        "SECRA_DATA_DIR", str(ROOT / "data"))))
    args = p.parse_args()
    try:
        source = args.input.expanduser()
        if (source.is_symlink() or not source.is_file()
                or stat.S_IMODE(source.stat().st_mode) != 0o600
                or source.stat().st_size > 40000):
            raise ReportError("REPORT_INPUT_MUST_BE_PRIVATE_0600_JSON")
        draft = json.loads(source.read_text(encoding="utf-8"))
        db = args.data_dir / "agent-events.sqlite3"
        if db.is_symlink() or not db.is_file():
            raise ReportError("REPORT_TASK_DATABASE_MISSING")
        store = TaskStore(args.data_dir)
        status = evaluate(store, args.task_id, args.lead_id, draft)
        write_private(args.output.expanduser(), render_draft(draft, status))
        print(json.dumps({
            "status": "draft_created_for_operator_review",
            "ready_for_final_human_review": status["ready_for_final_human_review"],
            "issues": status["issues"],
            "output": str(args.output),
            "platform_submission_performed": False,
        }, sort_keys=True))
        return 0 if status["ready_for_final_human_review"] else 2
    except (OSError, ValueError, TaskError, ReportError, json.JSONDecodeError) as exc:
        print("SECRA report error: " + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
