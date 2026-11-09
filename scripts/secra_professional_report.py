#!/usr/bin/env python3
"""Produce operator-private executive + chronological VAPT report from real audit.

No LLM, target traffic, auto-confirmation, or platform submission. Local
operator-supplied reviewed finding details must be owner-only JSON.
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

from app.bugbounty_report import write_private, ReportError
from app.loop.store import TaskStore, TaskError
from app.professional_report import build_report, NarrativeError


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--task-id", required=True)
    p.add_argument("--input", type=Path, required=True,
                   help="Private owner-only JSON: operator review and finding details")
    p.add_argument("--output", type=Path, required=True,
                   help="New private Markdown; cannot overwrite an existing report")
    p.add_argument("--data-dir", type=Path,
                   default=Path(os.environ.get("SECRA_DATA_DIR", str(ROOT / "data"))))
    p.add_argument("--strict", action="store_true",
                   help="Nonzero if report remains unreviewed or incomplete")
    args = p.parse_args()
    try:
        path = args.input.expanduser()
        db = args.data_dir / "agent-events.sqlite3"
        if (path.is_symlink() or not path.is_file()
                or stat.S_IMODE(path.stat().st_mode) != 0o600
                or path.stat().st_size > 250000):
            raise NarrativeError("REPORT_INPUT_MUST_BE_0600_AND_BOUNDED")
        if db.is_symlink() or not db.is_file() or args.data_dir.is_symlink():
            raise NarrativeError("EXISTING_TASK_DATABASE_REQUIRED")
        report = build_report(
            TaskStore(args.data_dir), args.task_id,
            json.loads(path.read_text(encoding="utf-8")),
        )
        write_private(args.output.expanduser(), report["markdown"])
        print(json.dumps({
            "status": report["quality"],
            "confirmed_findings": report["confirmed_findings"],
            "excluded_candidates": report["excluded_candidates"],
            "chronology_entries": report["chronology_entries"],
            "chronology_truncated": report["chronology_truncated"],
            "case_integrity": report["case_integrity"],
            "saved_to": str(args.output),
            "auto_submitted": False,
        }, indent=2, sort_keys=True))
        return 2 if args.strict and report["quality"] != "reviewed" else 0
    except (OSError, TaskError, NarrativeError, ReportError,
            ValueError, TypeError, json.JSONDecodeError) as exc:
        print("Professional report blocked: " + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
