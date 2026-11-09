#!/usr/bin/env python3
"""Export a privacy-minimized SECRA handoff from local audited task metadata.

Read-only for SECRA records, no network or target execution. The exported file
contains no target IP, CIDR, argv, raw evidence, credentials or model prompts.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.loop.continuity import build_handoff
from app.loop.store import TaskStore, TaskError


def markdown(doc: dict) -> str:
    m = doc["metrics"]
    lines = [
        "# SECRA HANDOFF — privacy-safe checkpoint",
        "",
        "Task ID: " + doc["task_id"],
        "Asset: " + doc["asset"],
        "Status: " + doc["task_status"],
        "Mode: " + doc["mode"],
        "Snapshot time (UTC): " + doc["generated_at_utc"],
        "Snapshot SHA-256: " + doc["snapshot_sha256"],
        "",
        "## Measured operational facts",
        "",
        "- Audited calls in window: " + str(m["tool_invocations_in_window"]),
        "- Successful tool receipts: " + str(m["successful_receipts"]),
        "- Denied/blocked tool receipts: " + str(m["blocked_or_denied_receipts"]),
        "- Incomplete audit rows: " + str(m["incomplete_audit_records"]),
        "- Repeated tool invocations: " + str(m["repeated_tool_invocations"]),
        "- Verified vulnerability findings: not measured",
        "- TTFV, handoff fidelity, model latency: not measured",
        "",
        "## Last reviewed tool observations (not verified findings)",
        "",
    ]
    for row in doc["observed_receipts"]:
        lines.append("- " + row["tool"] + " / " + row["status"] + " / "
                     + (row["output_ref"] or "no evidence reference"))
    if not doc["observed_receipts"]:
        lines.append("- None recorded")
    lines.extend(["", "## Do not repeat without new rationale", ""])
    lines.extend("- " + tool for tool in doc["do_not_repeat_without_new_reason"])
    if not doc["do_not_repeat_without_new_reason"]:
        lines.append("- None recorded")
    lines.extend([
        "", "## Next permitted decision", "",
        doc["handoff"]["next_action"], "",
        "## Open review gates", "",
        "- Suspected findings require independent verification.",
        "- Cleanup state needs operator review and evidence.",
        "- Negative hypotheses must be explicitly documented; denied tools alone are not negative tests.",
        "- Before resuming live tests, re-check the locally held scope and authorization.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--task-id", required=True, help="Existing SECRA task UUID")
    p.add_argument("--data-dir", type=Path, default=Path(os.environ.get(
        "SECRA_DATA_DIR", str(ROOT / "data"))))
    p.add_argument("--format", choices=("json", "markdown"), default="markdown")
    p.add_argument("--output", type=Path,
                   help="Optional new file (exclusive create 0600); else print to stdout")
    args = p.parse_args()
    try:
        if not (args.data_dir / "agent-events.sqlite3").is_file():
            raise TaskError("TASK_AUDIT_DATABASE_MISSING")
        store = TaskStore(args.data_dir)
        doc = build_handoff(store, args.task_id)
        content = (json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
                   if args.format == "json" else markdown(doc))
        if args.output is None:
            print(content, end="")
        else:
            output = args.output.expanduser()
            if output.is_symlink() or not output.parent.is_dir():
                raise ValueError("Unsafe destination or missing parent directory")
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(output, flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(content)
            print("Created private handoff:", output)
        return 0
    except (OSError, TaskError, ValueError) as exc:
        print("Handoff unavailable:", exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
