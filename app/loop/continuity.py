"""Deterministic, privacy-minimized process checkpoint for SECRA tasks.

A checkpoint records observed tool receipts and negative attempts, NOT
vulnerability findings. It never contains target IPs, credentials, raw
responses, command arguments, or model-supplied free text.
"""
from __future__ import annotations

import json
from collections import Counter
from hashlib import sha256

from .store import TaskStore

MAX_RUNS = 200
MAX_HANDOFF_RUNS = 25
NEGATIVE_STATUSES = frozenset({"blocked", "denied", "cancelled", "error"})
OBSERVED_STATUSES = frozenset({"completed", "simulated"})


def build_handoff(store: TaskStore, task_id: str) -> dict:
    """Reconstruct reproducible factual state from the *live* SQLite audit log.

    Existing tasks created before this feature have no tool_runs. That must be
    reported as unavailable rather than retroactively inventing timestamps.
    """
    task = store.require(task_id)
    runs = store.tool_runs(task_id, limit=MAX_RUNS)
    events = []
    cursor = 0
    for _ in range(10):
        batch = store.events(task_id, after=cursor, limit=200)
        if not batch:
            break
        events.extend(batch)
        cursor = batch[-1]["seq"]
        if len(batch) < 200:
            break

    successful = [r for r in runs if r["status"] in OBSERVED_STATUSES]
    failed = [r for r in runs if r["status"] in NEGATIVE_STATUSES]
    incomplete = [r for r in runs if r["finished_at"] is None]
    counts = Counter(r["tool"] for r in runs)
    duplicate = sum(count - 1 for count in counts.values() if count > 1)
    last_event = events[-1] if events else None
    recorded_refs = [r["output_ref"] for r in successful if r["output_ref"]]

    # Private target/scope are intentionally ignored; a boolean is sufficient.
    result = {
        "schema": "secra-continuity-v1",
        "asset": "ASSET_001",
        "task_id": task_id,
        "mode": task["mode"],
        "task_status": task["status"],
        "authorization_recorded": bool(task["authorized"]),
        "generated_at_utc": store.utc_now(),
        "source": "local-sqlite-live-events-and-tool-runs",
        "events_count_in_window": len(events),
        "events_window_truncated": len(events) >= 2000,
        "last_event": ({"seq": last_event["seq"], "kind": last_event["kind"],
                        "status": last_event["status"], "stamp": last_event["stamp"]}
                       if last_event else None),
        "metrics": {
            "tool_invocations_in_window": len(runs),
            "successful_receipts": len(successful),
            "blocked_or_denied_receipts": len(failed),
            "incomplete_audit_records": len(incomplete),
            "repeated_tool_invocations": duplicate,
            "redundant_call_ratio": round(duplicate / len(runs), 3) if runs else None,
            "ttfv_seconds": None,
            "verified_findings": None,
            "handoff_fidelity": None,
            "model_latency_seconds": None,
        },
        "observed_receipts": [
            {"tool": r["tool"], "status": r["status"],
             "at_utc": r["finished_at"], "duration_ms": r["duration_ms"],
             "output_ref": r["output_ref"]}
            for r in successful[-MAX_HANDOFF_RUNS:]
        ],
        "negative_or_denied": [
            {"tool": r["tool"], "status": r["status"],
             "at_utc": r["finished_at"]}
            for r in failed[-MAX_HANDOFF_RUNS:]
        ],
        "do_not_repeat_without_new_reason": sorted({r["tool"] for r in failed}),
        "evidence_refs_count": len(recorded_refs),
        "verified_facts": [],
        "unverified_hypotheses": [],
        "cleanup": {"verified": False, "operator_review_required": True},
        "handoff": {
            "proven_by_log": "Only reviewed tool invocations and their receipts, not findings.",
            "next_action": "Operator/analyst reviews the latest evidence references and selects the next approved action.",
            "missing": [
                "Independent verification of suspected findings",
                "Explicit hypothesis/negative-lead notes",
                "Cleanup proof and operator sign-off",
            ],
        },
    }
    # Stable digest of factual event content (omit variable generated_at_utc).
    stable = dict(result)
    stable.pop("generated_at_utc")
    result["snapshot_sha256"] = sha256(
        json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return result


def short_handoff(snapshot: dict) -> str:
    """Compact <500-character safe feedback for a remote model."""
    m = snapshot["metrics"]
    return (
        "SECRA checkpoint: " + snapshot["task_status"] + "; "
        + str(m["tool_invocations_in_window"]) + " audited calls, "
        + str(m["successful_receipts"]) + " successful receipts, "
        + str(m["blocked_or_denied_receipts"]) + " denied/blocked; "
        + str(m["incomplete_audit_records"]) + " unfinished records. "
        + "No findings verified by checkpoint. Snapshot sealed locally."
    )
