"""Read-only case integrity preflight across task DB, workspace and AES-GCM vault.

This does not archive the data and does not prove vulnerability findings.
It never returns raw evidence, scope, command arguments or customer details.
"""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from uuid import UUID

from app.evidence_vault import EvidenceVault, EvidenceError
from app.workspace import WorkspaceManager, WorkspaceError
from app.loop.store import TaskStore

REF = re.compile(r"^evidence://([a-f0-9-]{36})/([a-f0-9-]{36})$")
MAX_RUN_ROWS = 1000


def check_case(store: TaskStore, task_id: str) -> dict:
    task = store.require(task_id)
    workspace = WorkspaceManager(store.root / "engagements")
    try:
        checked = workspace.verify_manifest(task["id"])
        workspace_result = checked["status"]
        workspace_drift_count = sum(len(checked[name]) for name in ("added", "missing", "changed"))
    except (OSError, ValueError, WorkspaceError, KeyError, TypeError):
        workspace_result = "unverified_or_missing"
        workspace_drift_count = None

    with store._db() as db:
        run_rows = db.execute(
            "SELECT id,tool,status,finished_at,output_ref FROM tool_runs "
            "WHERE task_id=? ORDER BY id LIMIT ?", (task["id"], MAX_RUN_ROWS + 1)
        ).fetchall()
        lead_rows = db.execute(
            "SELECT primary_ref,review_ref FROM process_leads WHERE task_id=? "
            "ORDER BY id LIMIT ?", (task["id"], MAX_RUN_ROWS + 1)
        ).fetchall()

    truncated = len(run_rows) > MAX_RUN_ROWS or len(lead_rows) > MAX_RUN_ROWS
    runs = run_rows[:MAX_RUN_ROWS]
    leads = lead_rows[:MAX_RUN_ROWS]
    unfinished = sum(row["finished_at"] is None for row in runs)
    raw_refs = [row["output_ref"] for row in runs if row["output_ref"]]
    for row in leads:
        raw_refs.extend(x for x in (row["primary_ref"], row["review_ref"]) if x)
    references = sorted(set(raw_refs))

    verified = 0
    invalid_refs = 0
    missing_seals = 0
    # Initializing EvidenceVault would create directories. Stay read-only
    # for missing evidence roots; fail closed on any referenced content.
    root = store.root / "evidence"
    vault = (EvidenceVault(root) if references and root.is_dir() and not root.is_symlink()
             else None)
    for reference in references:
        match = REF.fullmatch(reference)
        if not match or match.group(1) != task["id"]:
            invalid_refs += 1
            continue
        if vault is None:
            missing_seals += 1
            continue
        try:
            # Read and authenticate in memory, do not return decrypted bytes.
            vault.verify_and_read(UUID(match.group(1)), UUID(match.group(2)))
        except (EvidenceError, OSError, ValueError):
            missing_seals += 1
        else:
            verified += 1

    statuses = Counter(row["status"] for row in runs)
    complete = (workspace_result == "verified" and not truncated
                and unfinished == 0 and invalid_refs == 0 and missing_seals == 0)
    return {
        "schema": "secra-case-integrity-v1",
        "task_id": task["id"],
        "asset": "ASSET_001",
        "mode": task["mode"],
        "status": "integrity_ok" if complete else "review_required",
        "workspace_manifest": workspace_result,
        "workspace_drift_count": workspace_drift_count,
        "tool_audit_rows_checked": len(runs),
        "tool_audit_truncated": truncated,
        "tool_audit_unfinished": unfinished,
        "tool_status_counts": dict(sorted(statuses.items())),
        "evidence_references_checked": len(references),
        "evidence_seals_verified": verified,
        "evidence_references_invalid": invalid_refs,
        "evidence_seals_missing_or_corrupt": missing_seals,
        "archive_includes_task_db": False,
        "archive_includes_encrypted_vault": False,
        "finding_validity_proven": False,
        "note": ("Integrity check of local metadata and referenced AES-GCM artifacts "
                 "only. Workspace-only archive does NOT include DB, keys or vault."),
    }
