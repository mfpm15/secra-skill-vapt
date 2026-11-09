"""Offline, operator-only bug-bounty report quality gate.

No LLM, network calls or submission. Never infer a vulnerability from the
mere existence of an observation receipt.
"""
from __future__ import annotations

import os
from pathlib import Path

from app.loop.leads import LeadRegistry
from app.loop.case_integrity import check_case
from app.loop.store import TaskStore

SEVERITIES = frozenset({"informational", "low", "medium", "high", "critical"})
FIELDS = frozenset({
    "program", "program_url", "policy_checked_at_utc", "asset",
    "asset_scope_confirmed", "automation_allowed", "rules_acknowledged",
    "title", "weakness", "severity", "prerequisites", "steps",
    "observed_result", "security_impact", "root_cause", "remediation",
    "operator_reviewed", "program_disclosure_allowed"
})


class ReportError(ValueError):
    pass


def evaluate(store: TaskStore, task_id: str, lead_id: str, draft: dict) -> dict:
    """Determine missing operator evidence and policy prerequisites."""
    task = store.require(task_id)
    lead = LeadRegistry(store).get(task_id, lead_id)
    if not isinstance(draft, dict) or set(draft) - FIELDS:
        raise ReportError("REPORT_UNKNOWN_FIELDS")

    gaps = []
    if task["mode"] == "demo":
        gaps.append("demo_mode_cannot_be_submitted")
    if lead["status"] != "verified" or not lead["primary_ref"] or not lead["review_ref"]:
        gaps.append("operator_signoff_and_two_sealed_receipts_required")
    integrity = check_case(store, task_id)
    if integrity["status"] != "integrity_ok":
        gaps.append("case_integrity_review_required")
    for key, minimum in (
        ("program", 3), ("program_url", 8), ("policy_checked_at_utc", 10),
        ("asset", 4), ("title", 8), ("weakness", 8), ("prerequisites", 8),
        ("observed_result", 30), ("security_impact", 40),
        ("root_cause", 20), ("remediation", 20)
    ):
        value = draft.get(key)
        if not isinstance(value, str) or not minimum <= len(value.strip()) <= 2400:
            gaps.append("missing_or_short_" + key)
    if draft.get("severity") not in SEVERITIES:
        gaps.append("severity_not_selected")
    for key in ("asset_scope_confirmed", "rules_acknowledged",
                "operator_reviewed", "program_disclosure_allowed"):
        if draft.get(key) is not True:
            gaps.append(key + "_not_confirmed")
    if type(draft.get("automation_allowed")) is not bool:
        gaps.append("automation_rule_not_documented")
    steps = draft.get("steps")
    if (not isinstance(steps, list) or not 2 <= len(steps) <= 15
            or any(not isinstance(s, str) or not 12 <= len(s.strip()) <= 1000
                   for s in steps)):
        gaps.append("reproduction_steps_incomplete")

    return {
        "schema": "secra-bounty-report-gate-v1",
        "task_id": task_id,
        "lead_id": lead_id,
        "lead_status": lead["status"],
        "case_integrity": integrity["status"],
        "ready_for_final_human_review": not gaps,
        "auto_submission_enabled": False,
        "platform_submission_performed": False,
        "issues": gaps,
        "evidence_refs": [
            ref for ref in (lead["primary_ref"], lead["review_ref"]) if ref
        ],
    }


def render_draft(draft: dict, result: dict) -> str:
    """Private Markdown draft, not a valid vulnerability claim by itself."""
    def field(name: str) -> str:
        value = draft.get(name, "")
        return value.strip() if isinstance(value, str) else "(not provided)"
    steps = draft.get("steps", [])
    reproduced = (
        "\n".join(str(i + 1) + ". " + step for i, step in enumerate(steps))
        if isinstance(steps, list) else "(missing)"
    )
    evidence = "\n".join("- " + ref for ref in result["evidence_refs"]) or "- none"
    status = (
        "Ready for final human review"
        if result["ready_for_final_human_review"]
        else "INCOMPLETE DRAFT - NOT FOR SUBMISSION"
    )
    gaps = "\n".join("- " + issue for issue in result["issues"]) or (
        "- No automatic field gaps; independently confirm demonstration and impact."
    )
    return (
        "# " + field("title") + "\n\n"
        + "**Status:** " + status + "\n\n"
        + "**Program:** " + field("program") + "\n"
        + "**Program rules:** " + field("program_url") + "\n"
        + "**Scope asset:** " + field("asset") + "\n"
        + "**Severity (operator-selected):** " + field("severity") + "\n\n"
        + "## Summary\n\n" + field("weakness") + "\n\n"
        + "## Prerequisites\n\n" + field("prerequisites") + "\n\n"
        + "## Steps to reproduce\n\n" + reproduced + "\n\n"
        + "## Observed result\n\n" + field("observed_result") + "\n\n"
        + "## Demonstrated security impact\n\n" + field("security_impact") + "\n\n"
        + "## Root cause\n\n" + field("root_cause") + "\n\n"
        + "## Remediation\n\n" + field("remediation") + "\n\n"
        + "## Local evidence references (not publicly accessible)\n\n"
        + evidence + "\n\n"
        + "## Quality gate / unresolved checks\n\n" + gaps + "\n\n"
        + "_Prepared locally; not submitted or published automatically. "
        + "Recheck program scope and disclosure terms before sending._\n"
    )


def write_private(path: Path, content: str) -> None:
    """Create mode-0600 report without overwriting existing files."""
    path = Path(path)
    if path.is_symlink() or not path.parent.is_dir() or path.parent.is_symlink():
        raise ReportError("REPORT_UNSAFE_DESTINATION")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise ReportError("REPORT_ALREADY_EXISTS") from exc
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
