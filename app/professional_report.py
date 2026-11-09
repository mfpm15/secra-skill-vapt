"""Evidence-grounded VAPT professional narrative, locally generated, no model guesses.

Maps real task audit + typed operator-reviewed findings to OWASP WSTG-style
executive summary, chronology, verification detail, remediation and gaps.
Does not promote model-generated hypotheses, demo receipts or empty proof into
confirmed findings. Does not expose raw vault data to remote models.
"""
from __future__ import annotations

import datetime as dt
import html
import re
from collections import Counter

from app.loop.case_integrity import check_case
from app.loop.leads import LeadRegistry
from app.loop.store import TaskStore
from app.workspace import WorkspaceManager

SEVERITIES = frozenset({"informational", "low", "medium", "high", "critical"})
FIELDS = frozenset({
    "engagement_title", "client_alias", "objectives", "scope_description",
    "assessment_constraints", "authorization_reference",
    "reviewer_identity", "operator_review_confirmed", "findings",
})
DETAILS = frozenset({
    "lead_id", "title", "severity", "cwe", "expected", "observed",
    "business_impact", "prerequisites", "reproduction_steps",
    "countercheck", "root_cause", "remediation", "retest",
    "reviewer_reproduced", "evidence_refs", "cvss_vector",
})


class NarrativeError(ValueError):
    pass


def _line(value: object, *, limit: int = 2400) -> str:
    if not isinstance(value, str) or not 1 <= len(value.strip()) <= limit:
        raise NarrativeError("REPORT_TEXT_MISSING_OR_TOO_LONG")
    # Markdown/HTML-safe; local file must not execute embedded source HTML.
    return html.escape(value.strip(), quote=True).replace("|", "\\|").replace("\n", " ")


def _list(value: object, *, minimum: int, maximum: int) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise NarrativeError("REPORT_LIST_INVALID")
    return [_line(x, limit=1600) for x in value]


def _time(value: str) -> tuple[int, str]:
    if not isinstance(value, str):
        raise NarrativeError("REPORT_AUDIT_TIMESTAMP_INVALID")
    try:
        instant = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise NarrativeError("REPORT_AUDIT_TIMESTAMP_INVALID") from exc
    if instant.tzinfo is None:
        raise NarrativeError("REPORT_AUDIT_TIMESTAMP_MISSING_OFFSET")
    instant = instant.astimezone(dt.timezone.utc)
    return int(instant.timestamp() * 1000), instant.isoformat(timespec="milliseconds")


def _observed_events(store: TaskStore, task_id: str) -> tuple[list[dict], bool]:
    # TaskStore supplies its latest bounded rows; verify whether history exists
    # outside the window, rather than claiming complete chronology.
    rows = store.tool_runs(task_id, limit=200)
    with store._db() as db:
        audit_total = db.execute(
            "SELECT COUNT(*) FROM tool_runs WHERE task_id=?", (task_id,)).fetchone()[0]
    records = []
    for row in rows:
        order, timestamp = _time(row["started_at"])
        records.append({
            "order": order, "time": timestamp, "kind": "tool",
            "action": row["tool"], "status": row["status"],
            "evidence": row["output_ref"] or "none",
        })
    for phase in WorkspaceManager(store.root / "engagements").phases(task_id):
        order, timestamp = _time(phase["at_utc"])
        records.append({
            "order": order, "time": timestamp, "kind": "phase",
            "action": phase["stage"], "status": phase["event"],
            "evidence": "local phase ledger",
        })
    records.sort(key=lambda row: (row["order"], row["kind"], row["action"]))
    return records, audit_total > len(rows)


def _reviewed_details(lead: dict, raw: object,
                      *, integrity_ok: bool, demo: bool,
                      operator_confirmed: bool) -> tuple[dict | None, list[str]]:
    issues = []
    if not isinstance(raw, dict) or set(raw) - DETAILS:
        return None, ["finding_detail_invalid"]
    if raw.get("lead_id") != lead["id"]:
        return None, ["finding_lead_id_mismatch"]
    if lead["status"] != "verified":
        issues.append("lead_not_operator_verified")
    if demo:
        issues.append("simulation_not_confirmed")
    if not integrity_ok:
        issues.append("case_integrity_not_verified")
    if not operator_confirmed or raw.get("reviewer_reproduced") is not True:
        issues.append("independent_reproduction_not_attested")
    expected_refs = {
        x for x in (lead["primary_ref"], lead["review_ref"]) if x
    }
    submitted = raw.get("evidence_refs")
    if (len(expected_refs) != 2 or not isinstance(submitted, list)
            or not all(isinstance(x, str) for x in submitted)
            or set(submitted) != expected_refs or len(submitted) != 2):
        issues.append("two_exact_sealed_evidence_refs_required")
    if raw.get("severity") not in SEVERITIES:
        issues.append("severity_invalid")
    required = ("title", "expected", "observed", "business_impact",
                "prerequisites", "countercheck", "root_cause",
                "remediation", "retest")
    details = {}
    for key in required:
        try:
            details[key] = _line(raw.get(key), limit=1500)
            if key in {"observed", "business_impact", "countercheck"} and len(details[key]) < 25:
                issues.append("insufficient_" + key)
        except NarrativeError:
            issues.append("missing_" + key)
    try:
        details["steps"] = _list(raw.get("reproduction_steps"), minimum=2, maximum=12)
    except NarrativeError:
        issues.append("reproduction_steps_incomplete")
    if raw.get("cvss_vector"):
        vector = raw.get("cvss_vector")
        if not isinstance(vector, str) or not re.fullmatch(r"CVSS:4\.0/[A-Z0-9:/._-]{10,240}", vector):
            issues.append("cvss_vector_invalid")
        else:
            details["cvss_vector"] = vector
    if issues:
        return None, sorted(set(issues))
    details["lead_id"] = lead["id"]
    details["severity"] = raw["severity"]
    details["refs"] = sorted(expected_refs)
    details["cwe"] = _line(raw.get("cwe", "Unassigned"), limit=120)
    return details, []


def build_report(store: TaskStore, task_id: str, operator: dict) -> dict:
    task = store.require(task_id)
    if not isinstance(operator, dict) or set(operator) - FIELDS:
        raise NarrativeError("REPORT_INPUT_SCHEMA_INVALID")
    title = _line(operator.get("engagement_title"), limit=160)
    client = _line(operator.get("client_alias"), limit=160)
    objectives = _list(operator.get("objectives"), minimum=1, maximum=12)
    constraints = _list(operator.get("assessment_constraints"), minimum=1, maximum=20)
    scope = _line(operator.get("scope_description"), limit=1400)
    authorization = _line(operator.get("authorization_reference"), limit=180)
    reviewer = _line(operator.get("reviewer_identity"), limit=140)
    operator_confirmed = operator.get("operator_review_confirmed") is True
    candidates = operator.get("findings", [])
    if not isinstance(candidates, list) or len(candidates) > 100:
        raise NarrativeError("REPORT_FINDINGS_LIMIT")

    case = check_case(store, task_id)
    integrity_ok = case["status"] == "integrity_ok"
    registry = LeadRegistry(store)
    all_leads = registry.list(task_id, limit=200)
    lead_map = {x["id"]: x for x in all_leads}
    approved = []
    excluded = []
    used = set()
    for raw in candidates:
        if not isinstance(raw, dict):
            excluded.append({"id": "unrecognized", "issues": ["invalid_data"]})
            continue
        uid = raw.get("lead_id")
        if not isinstance(uid, str) or uid in used:
            excluded.append({"id": "unrecognized", "issues": ["invalid_or_duplicate_id"]})
            continue
        used.add(uid)
        lead = lead_map.get(uid)
        if lead is None:
            excluded.append({"id": "unrecognized", "issues": ["not_registered_in_task"]})
            continue
        detail, issues = _reviewed_details(
            lead, raw, integrity_ok=integrity_ok,
            demo=task["mode"] == "demo",
            operator_confirmed=operator_confirmed,
        )
        if detail:
            approved.append(detail)
        else:
            excluded.append({"id": uid, "issues": issues})
    timeline, truncated = _observed_events(store, task_id)
    summary = Counter(x["status"] for x in all_leads)
    coverage = []
    if truncated:
        coverage.append("Audit window contains only the latest 200 tool calls; chronology is incomplete.")
    if len(all_leads) >= 200:
        coverage.append("Lead listing reached its 200-item display cap.")
    if not integrity_ok:
        coverage.append("Evidence integrity checks require review; no finding promoted.")
    if not operator_confirmed:
        coverage.append("Operator has not attested final reproduction and report review.")
    if task["mode"] == "demo":
        coverage.append("Demo task: all simulated observations are excluded from confirmed findings.")
    if excluded:
        coverage.append("Some submitted findings were excluded by independent quality gates.")
    if not timeline:
        coverage.append("No timestamped tool/phase observations were recorded.")

    markdown = [
        "# " + title, "",
        "**CONFIDENTIAL — operator-reviewed local draft; do not publish raw evidence.**",
        "",
        "Client/engagement alias: " + client,
        "Task ID: " + task_id,
        "Operator review: " + reviewer + (" (attested)" if operator_confirmed else " (pending)"),
        "Scope authorization reference: " + authorization, "",
        "## 1. Executive summary", "",
        "This point-in-time assessment considered " + scope + ". "
        + "The documented objectives were " + "; ".join(objectives) + ".",
        "",
        "There are **" + str(len(approved)) + " operator-reviewed and evidence-backed findings** "
        "included in this report. " +
        ("Their validated business impacts are outlined below."
         if approved else "No vulnerability is represented as confirmed solely from tool output, assumptions or demo results."),
        "",
    ]
    for finding in approved:
        markdown.append("- **" + finding["title"] + "** (" + finding["severity"]
                        + "): " + finding["business_impact"])
    markdown.extend([
        "",
        "**Priority actions:** "
        + ("; ".join(item["remediation"] for item in approved[:3])
           if approved else "Complete independent reproduction, verify case integrity and review current program permissions."),
        "",
        "These conclusions are restricted to the permitted scope and recorded test window. "
        "Untested areas are not assumed secure.", "",
        "## 2. Engagement boundaries and methodology", "",
        "**Scope:** " + scope, "",
        "**Authorization:** " + authorization, "",
        "**Methods and constraints:**", "",
        *("- " + item for item in constraints), "",
        "The report distinguishes operator-confirmed evidence from hypotheses, blocked tools, "
        "simulator outputs and tests that were never performed.", "",
        "## 3. Chronological evidence narrative", "",
    ])
    if not timeline:
        markdown.append("No recorded events; no test narrative can be reconstructed.")
    else:
        for index, row in enumerate(timeline, 1):
            status = _line(row["status"], limit=60)
            action = _line(row["action"], limit=90)
            evidence = _line(row["evidence"], limit=110)
            markdown.extend([
                "### Event " + str(index) + " — " + row["time"],
                "",
                "The local " + ("tool audit" if row["kind"] == "tool" else "phase ledger")
                + " recorded **" + action + "** with outcome **" + status + "**. "
                + ("Its sealed evidence reference is " + evidence + "."
                   if row["evidence"].startswith("evidence://")
                   else "No externally accessible evidence was attached to this entry."),
                "",
            ])
    markdown.extend([
        "Entries marked denied, blocked, simulated or incomplete are not evidence of an exploitable vulnerability.",
        "",
        "## 4. Findings summary", "",
        "| Reference | Finding | Severity | Review state |",
        "|---|---|---|---|",
    ])
    for number, finding in enumerate(approved, 1):
        markdown.append("| F-" + str(number).zfill(3) + " | "
                        + finding["title"] + " | " + finding["severity"]
                        + " | Operator-confirmed; evidence-linked |")
    if not approved:
        markdown.append("| — | No confirmed findings | — | Requires operator review |")
    markdown.extend(["", "## 5. Verified finding details", ""])
    for number, finding in enumerate(approved, 1):
        markdown.extend([
            "### F-" + str(number).zfill(3) + " — " + finding["title"], "",
            "**Severity:** " + finding["severity"],
            "**Weakness classification:** " + finding["cwe"], "",
            "**Preconditions:** " + finding["prerequisites"], "",
            "**Expected behavior:** " + finding["expected"], "",
            "**Observed behavior:** " + finding["observed"], "",
            "**Demonstrated impact:** " + finding["business_impact"], "",
            "**Independent countercheck:** " + finding["countercheck"], "",
            "**Reproduction steps:**", "",
            *(str(n) + ". " + step for n, step in enumerate(finding["steps"], 1)),
            "", "**Root cause:** " + finding["root_cause"], "",
            "**Remediation:** " + finding["remediation"], "",
            "**Retest acceptance:** " + finding["retest"], "",
            "**Encrypted evidence references:**", "",
            *("- " + ref for ref in finding["refs"]), "",
        ])
        if "cvss_vector" in finding:
            markdown.extend(["**Operator-supplied CVSS vector (not automatically scored):** "
                             + finding["cvss_vector"], ""])
    markdown.extend([
        "## 6. Unverified and rejected hypotheses", "",
        "The following lead states are not claimed as confirmed vulnerabilities.",
        "",
        "| State | Count |",
        "|---|---:|",
    ])
    for state in ("open", "testing", "review_requested", "negative", "rejected", "closed"):
        markdown.append("| " + state + " | " + str(summary.get(state, 0)) + " |")
    if excluded:
        markdown.extend(["", "**Excluded candidate details (quality gate):**", ""])
        for row in excluded:
            markdown.append("- " + row["id"] + ": " + ", ".join(row["issues"]))
    markdown.extend([
        "", "## 7. Limitations, cleanup and follow-up", "",
        *("- " + item for item in (coverage or ["No additional process gaps detected in the bounded audit."])),
        "- Local evidence vault data must stay protected; do not publish authentication tokens or sensitive request bodies.",
        "- Target-side cleanup and remediation confirmation require separate operator evidence and sign-off.",
        "- Retesting must occur under the applicable current written authorization.",
        "", "## 8. Evidence and integrity appendix", "",
        "- Case integrity: " + case["status"],
        "- Workspace manifest: " + case["workspace_manifest"],
        "- Tool audit records checked: " + str(case["tool_audit_rows_checked"]),
        "- Evidence seals verified: " + str(case["evidence_seals_verified"]),
        "- Invalid/missing evidence references: " +
        str(case["evidence_references_invalid"] + case["evidence_seals_missing_or_corrupt"]),
        "- Raw evidence stored locally; only opaque references are listed.",
        "- Standard: OWASP WSTG v4.2 reporting guidance and FIRST CVSS v4.0, when applicable.",
        "",
        "**Disclaimer:** This is a point-in-time security assessment. No technique not "
        "recorded in the audit is represented as executed, and unknown security state "
        "is not represented as tested or safe.",
        "",
    ])
    return {
        "schema": "secra-professional-report-v1",
        "quality": "reviewed" if integrity_ok and operator_confirmed and not excluded
                   and task["mode"] != "demo" and not truncated
                   else "draft_requires_operator_review",
        "confirmed_findings": len(approved),
        "excluded_candidates": excluded,
        "chronology_entries": len(timeline),
        "chronology_truncated": truncated,
        "case_integrity": case["status"],
        "markdown": "\n".join(markdown),
    }
