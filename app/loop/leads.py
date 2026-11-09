"""Local, append-audited VAPT lead registry independent of model context.

This is a process ledger, not a vulnerability scanner, finding generator or
permission authority. Only a local authenticated operator may sign off
verification. Target IPs, full commands, secrets, and raw evidence are never
stored in lead rows or emitted in model handoff snapshots.
"""
from __future__ import annotations

import re
import sqlite3
import uuid
from collections import Counter

from app.security import redact
from .store import TaskError, TaskStore, canonical_id

CATEGORIES = frozenset({
    "web", "api", "auth", "network", "tls", "code", "mobile", "other"
})
STATES = frozenset({
    "open", "testing", "negative", "review_requested",
    "verified", "rejected", "closed"
})
TRANSITIONS = {
    "open": frozenset({"testing", "negative"}),
    "testing": frozenset({"open", "negative", "review_requested"}),
    "negative": frozenset({"testing"}),
    "review_requested": frozenset({"testing", "verified", "rejected"}),
    "verified": frozenset({"closed"}),
    "rejected": frozenset({"testing", "closed"}),
    "closed": frozenset(),
}
REASONS = frozenset({
    "started", "no_effect", "cannot_reproduce", "evidence_captured",
    "further_analysis", "false_positive", "operator_signoff",
    "retest_needed", "reopened", "remediated", "not_applicable"
})
TITLE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .():_-]{4,119}$")
REF = re.compile(r"^evidence://([a-f0-9-]{36})/([a-f0-9-]{36})$")


class LeadError(ValueError):
    pass


class LeadRegistry:
    def __init__(self, store: TaskStore):
        self.store = store
        with self.store._db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS process_leads (
                id TEXT PRIMARY KEY, task_id TEXT NOT NULL,
                category TEXT NOT NULL, title TEXT NOT NULL,
                status TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1,
                primary_ref TEXT, review_ref TEXT,
                reason TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS process_lead_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                lead_id TEXT NOT NULL, task_id TEXT NOT NULL,
                from_status TEXT, to_status TEXT NOT NULL,
                reason TEXT, changed_at TEXT NOT NULL,
                version INTEGER NOT NULL)""")
            db.execute("CREATE INDEX IF NOT EXISTS process_leads_task "
                       "ON process_leads(task_id,updated_at,id)")
            db.execute("CREATE INDEX IF NOT EXISTS process_lead_events_lead "
                       "ON process_lead_events(task_id,lead_id,id)")

    @staticmethod
    def _title(text: str) -> str:
        if not isinstance(text, str) or not TITLE.fullmatch(text):
            raise LeadError("LEAD_TITLE_INVALID")
        # Reject rather than save redacted private text; never destroy original evidence.
        if redact(text) != text:
            raise LeadError("LEAD_TITLE_POTENTIALLY_SENSITIVE")
        return text

    def _check_ref(self, task_id: str, reference: str) -> None:
        if not isinstance(reference, str):
            raise LeadError("LEAD_EVIDENCE_REF_INVALID")
        match = REF.fullmatch(reference)
        if match is None or match.group(1) != task_id:
            raise LeadError("LEAD_EVIDENCE_REF_INVALID")
        # An R0 handoff receipt or simulated demo is NOT evidence of a finding.
        with self.store._db() as db:
            row = db.execute(
                "SELECT 1 FROM tool_runs WHERE task_id=? AND output_ref=? "
                "AND status='completed' AND finished_at IS NOT NULL "
                "AND tool != 'workflow.handoff' LIMIT 1",
                (task_id, reference)).fetchone()
        if row is None:
            raise LeadError("LEAD_EVIDENCE_NOT_A_COMPLETED_TOOL_RECEIPT")

    def create(self, task_id: str, category: str, title: str,
               *, primary_ref: str | None = None) -> dict:
        task = self.store.require(task_id)
        if category not in CATEGORIES:
            raise LeadError("LEAD_CATEGORY_INVALID")
        clean_title = self._title(title)
        if primary_ref is not None:
            self._check_ref(task["id"], primary_ref)
        lead_id = str(uuid.uuid4())
        now = self.store.utc_now()
        with self.store._db() as db:
            db.execute(
                "INSERT INTO process_leads(id,task_id,category,title,status,version,"
                "primary_ref,created_at,updated_at) VALUES(?,?,?,?,'open',1,?,?,?)",
                (lead_id, task["id"], category, clean_title, primary_ref, now, now))
            db.execute(
                "INSERT INTO process_lead_events(lead_id,task_id,from_status,"
                "to_status,reason,changed_at,version) VALUES(?,?,NULL,'open',NULL,?,1)",
                (lead_id, task["id"], now))
        return self.get(task["id"], lead_id)

    def get(self, task_id: str, lead_id: str) -> dict:
        self.store.require(task_id)
        canonical_id(lead_id)
        with self.store._db() as db:
            row = db.execute(
                "SELECT id,task_id,category,title,status,version,primary_ref,"
                "review_ref,reason,created_at,updated_at FROM process_leads "
                "WHERE task_id=? AND id=?", (task_id, lead_id)).fetchone()
        if row is None:
            raise LeadError("LEAD_NOT_FOUND")
        return dict(row)

    def list(self, task_id: str, *, limit: int = 100) -> list[dict]:
        self.store.require(task_id)
        if type(limit) is not int or not 1 <= limit <= 200:
            raise LeadError("LEAD_LIMIT_INVALID")
        with self.store._db() as db:
            return [dict(row) for row in db.execute(
                "SELECT id,task_id,category,title,status,version,primary_ref,"
                "review_ref,reason,created_at,updated_at FROM process_leads "
                "WHERE task_id=? ORDER BY created_at,id LIMIT ?",
                (task_id, limit))]

    def events(self, task_id: str, lead_id: str) -> list[dict]:
        self.get(task_id, lead_id)
        with self.store._db() as db:
            return [dict(row) for row in db.execute(
                "SELECT from_status,to_status,reason,changed_at,version "
                "FROM process_lead_events WHERE task_id=? AND lead_id=? ORDER BY id",
                (task_id, lead_id))]

    def transition(self, task_id: str, lead_id: str, next_status: str,
                   *, reason: str, expected_version: int,
                   evidence_ref: str | None = None,
                   operator: bool = False) -> dict:
        task = self.store.require(task_id)
        canonical_id(lead_id)
        if next_status not in STATES or reason not in REASONS:
            raise LeadError("LEAD_TRANSITION_INVALID")
        if type(expected_version) is not int or expected_version < 1:
            raise LeadError("LEAD_VERSION_INVALID")
        current = self.get(task["id"], lead_id)
        if next_status not in TRANSITIONS[current["status"]]:
            raise LeadError("LEAD_ILLEGAL_STATE_TRANSITION")
        if next_status in {"verified", "closed"} and not operator:
            raise LeadError("LEAD_OPERATOR_REVIEW_REQUIRED")
        if next_status == "verified" and task["mode"] == "demo":
            raise LeadError("LEAD_SIMULATED_TASK_CANNOT_VERIFY_FINDING")
        if next_status == "negative" and reason not in {
                "no_effect", "cannot_reproduce", "false_positive", "not_applicable"}:
            raise LeadError("LEAD_NEGATIVE_REASON_REQUIRED")
        if next_status == "verified" and reason != "operator_signoff":
            raise LeadError("LEAD_VERIFICATION_REASON_INVALID")
        if evidence_ref is not None:
            self._check_ref(task["id"], evidence_ref)

        new_primary = current["primary_ref"]
        review_ref = current["review_ref"]
        if next_status == "review_requested":
            new_primary = evidence_ref or new_primary
            if not new_primary:
                raise LeadError("LEAD_EVIDENCE_REQUIRED_FOR_REVIEW")
        elif next_status == "verified":
            if not new_primary or not evidence_ref or evidence_ref == new_primary:
                raise LeadError("LEAD_INDEPENDENT_SECOND_RECEIPT_REQUIRED")
            review_ref = evidence_ref
        elif evidence_ref and next_status in {"testing", "negative"}:
            new_primary = evidence_ref

        now = self.store.utc_now()
        # Compare-and-swap prevents two agents or operator tabs overwriting progress.
        with self.store._db() as db:
            updated = db.execute(
                "UPDATE process_leads SET status=?,version=version+1,"
                "primary_ref=?,review_ref=?,reason=?,updated_at=? "
                "WHERE task_id=? AND id=? AND version=?",
                (next_status, new_primary, review_ref, reason, now,
                 task["id"], lead_id, expected_version))
            if updated.rowcount != 1:
                raise LeadError("LEAD_STALE_VERSION")
            db.execute(
                "INSERT INTO process_lead_events(lead_id,task_id,from_status,"
                "to_status,reason,changed_at,version) VALUES(?,?,?,?,?,?,?)",
                (lead_id, task["id"], current["status"], next_status, reason,
                 now, expected_version + 1))
        return self.get(task["id"], lead_id)

    def summary(self, task_id: str) -> dict:
        leads = self.list(task_id, limit=200)
        counts = Counter(entry["status"] for entry in leads)
        active = [entry for entry in leads if entry["status"] not in
                  {"negative", "verified", "rejected", "closed"}]
        # Neither titles nor raw descriptions are shared with remote model.
        return {
            "schema": "secra-leads-v1",
            "total_in_window": len(leads),
            "counts": {state: counts.get(state, 0) for state in sorted(STATES)},
            "active": [
                {"lead_id": row["id"], "category": row["category"],
                 "status": row["status"], "version": row["version"],
                 "primary_ref": row["primary_ref"]}
                for row in active[-10:]
            ],
            "negative_count": counts.get("negative", 0),
            "operator_verified_count": counts.get("verified", 0),
            "window_truncated": len(leads) == 200,
        }
