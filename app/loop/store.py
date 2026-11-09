"""Durable, local task/event/approval ledger independent of the Sapper graph.

The private database may store an approved local target; public events never
include its address, credentials, raw tool output, or unmasked model messages.
"""
from __future__ import annotations

import ipaddress
import datetime as dt
import json
import os
import re
import sqlite3
import uuid
from pathlib import Path

from app.security import redact, validate_scope
from app.workspace import WorkspaceManager, WorkspaceError

STATUSES = frozenset({"created", "running", "completed", "exhausted",
                      "failed", "stopped", "refused", "awaiting_approval"})

# Hard backend call ceilings prevent unbounded direct OpenCode MCP loops.
# AgentLoop has a smaller independent 25-step budget.
MAX_TASK_TOOL_CALLS = 2000
MAX_TASK_SAME_TOOL_CALLS = 400


class TaskError(ValueError):
    pass


def canonical_id(text: str) -> str:
    try:
        value = str(uuid.UUID(text))
        if value != text:
            raise ValueError("noncanonical")
    except (ValueError, TypeError, AttributeError) as exc:
        raise TaskError("TASK_ID_INVALID") from exc
    return value


class TaskStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        if self.root.is_symlink():
            raise TaskError("TASK_ROOT_SYMLINK")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        self.path = self.root / "agent-events.sqlite3"
        with self._db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY, target TEXT NOT NULL, scope TEXT NOT NULL,
                mode TEXT NOT NULL, model TEXT NOT NULL, authorized INTEGER NOT NULL,
                status TEXT NOT NULL, created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                stop INTEGER NOT NULL DEFAULT 0)""")
            db.execute("""CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL, kind TEXT NOT NULL, tool TEXT NOT NULL,
                status TEXT NOT NULL, summary TEXT NOT NULL,
                output_ref TEXT, stamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""")
            db.execute("""CREATE TABLE IF NOT EXISTS approvals (
                id TEXT PRIMARY KEY, task_id TEXT NOT NULL, tool TEXT NOT NULL,
                risk TEXT NOT NULL, state TEXT NOT NULL,
                created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""")
            # Audited invocations, recorded BEFORE dispatch, UTC timestamps.
            # No argv, target, scope, credentials or raw tool output.
            db.execute("""CREATE TABLE IF NOT EXISTS tool_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL, tool TEXT NOT NULL,
                started_at TEXT NOT NULL, finished_at TEXT,
                duration_ms INTEGER, status TEXT NOT NULL,
                exit_code INTEGER, output_ref TEXT)""")
            db.execute("CREATE INDEX IF NOT EXISTS tool_runs_task "
                       "ON tool_runs(task_id,id)")
        os.chmod(self.path, 0o600)

    def _db(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=15000")
        return db

    def create(self, target: str, scope: str, *, mode: str = "demo",
               model: str = "", authorized: bool = False) -> str:
        if not authorized or mode not in {"demo", "live", "local", "evidence"}:
            raise TaskError("WRITTEN_AUTHORIZATION_REQUIRED")
        if not isinstance(target, str) or not isinstance(scope, str):
            raise TaskError("TARGET_SCOPE_INVALID")
        try:
            if mode == "evidence":
                # Explicitly offline-only. Store no IP, CIDR, hostname or
                # synthetic target. All target-facing manifest tools are
                # denied by task-mode checks independently in MCP.
                if target != "" or scope != "":
                    raise TaskError("EVIDENCE_MODE_MUST_NOT_SET_NETWORK_SCOPE")
                checked = ""
            elif mode in {"demo", "local"} and target == "127.0.0.1" and scope == "127.0.0.1/32":
                checked = target
            elif mode == "local":
                raise TaskError("LOCAL_ONLY_127_0_0_1")
            else:
                checked, _ = validate_scope(target, scope)
        except ValueError as exc:
            raise TaskError("SCOPE_INVALID") from exc
        if not isinstance(model, str) or not re.fullmatch(r"[A-Za-z0-9._:/+-]{0,110}", model):
            raise TaskError("MODEL_INVALID")
        tid = str(uuid.uuid4())
        # Persist private alias-only workspace before accepting a new task.
        # Scope and target stay in the existing local TaskStore database.
        try:
            workspace = WorkspaceManager(self.root / "engagements")
            workspace.initialize(tid)
            workspace.capture_preflight(tid)
        except (OSError, WorkspaceError) as exc:
            raise TaskError("WORKSPACE_INIT_FAILED") from exc
        with self._db() as db:
            db.execute("INSERT INTO tasks (id,target,scope,mode,model,authorized,status) VALUES (?,?,?,?,?,?,?)",
                       (tid, checked, scope, mode, model, 1, "created"))
        self.append(tid, "task", "", "created",
                    "Offline evidence task initialized; no network target."
                    if mode == "evidence" else "Engagement initialized; target is ASSET_001.")
        return tid

    def require(self, tid: str) -> dict:
        tid = canonical_id(tid)
        with self._db() as db:
            row = db.execute("SELECT * FROM tasks WHERE id=?", (tid,)).fetchone()
        if row is None or row["authorized"] != 1:
            raise TaskError("TASK_NOT_AUTHORIZED")
        return dict(row)

    def _note_test_phase(self, tid: str, event: str) -> None:
        """Supplementary UTC workspace phase marker; DB state is authoritative.

        Phase file I/O may fail independently of SQLite; never invent a
        timestamp or retroactively pretend that it was committed.
        """
        try:
            WorkspaceManager(self.root / "engagements").record_phase(
                tid, "testing", event)
        except (OSError, WorkspaceError):
            self.append(tid, "task", "", "error",
                        "Workspace testing-phase marker unavailable; DB task state remains authoritative.")

    def start(self, tid: str) -> None:
        with self._db() as db:
            result = db.execute("UPDATE tasks SET status='running', stop=0 WHERE id=? AND status='created'",
                                (canonical_id(tid),))
            if result.rowcount != 1:
                raise TaskError("TASK_NOT_STARTABLE")
        self.append(tid, "task", "", "running", "Authorized workflow started.")
        self._note_test_phase(tid, "started")

    def set_status(self, tid: str, status: str, message: str) -> None:
        if status not in STATUSES:
            raise TaskError("TASK_STATUS_INVALID")
        task = self.require(tid)
        if task["status"] == "stopped" and status != "stopped":
            raise TaskError("TASK_ALREADY_STOPPED")
        with self._db() as db:
            db.execute("UPDATE tasks SET status=? WHERE id=?", (status, tid))
        self.append(tid, "task", "", status, message)
        if status in {"completed", "failed", "exhausted", "refused", "awaiting_approval"}:
            self._note_test_phase(
                tid, "completed" if status == "completed" else "blocked")

    def stop(self, tid: str) -> None:
        self.require(tid)
        with self._db() as db:
            db.execute("UPDATE tasks SET stop=1,status='stopped' WHERE id=?", (canonical_id(tid),))
        self.append(tid, "task", "", "stopped", "Operator requested emergency stop.")
        self._note_test_phase(tid, "blocked")

    def is_stopped(self, tid: str) -> bool:
        t = self.require(tid)
        return bool(t["stop"]) or t["status"] == "stopped"

    def append(self, tid: str, kind: str, tool: str, status: str,
               summary: str, output_ref: str | None = None) -> int:
        canonical_id(tid)
        if (kind not in {"task", "model", "tool", "approval", "skill"}
                or not isinstance(tool, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{0,80}", tool)
                or status not in (STATUSES | {"requested", "done", "denied", "error", "queued", "approved", "rejected"})
                or not isinstance(summary, str) or len(summary) > 4096):
            raise TaskError("EVENT_INVALID")
        # The caller must supply short sanitized metadata; defense in depth.
        summary = redact(summary)[:700]
        if output_ref is not None and not re.fullmatch(
                r"evidence://[a-f0-9-]{36}/[a-f0-9-]{36}", output_ref):
            raise TaskError("OUTPUT_REF_INVALID")
        with self._db() as db:
            cursor = db.execute("INSERT INTO events(task_id,kind,tool,status,summary,output_ref) "
                                "VALUES(?,?,?,?,?,?)",
                                (tid, kind, tool, status, summary, output_ref))
            return cursor.lastrowid

    def events(self, tid: str, after: int = 0, limit: int = 100) -> list[dict]:
        self.require(tid)
        if not isinstance(after, int) or after < 0 or not 1 <= limit <= 200:
            raise TaskError("EVENT_CURSOR_INVALID")
        with self._db() as db:
            return [dict(x) for x in db.execute(
                "SELECT seq,kind,tool,status,summary,output_ref,stamp "
                "FROM events WHERE task_id=? AND seq>? ORDER BY seq LIMIT ?",
                (tid, after, limit))]


    @staticmethod
    def utc_now() -> str:
        """Actual UTC wall-clock timestamp; never reconstruct phase times."""
        return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")

    def begin_tool_run(self, tid: str, tool: str) -> int:
        """Durably log invocation BEFORE dispatch, including direct MCP calls.

        The caller must abort execution when this method fails. Arguments and
        customer addresses are intentionally never included in this record.
        """
        self.require(tid)
        if not isinstance(tool, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", tool):
            raise TaskError("TOOL_AUDIT_NAME_INVALID")
        with self._db() as db:
            # Atomic reservation across independent MCP processes/sessions.
            # Model prompt instructions cannot override these limits.
            db.execute("BEGIN IMMEDIATE")
            total = db.execute(
                "SELECT COUNT(*) FROM tool_runs WHERE task_id=?", (tid,)
            ).fetchone()[0]
            per_tool = db.execute(
                "SELECT COUNT(*) FROM tool_runs WHERE task_id=? AND tool=?",
                (tid, tool)).fetchone()[0]
            if total >= MAX_TASK_TOOL_CALLS:
                raise TaskError("TASK_TOOL_CALL_BUDGET_EXCEEDED")
            if per_tool >= MAX_TASK_SAME_TOOL_CALLS:
                raise TaskError("TASK_SAME_TOOL_CALL_BUDGET_EXCEEDED")
            cursor = db.execute(
                "INSERT INTO tool_runs(task_id,tool,started_at,status) VALUES(?,?,?,?)",
                (tid, tool, self.utc_now(), "requested"))
            return cursor.lastrowid

    def finish_tool_run(self, tid: str, audit_id: int, status: str,
                        exit_code: int | None, duration_ms: int,
                        output_ref: str | None = None) -> None:
        """Record outcomes without treating a receipt as a verified finding."""
        self.require(tid)
        if (type(audit_id) is not int or audit_id <= 0
                or status not in {"completed", "simulated", "denied", "blocked",
                                  "approval_required", "cancelled", "error"}
                or type(duration_ms) is not int or not 0 <= duration_ms <= 7_200_000
                or (exit_code is not None and
                    (type(exit_code) is not int or not -255 <= exit_code <= 255))
                or (output_ref is not None and
                    not re.fullmatch(r"evidence://[a-f0-9-]{36}/[a-f0-9-]{36}", output_ref))):
            raise TaskError("TOOL_AUDIT_OUTCOME_INVALID")
        with self._db() as db:
            updated = db.execute(
                "UPDATE tool_runs SET finished_at=?,duration_ms=?,status=?,"
                "exit_code=?,output_ref=? WHERE id=? AND task_id=? AND status='requested'",
                (self.utc_now(), duration_ms, status, exit_code, output_ref,
                 audit_id, tid))
            if updated.rowcount != 1:
                raise TaskError("TOOL_AUDIT_STATE_INVALID")

    def tool_runs(self, tid: str, *, limit: int = 200) -> list[dict]:
        """Bounded sanitized execution ledger for continuity and evaluations."""
        self.require(tid)
        if type(limit) is not int or not 1 <= limit <= 200:
            raise TaskError("TOOL_AUDIT_LIMIT_INVALID")
        with self._db() as db:
            return [dict(r) for r in db.execute(
                "SELECT id,tool,started_at,finished_at,duration_ms,status,"
                "exit_code,output_ref FROM tool_runs WHERE task_id=? "
                "ORDER BY id DESC LIMIT ?", (tid, limit))][::-1]

    def request_approval(self, tid: str, tool: str, risk: str) -> str:
        self.require(tid)
        if risk not in {"R3", "R4"}:
            raise TaskError("APPROVAL_RISK_INVALID")
        aid = str(uuid.uuid4())
        with self._db() as db:
            db.execute("INSERT INTO approvals(id,task_id,tool,risk,state) VALUES(?,?,?,?,?)",
                       (aid, tid, tool, risk, "pending"))
        self.append(tid, "approval", tool, "queued", risk + ": awaiting explicit operator review.")
        return aid

    def approvals(self, tid: str) -> list[dict]:
        self.require(tid)
        with self._db() as db:
            return [dict(row) for row in db.execute(
                "SELECT id,tool,risk,state,created FROM approvals WHERE task_id=? ORDER BY created", (tid,))]

    def decide(self, tid: str, approval_id: str, decision: str) -> None:
        self.require(tid)
        if decision not in {"approved", "rejected"}:
            raise TaskError("DECISION_INVALID")
        canonical_id(approval_id)
        with self._db() as db:
            row = db.execute("SELECT risk,tool FROM approvals WHERE id=? AND task_id=? AND state='pending'",
                             (approval_id, tid)).fetchone()
            if row is None:
                raise TaskError("APPROVAL_NOT_PENDING")
            if row["risk"] == "R4" and decision == "approved":
                raise TaskError("R4_ALWAYS_PROHIBITED")
            db.execute("UPDATE approvals SET state=? WHERE id=?", (decision, approval_id))
        self.append(tid, "approval", row["tool"], decision, row["risk"] + ": operator decision recorded.")
