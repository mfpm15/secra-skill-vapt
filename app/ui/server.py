"""One-page localhost operator console: durable events, approvals and stop.

Never expose this console on a public interface. All API routes require a
per-process bearer token; static HTML contains no credentials or customer data.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import os
import secrets
import threading
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field

from app.loop.agent import AgentLoop
from app.loop.store import TaskStore, TaskError
from app.loop.continuity import build_handoff
from app.workspace import WorkspaceManager, WorkspaceError
from app.mcp.dispatcher import ToolDispatcher

DATA = Path(os.environ.get("SECRA_DATA_DIR", str(Path(__file__).resolve().parents[2] / "data")))
TOKEN = os.environ.get("SECRA_DASHBOARD_TOKEN") or secrets.token_urlsafe(30)
if not os.environ.get("SECRA_DASHBOARD_TOKEN"):
    print("[SECRA] Local UI operator token: " + TOKEN, flush=True)
STORE = TaskStore(DATA)
DISPATCHER = ToolDispatcher(DATA, store=STORE)
LOOP = AgentLoop(STORE, DISPATCHER)
CANCEL: dict[str, threading.Event] = {}
LOCK = threading.Lock()
app = FastAPI(title="SECRA Agent Console", docs_url=None, redoc_url=None)


class TaskForm(BaseModel):
    target: str = Field(min_length=7, max_length=45)
    scope: str = Field(min_length=7, max_length=2048)
    mode: str = "demo"
    model: str = Field(default="", max_length=110)
    authorized: bool = False


class ApprovalDecision(BaseModel):
    decision: str


class PhaseDecision(BaseModel):
    stage: str
    event: str


def auth(x_secra_token: str | None = Header(default=None)):
    if not x_secra_token or not hmac.compare_digest(x_secra_token, TOKEN):
        raise HTTPException(401, "Unauthorized.")


@app.get("/")
def index():
    return FileResponse(Path(__file__).with_name("index.html"),
                        headers={"Cache-Control": "no-store"})


@app.get("/api/tools", dependencies=[Depends(auth)])
def tools():
    return [{"name": x.name, "risk": x.risk, "mode": x.mode,
             "description": x.description}
            for x in DISPATCHER.manifest.visible()]


@app.post("/api/tasks", dependencies=[Depends(auth)])
def create_task(body: TaskForm):
    try:
        tid = STORE.create(body.target, body.scope, mode=body.mode,
                           model=body.model, authorized=body.authorized)
    except TaskError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"id": tid, "status": "created", "asset": "ASSET_001"}


def _job(tid: str, stopper: threading.Event):
    try:
        LOOP.run(tid, stop=stopper)
    except BaseException:
        try:
            if not STORE.is_stopped(tid):
                STORE.set_status(tid, "failed", "Worker failed; no additional tools launched.")
        except Exception:
            pass
    finally:
        with LOCK:
            CANCEL.pop(tid, None)


@app.post("/api/tasks/{tid}/start", dependencies=[Depends(auth)])
def start_task(tid: str):
    try:
        task = STORE.require(tid)
        if task["status"] != "created":
            raise TaskError("TASK_NOT_STARTABLE")
        with LOCK:
            if tid in CANCEL:
                raise TaskError("TASK_ALREADY_RUNNING")
            stopper = threading.Event()
            CANCEL[tid] = stopper
        thread = threading.Thread(target=_job, args=(tid, stopper), daemon=True)
        thread.start()
        return {"id": tid, "status": "starting"}
    except TaskError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.get("/api/tasks/{tid}", dependencies=[Depends(auth)])
def task_status(tid: str):
    try:
        record = STORE.require(tid)
    except TaskError as exc:
        raise HTTPException(404, "Unknown task") from exc
    return {"id": tid, "asset": "ASSET_001", "mode": record["mode"],
            "status": record["status"], "model": record["model"],
            "stopped": bool(record["stop"])}


@app.get("/api/tasks/{tid}/events", dependencies=[Depends(auth)])
async def sse_events(tid: str, request: Request, after: int = 0):
    try:
        STORE.require(tid)
    except TaskError as exc:
        raise HTTPException(404, "Unknown task") from exc

    async def stream():
        cursor = max(0, after)
        while True:
            if await request.is_disconnected():
                break
            events = STORE.events(tid, after=cursor, limit=100)
            for event in events:
                cursor = event["seq"]
                yield ("id: " + str(cursor) + "\nevent: secra\ndata: " +
                       json.dumps(event, separators=(",", ":")) + "\n\n")
            current = STORE.require(tid)["status"]
            if current in {"completed", "stopped", "exhausted", "failed", "refused", "awaiting_approval"}:
                break
            yield ": heartbeat\n\n"
            await asyncio.sleep(0.4)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store",
                                      "X-Accel-Buffering": "no"})


@app.get("/api/tasks/{tid}/workspace", dependencies=[Depends(auth)])
def workspace_status(tid: str):
    """Operator-only workspace health; no IP, CIDR or raw evidence."""
    try:
        STORE.require(tid)
        manager = WorkspaceManager(STORE.root / "engagements")
        directory = manager.require(tid)
        phases = manager.phases(tid)
        manifest = directory / "06-ledger/manifest.json"
        return {"task_id": tid, "asset": "ASSET_001",
                "workspace": str(directory),
                "phase_events": len(phases),
                "latest_phase": phases[-1] if phases else None,
                "preflight_recorded": (directory / "00-preflight/local-readiness.json").is_file(),
                "manifest_present": manifest.is_file()}
    except (TaskError, WorkspaceError):
        raise HTTPException(404, "Unknown task or workspace")


@app.post("/api/tasks/{tid}/phase", dependencies=[Depends(auth)])
def record_phase(tid: str, body: PhaseDecision):
    """Explicit operator stage transition with real UTC timestamp."""
    try:
        STORE.require(tid)
        return WorkspaceManager(STORE.root / "engagements").record_phase(
            tid, body.stage, body.event)
    except (TaskError, WorkspaceError) as exc:
        raise HTTPException(400, "Invalid task or phase") from exc


@app.post("/api/tasks/{tid}/manifest", dependencies=[Depends(auth)])
def create_manifest(tid: str):
    """Regenerate hashed inventory of workspace, never raw evidence content."""
    try:
        STORE.require(tid)
        info = WorkspaceManager(STORE.root / "engagements").write_manifest(tid)
        return {"status": "created", "task_id": tid,
                "file_count": info["file_count"], "total_bytes": info["total_bytes"],
                "duplicate_groups": len(info["duplicates"])}
    except (OSError, TaskError, WorkspaceError) as exc:
        raise HTTPException(400, "Cannot create workspace manifest") from exc


@app.get("/api/tasks/{tid}/manifest/verify", dependencies=[Depends(auth)])
def verify_manifest(tid: str):
    try:
        STORE.require(tid)
        return WorkspaceManager(STORE.root / "engagements").verify_manifest(tid)
    except (OSError, TaskError, WorkspaceError) as exc:
        raise HTTPException(400, "Manifest unavailable or invalid") from exc


@app.get("/api/tasks/{tid}/handoff", dependencies=[Depends(auth)])
def handoff(tid: str):
    """Operator-only sanitized process checkpoint, never raw target evidence."""
    try:
        return build_handoff(STORE, tid)
    except TaskError as exc:
        raise HTTPException(404, "Unknown task") from exc


@app.get("/api/tasks/{tid}/approvals", dependencies=[Depends(auth)])
def approvals(tid: str):
    try:
        return STORE.approvals(tid)
    except TaskError as exc:
        raise HTTPException(404, "Unknown task") from exc


@app.post("/api/tasks/{tid}/approvals/{approval_id}", dependencies=[Depends(auth)])
def decide(tid: str, approval_id: str, body: ApprovalDecision):
    try:
        STORE.decide(tid, approval_id, body.decision)
        return {"status": body.decision,
                "execution": "not-enabled-until-reviewed-R3-adapter"}
    except TaskError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/tasks/{tid}/stop", dependencies=[Depends(auth)])
def stop_task(tid: str):
    try:
        STORE.stop(tid)
    except TaskError as exc:
        raise HTTPException(404, "Unknown task") from exc
    with LOCK:
        stopper = CANCEL.get(tid)
        if stopper:
            stopper.set()
    return {"id": tid, "status": "stopped"}
