"""SECRA VAPT console: scoped, local-first assessment orchestration MVP."""
from __future__ import annotations
import datetime as dt
import json
import os
import secrets
import shutil
import sqlite3
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel, Field

from .security import (
    assert_no_sensitive_payload, llm_safe_payload, redact, safe_gateway,
    safe_model, validate_scope,
)

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(os.getenv("SECRA_DATA_DIR", str(ROOT / "data")))
DATA.mkdir(parents=True, exist_ok=True)
DB = DATA / "secra.sqlite3"
TOKEN = os.getenv("SECRA_DASHBOARD_TOKEN") or secrets.token_urlsafe(24)
if not os.getenv("SECRA_DASHBOARD_TOKEN"):
    print("\n[SECRA] Local dashboard access token: " + TOKEN + "\n", flush=True)
GATEWAY = safe_gateway(os.getenv("SECRA_9ROUTER_BASE_URL", "http://127.0.0.1:20128/v1"))
LLM_KEY = os.getenv("SECRA_9ROUTER_API_KEY", "")
app = FastAPI(title="SECRA VAPT", version="0.1.0", docs_url=None, redoc_url=None)
workers: dict[str, threading.Event] = {}
worker_lock = threading.Lock()

class CreateEngagement(BaseModel):
    name: str = Field(min_length=3, max_length=100)
    target: str = Field(min_length=7, max_length=45)
    scope: str = Field(min_length=7, max_length=2048)
    authorized: bool
    mode: Literal["demo", "live"] = "demo"
    model: str = Field(default="", max_length=110)

class PrivacyPreview(BaseModel):
    text: str = Field(min_length=1, max_length=4000)

def connect():
    conn = sqlite3.connect(DB, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def initialize():
    with connect() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS engagements (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, target TEXT NOT NULL,
            scope TEXT NOT NULL, mode TEXT NOT NULL, model TEXT NOT NULL,
            status TEXT NOT NULL, created_at TEXT NOT NULL,
            report TEXT NOT NULL DEFAULT '')""")
        conn.execute("""CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, engagement_id TEXT NOT NULL,
            stamp TEXT NOT NULL, agent TEXT NOT NULL,
            level TEXT NOT NULL, message TEXT NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS services (
            engagement_id TEXT NOT NULL, port INTEGER NOT NULL,
            service TEXT NOT NULL, observation TEXT NOT NULL,
            PRIMARY KEY (engagement_id, port))""")
        conn.execute("UPDATE engagements SET status='interrupted' WHERE status='running'")

initialize()

def auth(x_secra_token: str | None = Header(default=None)):
    if not x_secra_token or not secrets.compare_digest(x_secra_token, TOKEN):
        raise HTTPException(401, "Access token required")

def fetch_engagement(eid):
    with connect() as conn:
        row = conn.execute("SELECT * FROM engagements WHERE id=?", (eid,)).fetchone()
    if row is None:
        raise HTTPException(404, "Engagement not found")
    return dict(row)

def event(eid, agent, level, message):
    stamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    with connect() as conn:
        conn.execute("INSERT INTO events (engagement_id,stamp,agent,level,message) VALUES (?,?,?,?,?)",
                     (eid, stamp, agent, level, redact(message)))

def set_status(eid, status):
    with connect() as conn:
        conn.execute("UPDATE engagements SET status=? WHERE id=?", (status, eid))

def set_report(eid, body):
    with connect() as conn:
        conn.execute("UPDATE engagements SET report=? WHERE id=?", (body, eid))

def save_services(eid, ports, simulation):
    with connect() as conn:
        for svc in ports:
            conn.execute("INSERT OR REPLACE INTO services VALUES (?,?,?,?)",
                         (eid, svc["port"], svc["service"],
                          "SIMULATED" if simulation else "observed by Nmap"))

def service_rows(eid):
    with connect() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT port,service,observation FROM services WHERE engagement_id=? ORDER BY port", (eid,))]

def run_argv(args: list[str], seconds: int, stop: threading.Event) -> tuple[int, str]:
    """Fixed argv only, no shell; terminate subprocess when cancelled or timed out."""
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            stdin=subprocess.DEVNULL, start_new_session=True)
    deadline = time.monotonic() + seconds
    while proc.poll() is None:
        if stop.is_set() or time.monotonic() > deadline:
            proc.kill()
            proc.communicate()
            raise RuntimeError("Tool cancelled or timed out")
        time.sleep(0.15)
    out, err = proc.communicate()
    return proc.returncode, out[:100000]

def nmap_scan(target, stop):
    if not shutil.which("nmap"):
        raise RuntimeError("Nmap tidak ditemukan di PATH; install nmap pada host Kali.")
    argv = ["nmap", "-sT", "-Pn", "-n", "-T2", "--top-ports", "20",
            "--max-retries", "1", "--host-timeout", "45s", "-oX", "-", target]
    code, out = run_argv(argv, 65, stop)
    if code != 0:
        raise RuntimeError("Nmap exited with a nonzero status")
    root = ET.fromstring(out)
    services = []
    for p in root.findall(".//port"):
        state = p.find("state")
        if state is not None and state.get("state") == "open":
            port = int(p.get("portid", "0"))
            if 0 < port <= 65535:
                services.append({"port": port, "service": {
                    80: "http", 443: "https", 22: "ssh", 25: "smtp", 21: "ftp",
                    53: "domain", 3306: "mysql", 5432: "postgresql",
                    445: "microsoft-ds", 3389: "ms-wbt-server",
                    8080: "http", 8443: "https",
                }.get(port, "unknown")})
    return services

HTTP_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 3000, 5000, 9443}
HTTPS_PORTS = {443, 8443, 9443}

def probe_http(target, services, stop):
    if not shutil.which("curl"):
        return ["curl unavailable; skipped HTTP header review"]
    notes = []
    for item in services:
        port = item["port"]
        if port not in HTTP_PORTS:
            continue
        scheme = "https" if port in HTTPS_PORTS else "http"
        url = scheme + "://" + target + ":" + str(port) + "/"
        args = ["curl", "--noproxy", "*", "--proto", "=http,https",
                "--max-redirs", "0", "--connect-timeout", "3",
                "--max-time", "7", "-k", "-sS", "-I", url]
        try:
            code, response = run_argv(args, 10, stop)
            first = response.splitlines()[0][:90] if response.splitlines() else ""
            # Do not retain raw server headers or responses.
            status = next((tok for tok in first.split() if len(tok) == 3 and tok.isdigit()), "unknown")
            notes.append("Port " + str(port) + ": HTTP status " + status if code == 0 else
                         "Port " + str(port) + ": HTTP probe failed")
        except RuntimeError:
            notes.append("Port " + str(port) + ": HTTP probe interrupted")
            if stop.is_set():
                break
    return notes

def gateway_request(path, method="GET", payload=None, timeout=7):
    headers = {"Accept": "application/json"}
    if LLM_KEY:
        headers["Authorization"] = "Bearer " + LLM_KEY
    if payload is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(GATEWAY + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read(400000))

def llm_assessment(model, services):
    if not model:
        return "LLM skipped: no model selected."
    if not LLM_KEY:
        return "LLM skipped: configure SECRA_9ROUTER_API_KEY locally."
    payload = llm_safe_payload(services)
    assert_no_sensitive_payload(payload)
    request = {"model": safe_model(model), "temperature": 0.1, "max_tokens": 320,
      "messages": [
       {"role": "system", "content": "You are a defensive VAPT reviewer. You receive only sanitized port metadata. Suggest verification CHECKLIST items, not claims of actual vulnerabilities. Never issue tool commands. Never assume a finding is confirmed."},
       {"role": "user", "content": json.dumps(payload, separators=(",", ":"))}
      ]}
    try:
        result = gateway_request("/chat/completions", "POST", request, timeout=25)
        content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
        if not isinstance(content, str):
            return "LLM returned no text."
        return redact(content[:1400])
    except (urllib.error.URLError, ValueError, KeyError, TimeoutError, OSError):
        return "LLM request failed; no prompt or raw tool output was logged."

AGENTS = ["Scope Guardian", "Recon Agent", "HTTP Analyst", "LLM Advisor",
          "Verification", "Report Builder"]

def pipeline(eid, stop):
    entry = fetch_engagement(eid)
    demo = entry["mode"] == "demo"
    services = []
    notes = []
    try:
        set_status(eid, "running")
        event(eid, "Scope Guardian", "running", "Scope policy validation started.")
        validate_scope(entry["target"], entry["scope"])
        event(eid, "Scope Guardian", "completed", "Target contained in approved scope. Mode: " + entry["mode"] + ".")
        if stop.is_set():
            raise InterruptedError()
        event(eid, "Recon Agent", "running", "Starting " + ("SIMULATION" if demo else "bounded Nmap discovery") + ".")
        if demo:
            time.sleep(0.4)
            services = [{"port": 22, "service": "ssh"}, {"port": 80, "service": "http"},
                        {"port": 443, "service": "https"}]
            event(eid, "Recon Agent", "completed", "SIMULATED: three services in demo dataset.")
        else:
            try:
                services = nmap_scan(entry["target"], stop)
                event(eid, "Recon Agent", "completed",
                      "Nmap completed: " + str(len(services)) + " open services in top 20 TCP ports.")
            except (RuntimeError, ET.ParseError) as exc:
                event(eid, "Recon Agent", "error", str(exc))
                notes.append("Recon unavailable or incomplete.")
        save_services(eid, services, demo)
        if stop.is_set():
            raise InterruptedError()
        event(eid, "HTTP Analyst", "running", "Reviewing discovered HTTP endpoints.")
        if demo:
            time.sleep(0.35)
            notes.append("SIMULATED HTTP status 200 on ports 80 and 443.")
        else:
            notes.extend(probe_http(entry["target"], services, stop))
        for message in notes:
            event(eid, "HTTP Analyst", "note", message)
        event(eid, "HTTP Analyst", "completed", "HTTP stage finished.")
        if stop.is_set():
            raise InterruptedError()
        event(eid, "LLM Advisor", "running", "Sending only allowlisted service metadata to configured model.")
        advice = "Demo mode: model invocation intentionally disabled." if demo else llm_assessment(entry["model"], services)
        event(eid, "LLM Advisor", "completed", advice)
        event(eid, "Verification", "running", "Checking evidence sufficiency.")
        event(eid, "Verification", "completed",
              "No vulnerabilities automatically confirmed. Open ports are observations, not findings.")
        event(eid, "Report Builder", "running", "Generating local assessment record.")
        lines = ["# SECRA VAPT Assessment", "", "Engagement: " + entry["name"],
                 "Target: " + entry["target"], "Scope: " + entry["scope"],
                 "Mode: " + entry["mode"].upper(), "", "## Discovered services",
                 "", "| TCP port | Service | Status |", "|---|---|---|"]
        for s in services:
            lines.append("| " + str(s["port"]) + " | " + s["service"] +
                         " | " + ("SIMULATED" if demo else "Observed") + " |")
        lines.extend(["", "## Notes", *["- " + redact(n) for n in notes],
                      "", "## Verification", "No vulnerability was automatically confirmed.",
                      "Human validation is required for any security conclusions.",
                      "", "## AI advisory", redact(advice),
                      "", "## Limitations", "Top 20 TCP ports only; no exploitation, credential testing, or brute force.",
                      "Demo mode results are simulated." if demo else "Findings require additional manual verification."])
        set_report(eid, "\n".join(lines) + "\n")
        event(eid, "Report Builder", "completed", "Report available for local download.")
        set_status(eid, "completed")
    except InterruptedError:
        set_status(eid, "cancelled")
        event(eid, "System", "warning", "Assessment cancelled by operator.")
    except Exception:
        set_status(eid, "failed")
        event(eid, "System", "error", "Assessment failed; inspect local application logs.")
    finally:
        with worker_lock:
            workers.pop(eid, None)

@app.get("/")
def dashboard():
    return FileResponse(ROOT / "app" / "static" / "index.html",
                        headers={"Cache-Control": "no-store"})

@app.get("/api/health", dependencies=[Depends(auth)])
def health():
    return {"status": "ok", "available_tools": {t: bool(shutil.which(t)) for t in ("nmap", "curl")},
            "gateway_configured": bool(LLM_KEY), "mode": "local-only"}

@app.post("/api/privacy-preview", dependencies=[Depends(auth)])
def privacy_preview(body: PrivacyPreview):
    return {"masked": redact(body.text)}

@app.get("/api/models", dependencies=[Depends(auth)])
def models():
    if not LLM_KEY:
        return {"models": [], "status": "missing API key"}
    try:
        result = gateway_request("/models", timeout=6)
        names = [m["id"] for m in result.get("data", [])
                 if isinstance(m, dict) and isinstance(m.get("id"), str)]
        valid = []
        for name in names:
            try:
                valid.append(safe_model(name))
            except ValueError:
                pass
        return {"models": valid[:200], "status": "connected"}
    except (urllib.error.URLError, OSError, ValueError):
        return {"models": [], "status": "gateway unavailable"}

@app.post("/api/engagements", dependencies=[Depends(auth)])
def create(body: CreateEngagement):
    if not body.authorized:
        raise HTTPException(400, "Written authorization must be confirmed.")
    try:
        ip, scope = validate_scope(body.target, body.scope)
        model = safe_model(body.model) if body.model else ""
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    eid = str(uuid.uuid4())
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    with connect() as conn:
        conn.execute("INSERT INTO engagements(id,name,target,scope,mode,model,status,created_at) VALUES (?,?,?,?,?,?,?,?)",
            (eid, body.name.strip(), ip, ", ".join(scope), body.mode, model, "created", now))
    event(eid, "System", "note", "Engagement created. Explicit operator start required.")
    return {"id": eid}

@app.get("/api/engagements", dependencies=[Depends(auth)])
def list_engagements():
    with connect() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT id,name,target,mode,model,status,created_at FROM engagements ORDER BY created_at DESC LIMIT 80")]

@app.get("/api/engagements/{eid}", dependencies=[Depends(auth)])
def get_engagement(eid: str):
    entry = fetch_engagement(eid)
    entry["services"] = service_rows(eid)
    entry["agents"] = AGENTS
    with connect() as conn:
        entry["event_count"] = conn.execute(
            "SELECT count(*) FROM events WHERE engagement_id=?", (eid,)).fetchone()[0]
    return entry

@app.get("/api/engagements/{eid}/events", dependencies=[Depends(auth)])
def get_events(eid: str, after: int = 0):
    fetch_engagement(eid)
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM events WHERE engagement_id=? AND id>? ORDER BY id LIMIT 300",
            (eid, max(after, 0))).fetchall()
    return [dict(r) for r in rows]

@app.post("/api/engagements/{eid}/start", dependencies=[Depends(auth)])
def start(eid: str):
    entry = fetch_engagement(eid)
    if entry["status"] not in {"created", "interrupted"}:
        raise HTTPException(409, "Engagement already started or completed.")
    with worker_lock:
        if len(workers) >= 2:
            raise HTTPException(429, "Maximum two concurrent assessments.")
        if eid in workers:
            raise HTTPException(409, "Already running.")
        stop = threading.Event()
        workers[eid] = stop
        set_status(eid, "running")
        threading.Thread(target=pipeline, args=(eid, stop), daemon=True).start()
    return {"status": "running"}

@app.post("/api/engagements/{eid}/cancel", dependencies=[Depends(auth)])
def cancel(eid: str):
    fetch_engagement(eid)
    with worker_lock:
        if eid not in workers:
            raise HTTPException(409, "No active worker.")
        workers[eid].set()
    event(eid, "System", "warning", "Cancellation requested; tool termination pending.")
    return {"status": "cancelling"}

@app.get("/api/engagements/{eid}/report", dependencies=[Depends(auth)])
def report(eid: str):
    entry = fetch_engagement(eid)
    if not entry["report"]:
        raise HTTPException(404, "No report available.")
    return PlainTextResponse(entry["report"], media_type="text/markdown",
      headers={"Content-Disposition": 'attachment; filename="secra-vapt-report.md"',
               "Cache-Control": "no-store"})
