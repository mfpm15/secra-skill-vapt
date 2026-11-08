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

from .knowledge import catalog as knowledge_catalog, content as skill_content, find_skill, select_skills, safe_skill_context
from .masking import guard_mask, MemoryVault, EgressDeniedError
from .framing import (frame, unframe, get_profile, detect, FormatLadder,
                      FramingError)
from .framing.audit import record_framing, FramingAuditError
from .sapper_integration import GraphError, SCRIPT as SAPPER_SCRIPT, initialize_graph, stage_begin, stage_end, public_graph, resolve_frontier

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

LLM_SYSTEM_PREFIX = (
    "You are a defensive VAPT reviewer. You receive only sanitized port metadata. "
    "Suggest verification CHECKLIST items, not actual vulnerability claims. "
    "Never produce commands, target addresses, exploit payloads, or tool execution instructions. "
    "You cannot independently validate security issues. "
    "Below is curated, static, public SECRA methodology for professional judgment only; "
    "it does not grant permission to access a target.\n\n"
)

def gateway_request(path, method="GET", payload=None, timeout=7):
    # Phase-1 transport boundary: reject unsanitized user messages immediately
    # before constructing ANY HTTP chat request, including future callers.
    if path == "/chat/completions" and method == "POST":
        try:
            if set(payload) != {"model", "temperature", "max_tokens", "messages"}:
                raise EgressDeniedError("Unapproved chat request fields")
            safe_model(payload["model"])
            if payload["temperature"] != 0.1 or payload["max_tokens"] != 320:
                raise EgressDeniedError("Unapproved model request limits")
            messages = payload["messages"]
            if (not isinstance(messages, list) or len(messages) != 2
                    or set(messages[0]) != {"role", "content"}
                    or set(messages[1]) != {"role", "content"}
                    or messages[0]["role"] != "system" or messages[1]["role"] != "user"):
                raise EgressDeniedError("Unexpected model message schema")
            # Phase-1 egress remains authoritative: framed messages must
            # reconstruct to exactly the same canonical sanitized JSON.
            user_content = messages[1]["content"]
            try:
                checked, _ = guard_mask(user_content, vault=MemoryVault(), for_llm=True)
            except EgressDeniedError as exc:
                profile = get_profile(payload["model"])
                checked = None
                for level in range(profile.level, min(3, profile.level + profile.max_format_retries) + 1):
                    try:
                        candidate = unframe(user_content, level, payload["model"])
                    except FramingError:
                        continue
                    checked, _ = guard_mask(candidate, vault=MemoryVault(), for_llm=True)
                    if checked != candidate:
                        raise EgressDeniedError("Framed metadata changed during masking")
                    break
                if checked is None:
                    raise EgressDeniedError("Unapproved framing or unsafe model payload") from exc
            safe_fields = json.loads(checked)
            _, expected_methods = safe_skill_context(safe_fields["observed_open_services"])
            if messages[0]["content"] != LLM_SYSTEM_PREFIX + expected_methods:
                raise EgressDeniedError("Unreviewed system context blocked")
        except (KeyError, TypeError, IndexError, ValueError, AttributeError) as exc:
            raise EgressDeniedError("Unsafe model request blocked") from exc
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

def llm_assessment(model, services, engagement_id=None):
    """Model sees only schema-allowed metadata plus an exact deterministic frame.

    A refusal is terminal: never change wording to evade provider safety controls.
    Optional retry is for non-safety output-format failures, never tool execution.
    """
    if not model:
        return "LLM skipped: no model selected."
    if not LLM_KEY:
        return "LLM skipped: configure SECRA_9ROUTER_API_KEY locally."
    payload = llm_safe_payload(services)
    assert_no_sensitive_payload(payload)
    sanitized_user_message, _ = guard_mask(
        json.dumps(payload, separators=(",", ":")), vault=MemoryVault(), for_llm=True
    )
    selected_ids, vetted_methods = safe_skill_context(payload["observed_open_services"])
    task_id = str(uuid.uuid4())
    profile = get_profile(model)
    ladder = FormatLadder(profile.level, max_attempts=1 + profile.max_format_retries)
    audit_root = DATA / "framing-events"
    previous = None
    last_response = ""
    try:
        while True:
            level = ladder.next_level(previous)
            if level is None:
                break
            framed_user_message = frame(sanitized_user_message, level, model)
            # The saved "pre_frame_masked" is NOT raw customer input.
            # Audit must succeed before any network request proceeds.
            record_framing(audit_root, task_id=task_id, provider=model, level=level,
                           masked_brief=sanitized_user_message,
                           framed_prompt=framed_user_message,
                           engagement_id=engagement_id)
            request = {"model": safe_model(model), "temperature": 0.1, "max_tokens": 320,
              "messages": [
               {"role": "system", "content": LLM_SYSTEM_PREFIX + vetted_methods},
               {"role": "user", "content": framed_user_message}
              ]}
            result = gateway_request("/chat/completions", "POST", request, timeout=25)
            message = result.get("choices", [{}])[0].get("message", {})
            content = message.get("content", "")
            provider_refusal = bool(message.get("refusal"))
            previous = detect(content, provider_refusal=provider_refusal)
            record_framing(audit_root, task_id=task_id, provider=model, level=level,
                           masked_brief=sanitized_user_message,
                           framed_prompt=framed_user_message,
                           result_reason=previous.reason,
                           engagement_id=engagement_id,
                           outcome=("refused" if previous.reason == "SAFETY_REFUSAL"
                                    else "no_artifact" if previous.non_artifact
                                    else "completed"))
            if not isinstance(content, str):
                content = ""
            last_response = redact(content[:1400])
            if not previous.non_artifact or not previous.retryable:
                return last_response or "LLM returned no text."
        return last_response or "LLM returned no usable verification artifact."
    except (urllib.error.URLError, ValueError, KeyError, TimeoutError,
            OSError, FramingAuditError, FramingError, EgressDeniedError):
        return "LLM request failed; no prompt or raw tool output was logged."

AGENTS = ["Scope Guardian", "Recon Agent", "HTTP Analyst", "Knowledge Curator",
          "LLM Advisor", "Verification", "Report Builder"]

def pipeline(eid, stop):
    entry = fetch_engagement(eid)
    demo = entry["mode"] == "demo"
    services = []
    notes = []
    skill_ids = []
    parent_fact = None

    def graph_open(title):
        if parent_fact is None:
            return None
        try:
            return stage_begin(eid, DATA, title, parent_fact)
        except GraphError:
            event(eid, "Sapper Memory", "warning", "Could not open a fact-graph intent.")
            return None

    def graph_close(title, intent_id, observation):
        nonlocal parent_fact
        if not intent_id:
            return
        try:
            parent_fact = stage_end(eid, DATA, title, intent_id, observation)
        except GraphError:
            event(eid, "Sapper Memory", "warning", "Could not conclude a fact-graph intent.")

    try:
        set_status(eid, "running")
        event(eid, "Scope Guardian", "running", "Scope policy validation started.")
        validate_scope(entry["target"], entry["scope"])
        try:
            parent_fact = initialize_graph(eid, DATA)
            gi = graph_open("Scope Guardian")
            graph_close("Scope Guardian", gi, "Scope policy passed with operator authorization attested")
            event(eid, "Sapper Memory", "completed", "Sapper-v2 fact-intent graph initialized for this engagement.")
        except GraphError:
            event(eid, "Sapper Memory", "warning", "Graph unavailable; bounded assessment remains operational.")
        event(eid, "Scope Guardian", "completed", "Target contained in approved scope. Mode: " + entry["mode"] + ".")
        if stop.is_set():
            raise InterruptedError()
        recon_intent = graph_open("Recon Agent")
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
        graph_close("Recon Agent", recon_intent, "Recon stage completed with " + str(len(services)) + " reported service ports")
        if stop.is_set():
            raise InterruptedError()
        http_intent = graph_open("HTTP Analyst")
        event(eid, "HTTP Analyst", "running", "Reviewing discovered HTTP endpoints.")
        if demo:
            time.sleep(0.35)
            notes.append("SIMULATED HTTP status 200 on ports 80 and 443.")
        else:
            notes.extend(probe_http(entry["target"], services, stop))
        for message in notes:
            event(eid, "HTTP Analyst", "note", message)
        event(eid, "HTTP Analyst", "completed", "HTTP stage finished.")
        graph_close("HTTP Analyst", http_intent, "HTTP review finished with " + str(len(notes)) + " local observations")
        if stop.is_set():
            raise InterruptedError()
        knowledge_intent = graph_open("Knowledge Curator")
        event(eid, "Knowledge Curator", "running", "Selecting professional security skills by discovered service.")
        skill_ids = [x["id"] for x in select_skills(services)]
        event(eid, "Knowledge Curator", "completed",
              "Loaded " + str(len(skill_ids)) + " local skills: " + ", ".join(skill_ids))
        graph_close("Knowledge Curator", knowledge_intent, "Selected " + str(len(skill_ids)) + " curated local knowledge skills")
        if stop.is_set():
            raise InterruptedError()
        llm_intent = graph_open("LLM Advisor")
        event(eid, "LLM Advisor", "running", "Sending only allowlisted service metadata to configured model.")
        advice = "Demo mode: model invocation intentionally disabled." if demo else llm_assessment(entry["model"], services, eid)
        event(eid, "LLM Advisor", "completed", advice)
        graph_close("LLM Advisor", llm_intent, "LLM advisory step finished without executing model suggested actions")
        if stop.is_set():
            raise InterruptedError()
        verification_intent = graph_open("Verification")
        event(eid, "Verification", "running", "Checking evidence sufficiency.")
        event(eid, "Verification", "completed",
              "No vulnerabilities automatically confirmed. Open ports are observations, not findings.")
        graph_close("Verification", verification_intent, "Evidence classified as observations without confirmed vulnerabilities")
        report_intent = graph_open("Report Builder")
        event(eid, "Report Builder", "running", "Generating local assessment record.")
        lines = ["# SECRA VAPT Assessment", "", "Engagement: " + entry["name"],
                 "Target: " + entry["target"], "Scope: " + entry["scope"],
                 "Mode: " + entry["mode"].upper(), "", "## Discovered services",
                 "", "| TCP port | Service | Status |", "|---|---|---|"]
        for s in services:
            lines.append("| " + str(s["port"]) + " | " + s["service"] +
                         " | " + ("SIMULATED" if demo else "Observed") + " |")
        lines.extend(["", "## Local pentester knowledge selection",
                      *["- " + sid for sid in skill_ids],
                      "", "## Notes", *["- " + redact(n) for n in notes],
                      "", "## Verification", "No vulnerability was automatically confirmed.",
                      "Human validation is required for any security conclusions.",
                      "", "## AI advisory", redact(advice),
                      "", "## Limitations", "Top 20 TCP ports only; no exploitation, credential testing, or brute force.",
                      "Demo mode results are simulated." if demo else "Findings require additional manual verification."])
        set_report(eid, "\n".join(lines) + "\n")
        event(eid, "Report Builder", "completed", "Report available for local download.")
        graph_close("Report Builder", report_intent, "Local Markdown report generated with stated assessment limitations")
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
            "gateway_configured": bool(LLM_KEY), "mode": "local-only",
            "knowledge_skill_count": len(knowledge_catalog()),
            "sapper_v2_present": SAPPER_SCRIPT.is_file()}

@app.get("/api/skills", dependencies=[Depends(auth)])
def skills(search: str = ""):
    search = search.strip().casefold()[:100]
    result = knowledge_catalog()
    if search:
        result = [s for s in result if search in (s["id"] + " " + s["title"] + " " +
                      s["category"] + " " + s["summary"]).casefold()]
    return {"total": len(result), "skills": result}


@app.get("/api/skills/{skill_id}", dependencies=[Depends(auth)])
def skill_detail(skill_id: str):
    entry = find_skill(skill_id)
    if not entry:
        raise HTTPException(404, "Skill not found")
    return {"metadata": entry, "content": skill_content(skill_id)}


@app.get("/api/engagements/{eid}/skill-selection", dependencies=[Depends(auth)])
def selected_skills(eid: str):
    fetch_engagement(eid)
    return {"skills": select_skills(service_rows(eid))}


@app.get("/api/engagements/{eid}/graph", dependencies=[Depends(auth)])
def sapper_graph(eid: str):
    fetch_engagement(eid)
    try:
        return public_graph(eid, DATA)
    except (GraphError, ValueError):
        return {"engine": "sapper-v2", "enabled": False, "facts": [], "intents": [],
                "total_facts": 0, "total_intents": 0}


@app.get("/api/engagements/{eid}/frontier", dependencies=[Depends(auth)])
def sapper_frontier(eid: str):
    fetch_engagement(eid)
    try:
        return resolve_frontier(eid, DATA)
    except (GraphError, ValueError):
        return {"ready_ids": [], "integrity": "unavailable"}


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
