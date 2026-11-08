"""Bounded adapter to the real, vendored sapper-v2 fact-intent graph CLI.

Only five approved graph commands are ever invoked. No sapper dispatch,
arena, shell, worker spawns, credentials, or external LLM integration.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
from uuid import UUID

from .security import redact

SCRIPT = Path(__file__).resolve().parents[1] / "vendor" / "sapper_v2" / "sapper.py"
GOAL = "Document an authorized, bounded VAPT assessment with verified observations and a final report."
_ID = re.compile(r"^[fi]\d{3,}$")
_TITLE = re.compile(r"^[A-Za-z][A-Za-z0-9 ]{0,69}$")
GRAPH_ROOT: Path | None = None


class GraphError(RuntimeError):
    pass


def graph_store(eid: str, data_dir: Path) -> Path:
    """A validated UUID means the caller cannot escape the engagement graph root."""
    try:
        identifier = str(UUID(eid))
    except (ValueError, AttributeError, TypeError) as exc:
        raise GraphError("Invalid engagement id") from exc
    if identifier != eid:
        raise GraphError("Noncanonical engagement id")
    return data_dir / "sapper_graphs" / identifier / ".sapper"


def _call(store: Path, *arguments: str) -> str:
    allowed = {"init", "fact", "intent", "graph", "validate"}
    if not arguments or arguments[0] not in allowed:
        raise GraphError("Sapper operation not permitted")
    if not SCRIPT.is_file():
        raise GraphError("Sapper-v2 CLI is not installed")
    workspace = store.parent
    workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Do not inherit sensitive keys, 9Router credentials or agent CLIs.
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(workspace),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8",
        "LANG": "C.UTF-8",
    }
    try:
        result = subprocess.run(
            [sys.executable, "-I", str(SCRIPT), "--store", str(store), *arguments],
            cwd=str(workspace),
            env=env,
            input="",
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GraphError("Sapper-v2 graph command failed") from exc
    if result.returncode:
        # Never surface upstream stderr: it may contain sensitive graph data.
        raise GraphError("Sapper-v2 graph command returned a failure")
    return result.stdout[:250000].strip()


def _node_id(text: str, kind: str) -> str:
    value = text.splitlines()[0].strip() if text else ""
    if not _ID.fullmatch(value) or not value.startswith(kind):
        raise GraphError("Unexpected Sapper-v2 node identifier")
    return value


def initialize_graph(eid: str, data_dir: Path) -> str:
    store = graph_store(eid, data_dir)
    if not (store / "project.json").is_file():
        _call(store, "init", "--origin", "SECRA authorized local assessment", "--goal", GOAL)
    graph = _raw_graph(store)
    first = next((x["id"] for x in graph.get("facts", []) if x.get("title") == "Scope Approved"), None)
    if first:
        return first
    # No customer IP, hostname, credentials, headers, or raw findings in graph.
    return _node_id(_call(
        store, "fact", "Operator authorization attested; backend scope policy validated.",
        "--title", "Scope Approved", "--kind", "note", "--creator", "secra-guardian"
    ), "f")


def _raw_graph(store: Path) -> dict:
    if not (store / "project.json").is_file():
        return {"facts": [], "intents": [], "project": {}}
    data = json.loads(_call(store, "graph", "--format", "json"))
    if not isinstance(data, dict):
        raise GraphError("Unexpected graph response")
    return data


def stage_begin(eid: str, data_dir: Path, title: str, parent_id: str) -> str:
    if not _TITLE.fullmatch(title) or not _ID.fullmatch(parent_id) or not parent_id.startswith("f"):
        raise GraphError("Unrecognized stage title or parent id")
    store = graph_store(eid, data_dir)
    return _node_id(_call(
        store, "intent", "--from", parent_id,
        "Complete the approved local assessment stage: " + title,
        "--title", title, "--creator", "secra-commander",
    ), "i")


def stage_end(eid: str, data_dir: Path, title: str, intent_id: str, observation: str) -> str:
    if not _TITLE.fullmatch(title) or not _ID.fullmatch(intent_id) or not intent_id.startswith("i"):
        raise GraphError("Unrecognized stage title or intent id")
    if not re.fullmatch(r"[A-Za-z0-9 ,.:;()/-]{1,200}", observation):
        raise GraphError("Observation must be schema-controlled plain text")
    store = graph_store(eid, data_dir)
    return _node_id(_call(
        store, "fact", observation, "--from-intent", intent_id,
        "--title", title + " Result", "--kind", "note",
        "--creator", "secra-commander",
    ), "f")


def public_graph(eid: str, data_dir: Path) -> dict:
    """Allowlisted presentation; never expose arbitrary file paths or graph docs."""
    store = graph_store(eid, data_dir)
    source = _raw_graph(store)
    def clean_fact(node: dict) -> dict:
        return {
            "id": str(node.get("id", ""))[:16],
            "title": redact(node.get("title") or "Observation")[:80],
            "description": redact(node.get("description") or "")[:220],
            "kind": str(node.get("kind") or "note")[:20],
        }
    def clean_intent(node: dict) -> dict:
        return {
            "id": str(node.get("id", ""))[:16],
            "title": redact(node.get("title") or "Task")[:80],
            "description": redact(node.get("description") or "")[:220],
            "from": [str(x)[:16] for x in node.get("from", [])[:5]],
            "to": str(node["to"])[:16] if node.get("to") else None,
            "status": str(node.get("status", "open"))[:20],
        }
    facts = [clean_fact(n) for n in source.get("facts", [])[:100] if isinstance(n, dict)]
    intents = [clean_intent(n) for n in source.get("intents", [])[:100] if isinstance(n, dict)]
    return {"engine": "N1nEmAn/sapper-v2 pinned CLI", "enabled": bool(facts),
            "facts": facts, "intents": intents, "total_facts": len(facts), "total_intents": len(intents)}
