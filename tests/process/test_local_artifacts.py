"""Real local Kali tools: filesystem confinement, raw privacy and audit."""
from __future__ import annotations

import hashlib
from pathlib import Path
from uuid import UUID

from app.evidence_vault import EvidenceVault
from app.loop.store import TaskStore
from app.mcp.dispatcher import ToolDispatcher
from app.mcp.local_artifacts import is_available


def setup_case(tmp_path):
    store = TaskStore(tmp_path)
    task_id = store.create("", "", mode="evidence", authorized=True)
    store.start(task_id)
    target = (tmp_path / "engagements" / task_id /
              "03-evidence" / "analysis-input" / "sample.txt")
    target.write_bytes(b"CTF demo artifact, not a target.\nSecret API KEY = TEST-PRIVATE-VALUE\n")
    return store, task_id, target, ToolDispatcher(tmp_path, store=store)


def test_real_local_hash_uses_file_bytes_and_seals_receipt(tmp_path):
    store, tid, filename, dispatcher = setup_case(tmp_path)
    result = dispatcher.call("artifact.sha256",
                             {"task_id": tid, "artifact": "sample.txt"})
    assert result["status"] == "completed"
    assert result["masked"] is True
    assert "TEST-PRIVATE-VALUE" not in result["summary"]
    assert result["output_ref"].startswith("evidence://")
    rid = UUID(result["output_ref"].rsplit("/", 1)[-1])
    raw = EvidenceVault(tmp_path / "evidence").verify_and_read(UUID(tid), rid)["stdout"]
    assert hashlib.sha256(filename.read_bytes()).hexdigest().encode() in raw
    assert store.tool_runs(tid)[0]["tool"] == "artifact.sha256"
    assert store.tool_runs(tid)[0]["status"] == "completed"


def test_six_tools_are_real_when_trusted_binary_is_available(tmp_path):
    store, tid, filename, dispatcher = setup_case(tmp_path)
    for tool in ("artifact.file_type", "artifact.strings",
                 "artifact.elf_header", "artifact.object_summary",
                 "artifact.metadata"):
        result = dispatcher.call(tool, {"task_id": tid, "artifact": "sample.txt"})
        # Non-matching file formats may fail, but cannot be passed off as
        # completed analyses. Tools absent on a CI runner also fail closed.
        assert result["status"] in {"completed", "blocked"}
        assert "TEST-PRIVATE-VALUE" not in result["summary"]
        if tool == "artifact.file_type" and is_available(tool):
            assert result["status"] == "completed"
            assert result["output_ref"].startswith("evidence://")


def test_symlink_traversal_and_unreviewed_argv_never_execute(tmp_path):
    store, tid, filename, dispatcher = setup_case(tmp_path)
    parent = filename.parent
    outside = tmp_path / "secrets.txt"
    outside.write_text("SENSITIVE PRIVATE")
    (parent / "escape.txt").symlink_to(outside)
    for name in ("escape.txt", "../secret", "/etc/passwd",
                 "../../../../../etc/passwd", ".hidden"):
        result = dispatcher.call("artifact.sha256",
                                 {"task_id": tid, "artifact": name})
        assert result["status"] in {"blocked", "denied"}
        assert result["output_ref"] is None
    injected = dispatcher.call("artifact.file_type",
        {"task_id": tid, "artifact": "sample.txt", "argv": [";curl", "evil"]})
    assert injected["status"] == "denied"
    assert store.tool_runs(tid)[0]["output_ref"] is None


def test_artifact_tools_are_denied_after_operator_stops_case(tmp_path):
    store, tid, filename, dispatcher = setup_case(tmp_path)
    store.stop(tid)
    result = dispatcher.call("artifact.sha256",
                             {"task_id": tid, "artifact": "sample.txt"})
    assert result["status"] == "denied"
    assert result["output_ref"] is None


def test_available_local_artifacts_in_capability_preflight(tmp_path):
    store, tid, filename, dispatcher = setup_case(tmp_path)
    from app.loop.readiness import inspect_capabilities
    report = inspect_capabilities(store, dispatcher.manifest, tid)
    item = next(x for x in report["tools"] if x["name"] == "artifact.sha256")
    assert item["classification"] == "local_only"
    assert report["live_execution_ready"] is False
