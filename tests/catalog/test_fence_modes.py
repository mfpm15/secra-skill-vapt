"""Explicit mode display cannot weaken the independent Kali network fence."""
from __future__ import annotations

import json
from uuid import UUID

import pytest

from app.loop.store import TaskStore
from app.mcp.dispatcher import ToolDispatcher
from app.mcp.fence_mode import FenceModeError, get_fence_mode, fence_label


def test_strict_default_and_invalid_mode_fail_closed(monkeypatch):
    monkeypatch.delenv("SECRA_FENCE_MODE", raising=False)
    assert get_fence_mode() == "strict"
    assert fence_label("strict", local=True) == "local_loopback_only"
    monkeypatch.setenv("SECRA_FENCE_MODE", "invalid-unfenced")
    with pytest.raises(FenceModeError):
        get_fence_mode()


def test_dev_reports_unfenced_only_for_existing_local_adapter(tmp_path, monkeypatch):
    import app.mcp.dispatcher as mod
    monkeypatch.setenv("SECRA_FENCE_MODE", "dev")
    store = TaskStore(tmp_path)
    dispatcher = ToolDispatcher(tmp_path, store=store)
    tid = store.create("127.0.0.1", "127.0.0.1/32",
                       mode="local", authorized=True)
    store.start(tid)
    def fake_head(*, target, scope, port, vault, engagement_id):
        assert target == "127.0.0.1" and scope == "127.0.0.1/32"
        assert port == 8765 and engagement_id == UUID(tid)
        return 204, "LOCAL HEAD: status 204 on loopback port 8765.", None
    monkeypatch.setattr(mod, "run_head", fake_head)
    result = dispatcher.call("local.http_head", {"task_id": tid, "port": 8765})
    assert result["status"] == "completed"
    assert result["fence_status"] == "unfenced"
    assert "UNFENCED LOCAL ONLY" in result["summary"]
    assert not result["output_ref"]


def test_dev_cannot_enable_unverified_external_live_gateway(tmp_path, monkeypatch):
    import subprocess
    monkeypatch.setenv("SECRA_FENCE_MODE", "dev")
    monkeypatch.delenv("SECRA_FENCE_BACKEND", raising=False)
    monkeypatch.setattr(subprocess, "Popen",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("Kali subprocess bypass")))
    store = TaskStore(tmp_path)
    dispatcher = ToolDispatcher(tmp_path, store=store)
    tid = store.create("192.0.2.10", "192.0.2.0/24",
                       mode="live", authorized=True)
    store.start(tid)
    result = dispatcher.call("nmap.tcp_top20", {"task_id": tid})
    assert result["status"] == "blocked"
    assert result["fence_status"] == "blocked_until_kernel_verified"
    assert result["output_ref"] is None


def test_mode_visible_in_local_ui_status(tmp_path, monkeypatch):
    import app.ui.server as ui
    from fastapi.testclient import TestClient
    monkeypatch.setenv("SECRA_FENCE_MODE", "dev")
    store = TaskStore(tmp_path)
    monkeypatch.setattr(ui, "STORE", store)
    monkeypatch.setattr(ui, "TOKEN", "ci-test-fence-mode-token-123456")
    tid = store.create("127.0.0.1", "127.0.0.1/32",
                       mode="local", authorized=True)
    res = TestClient(ui.app).get("/api/tasks/" + tid,
                             headers={"X-Secra-Token": "ci-test-fence-mode-token-123456"})
    assert res.status_code == 200
    assert res.json()["fence_mode"] == "dev"
