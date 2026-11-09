"""Kali readiness reports do not enable live execution or touch network."""
from __future__ import annotations

import json
from pathlib import Path

from app.live_preflight import check_live_prerequisites
from app.loop.store import TaskStore


def test_live_prerequisite_inventory_does_not_attest_fence(tmp_path, monkeypatch):
    store = TaskStore(tmp_path)
    tid = store.create("10.77.0.2", "10.77.0.2/32", mode="live", authorized=True)
    monkeypatch.setenv("SECRA_FENCE_BACKEND", "systemd")
    result = check_live_prerequisites(store, tid)
    assert result["checks"]["task_is_live"] is True
    assert result["live_execution_independently_verified"] is False
    assert result["network_tests_performed"] == 0
    assert result["kernel_lab_proof_required"] is True
    assert "10.77.0.2" not in json.dumps(result)
    assert "target" not in result


def test_even_fake_good_metadata_cannot_claim_live_verification(tmp_path, monkeypatch):
    from app import live_preflight as check
    store = TaskStore(tmp_path)
    tid = store.create("10.77.0.2", "10.77.0.2/32", mode="live", authorized=True)
    wrapper = tmp_path / "secra-run"
    wrapper.write_text("trusted placeholder")
    monkeypatch.setattr(check, "WRAPPER", str(wrapper))
    monkeypatch.setattr(check, "read_attestation", lambda _: {"result": "pass"})
    monkeypatch.setenv("SECRA_FENCE_BACKEND", "systemd")
    result = check_live_prerequisites(store, tid)
    assert not result["live_execution_independently_verified"]
    assert "kernel_lab_proof_required" in result
