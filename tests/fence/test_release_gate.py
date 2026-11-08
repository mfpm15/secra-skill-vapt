"""Additional offline fence regression and release-gate tests."""
from __future__ import annotations

import runpy
import subprocess
import threading
from pathlib import Path
from uuid import uuid4

import pytest

from app.gateway.fence import FenceUnverified, SystemdFence
from app.scope_guard import ScopePolicy
from app.tool_gateway import ToolGateway
from app.tool_registry import StructuredToolIntent


def test_systemd_backend_blocks_without_root_lab_proof(tmp_path, monkeypatch):
    gateway = ToolGateway(tmp_path / "evidence", fence=SystemdFence(attestation=str(tmp_path / "missing")))
    monkeypatch.setattr("app.tool_gateway.subprocess.Popen",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("Popen bypass")))
    intent = StructuredToolIntent(uuid4(), uuid4(), "recon", "nmap.tcp_top20",
                                  "192.0.2.10", {})
    with pytest.raises(FenceUnverified):
        gateway.execute(intent, "192.0.2.10", "192.0.2.0/24", threading.Event())
    assert gateway.audit.events(intent.engagement_id)[-1]["outcome"] == "FENCE_BLOCKED"


def test_systemd_stop_uses_root_helper_only_no_pid_kill(tmp_path, monkeypatch):
    gateway = ToolGateway(tmp_path, fence=SystemdFence())
    run_id = uuid4()
    gateway._active[run_id] = 123456
    observed = []
    class Completed:
        returncode = 0
    def recorder(argv, **kwargs):
        observed.append(argv)
        return Completed()
    monkeypatch.setattr("app.tool_gateway.subprocess.run", recorder)
    monkeypatch.setattr("app.tool_gateway.os.killpg",
                        lambda *args: (_ for _ in ()).throw(AssertionError("PID kill used")))
    gateway.terminate_process_group(run_id)
    assert observed == [("sudo", "-n", "/usr/local/sbin/secra-run",
                         "stop", "--run", str(run_id))]


def test_systemd_stop_failure_is_not_silently_ignored(tmp_path, monkeypatch):
    gateway = ToolGateway(tmp_path, fence=SystemdFence())
    run_id = uuid4()
    gateway._active[run_id] = 123456
    class Completed:
        returncode = 1
    monkeypatch.setattr("app.tool_gateway.subprocess.run", lambda *a, **k: Completed())
    with pytest.raises(RuntimeError, match="SYSTEMD_STOP_FAILED"):
        gateway.terminate_process_group(run_id)


def test_release_gate_missing_lab_is_a_failure(tmp_path):
    source = Path(__file__).with_name("verify_lab.py")
    verifier = runpy.run_path(str(source))
    gate = verifier["verify_lab_evidence"]
    with pytest.raises(verifier["LabGateError"]):
        gate(tmp_path)
    assert verifier["main"]([]) == 2
