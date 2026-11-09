"""Deterministic end-to-end smoke: never depends on external model or network."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts.secra_smoke import run_offline_smoke

ROOT = Path(__file__).resolve().parents[2]


def test_complete_offline_agent_workflow_without_network():
    result = run_offline_smoke()
    assert result["simulation_only"] is True
    assert result["real_provider_tested"] is False
    assert result["kali_kernel_fence_tested"] is False
    assert result["real_target_probed"] is False
    assert result["preflight_status"] == "completed"
    assert result["lead_proposal_status"] == "completed"
    assert result["agent_tool_steps"] == 2
    assert result["agent_status"] == "completed"
    assert result["handoff_status"] == "completed"
    assert result["evidence_integrity"] == "integrity_ok"
    assert result["simulated_observations"] == 2
    assert result["verified_vulnerabilities"] == 0


def test_offline_smoke_cli_from_arbitrary_directory():
    run = subprocess.run([sys.executable, str(ROOT / "scripts" / "secra_smoke.py")],
                         cwd="/tmp", capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    report = json.loads(run.stdout)
    assert report["simulation_only"]
    assert report["evidence_integrity"] == "integrity_ok"
    assert "127.0.0.1" not in run.stdout
