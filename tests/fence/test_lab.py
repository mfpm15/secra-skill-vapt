"""Mandatory Kali VM adversarial acceptance: NOT run in standard GitHub CI.

Run with: pytest tests/fence/test_lab.py -m lab -q -ra
Without a root-controlled Kali testbed and explicit test-network configuration,
these tests FAIL, never skip. Do not issue an attestation before real passes.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.lab

CASES = (
    "allow_in_scope", "deny_out_of_scope", "deny_ipv6", "deny_ipv4_mapped",
    "deny_dns_rebinding", "deny_cname_outside_scope", "deny_hardcoded_resolver",
    "deny_proxy", "kill_child_grandchild", "timeout_zero_survivors",
    "enforce_memory_cpu_tasks", "verify_exec_sandbox_properties",
    "verify_cgroup_bpf_attached",
)


@pytest.fixture(scope="module")
def kali_evidence():
    lab = os.environ.get("SECRA_LAB_PROFILE", "")
    destination = os.environ.get("SECRA_FENCE_LAB_EVIDENCE", "")
    if os.geteuid() != 0 or lab != "authorized-kali-vm" or not destination:
        pytest.fail("LAB_NOT_RUN: authorized Kali VM, root and private evidence path required")
    if not shutil.which("systemd-run") or not shutil.which("systemctl"):
        pytest.fail("LAB_NOT_RUN: systemd PID 1 tools absent")
    root = Path(destination)
    if not str(root).startswith("/var/lib/secra/evidence/fence-lab/"):
        pytest.fail("LAB_EVIDENCE_PATH_INVALID")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root


@pytest.mark.parametrize("case", CASES)
def test_kali_mandatory_case(case, kali_evidence):
    """A real test harness must supply an independently generated signed/owned
    observation per case. We DO NOT fabricate a PASS or ignore missing cases.
    Each observation records unit properties, commands, exit statuses and
    kernel/pgrep evidence; assertions here check its presence and integrity.
    """
    path = kali_evidence / (case + ".json")
    if not path.is_file() or path.is_symlink():
        pytest.fail("LAB_MISSING_RAW_OBSERVATION: " + case)
    with path.open("rb") as handle:
        data = json.load(handle)
    if (data.get("case") != case or data.get("result") != "pass"
            or not data.get("unit") or not data.get("kernel_observation")
            or not data.get("commands") or not data.get("timestamp_utc")
            or not data.get("witness_sha256")):
        pytest.fail("LAB_OBSERVATION_UNVERIFIED: " + case)
    assert data.get("environment") == "authorized-kali-vm"
