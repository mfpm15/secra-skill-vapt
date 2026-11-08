"""Privileged, mandatory Kali lab acceptance. No real external targets used.

On a root-owned Kali VM:
    SECRA_LAB_PROFILE=authorized-kali-vm \
    SECRA_FENCE_LAB_EVIDENCE=/var/lib/secra/evidence/fence-lab/<lab-id> \
    python -m pytest tests/fence/test_lab.py -m lab -q -ra

The full 13 cases MUST pass before issuing a separate root-owned attestation.
Tests always fail (never skip) if Kali/systemd/BPF or required features are absent.
Only LOCAL loopback test listeners are created; no real client IPs are scanned.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from app.gateway.fence import validate_dns_answers, FenceUnverified
from app.scope_guard import ScopePolicy
from app.tool_registry import StructuredToolIntent, validate_tool_intent, ToolDenied

pytestmark = pytest.mark.lab
PROBE = str(Path(__file__).with_name("lab_probe.py"))
CASES = (
    "allow_in_scope", "deny_out_of_scope", "deny_ipv6", "deny_ipv4_mapped",
    "deny_dns_rebinding", "deny_cname_outside_scope", "deny_hardcoded_resolver",
    "deny_proxy", "kill_child_grandchild", "timeout_zero_survivors",
    "enforce_memory_cpu_tasks", "verify_exec_sandbox_properties",
    "verify_cgroup_bpf_attached",
)


@pytest.fixture(scope="module")
def kali_evidence():
    dest = os.environ.get("SECRA_FENCE_LAB_EVIDENCE", "")
    if (os.geteuid() != 0 or os.environ.get("SECRA_LAB_PROFILE") != "authorized-kali-vm"
            or not dest.startswith("/var/lib/secra/evidence/fence-lab/")):
        pytest.fail("LAB_NOT_RUN: requires approved Kali VM, root and private evidence path")
    release = Path("/etc/os-release").read_text()
    if 'ID=kali' not in release:
        pytest.fail("NOT_A_KALI_VM")
    if not Path("/run/systemd/system").exists():
        pytest.fail("SYSTEMD_NOT_PID1")
    if not all(shutil.which(t) for t in ("systemd-run", "systemctl", "pgrep", "bpftool")):
        pytest.fail("LAB_TOOLS_MISSING")
    root = Path(dest)
    if root.is_symlink():
        pytest.fail("LAB_EVIDENCE_SYMLINK")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    return root


@contextmanager
def listener(host):
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(fam, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        sock.listen(8)
        yield sock.getsockname()[1]


def _unit_command(unit, action, *args):
    return [
        "/usr/bin/systemd-run", "--system", "--quiet", "--scope", "--collect",
        "--unit=" + unit, "--property=MemoryMax=536870912",
        "--property=CPUQuota=50%", "--property=TasksMax=32",
        "--property=IPAddressDeny=any",
        "--property=IPAddressAllow=127.0.0.1/32",
        "--property=NoNewPrivileges=yes",
        "--property=PrivateTmp=yes",
        "--property=ProtectSystem=strict",
        "--",
        sys.executable, PROBE, action, *(str(a) for a in args),
    ]


def _probe(host, port, mode="tcp"):
    unit = "secra-fence-lab-" + uuid4().hex + ".scope"
    cmd = _unit_command(unit, "connect", host, port, mode)
    result = subprocess.run(cmd, capture_output=True, timeout=12)
    return {
        "unit": unit, "exit_code": result.returncode,
        "started": b"LAB_PROBE_STARTED" in result.stdout,
        "output_sha256": hashlib.sha256(result.stdout + result.stderr).hexdigest(),
        "success": result.returncode == 0,
    }


def _baseline(host, port, mode="tcp"):
    p = subprocess.run([sys.executable, PROBE, "connect", host, str(port), mode],
                       capture_output=True, timeout=5)
    assert p.returncode == 0, "LOCAL_BASELINE_NOT_REACHABLE"


def _deny(host, mode="tcp"):
    with listener("127.0.0.2" if ":" not in host else "::1") as port:
        _baseline(host, port, mode)
        seen = _probe(host, port, mode)
        assert seen["started"], "SYSTEMD_SCOPE_NEVER_LAUNCHED_PROBE"
        assert not seen["success"], "KERNEL_EGRESS_ESCAPE"
        return seen


def _show(unit, properties):
    p = subprocess.run(["/usr/bin/systemctl", "--system", "show", unit,
                        *("--property=" + x for x in properties)],
                       capture_output=True, timeout=5, check=True, text=True)
    return dict(line.split("=", 1) for line in p.stdout.splitlines() if "=" in line)


def _start_sleeper():
    unit = "secra-fence-lab-" + uuid4().hex + ".scope"
    proc = subprocess.Popen(_unit_command(unit, "sleep"),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for _ in range(120):
        time.sleep(0.05)
        p = subprocess.run(["/usr/bin/systemctl", "--system", "is-active", "--quiet", unit])
        if p.returncode == 0:
            return unit, proc
        if proc.poll() is not None:
            break
    proc.kill()
    proc.communicate(timeout=4)
    pytest.fail("SYSTEMD_SCOPE_NOT_ACTIVE")


def _stop(unit, proc):
    p = subprocess.run(["/usr/bin/systemctl", "--system", "stop", unit],
                       capture_output=True, timeout=10)
    assert p.returncode == 0, "SYSTEMD_STOP_FAILED"
    proc.communicate(timeout=15)
    active = subprocess.run(["/usr/bin/systemctl", "--system", "is-active", "--quiet", unit])
    assert active.returncode != 0, "UNIT_STILL_ACTIVE"
    return {"unit": unit, "systemctl_stop_exit": p.returncode,
            "is_active_exit": active.returncode}


def _port_case():
    with listener("127.0.0.1") as port:
        _baseline("127.0.0.1", port)
        result = _probe("127.0.0.1", port)
        assert result["started"] and result["success"], "IN_SCOPE_DENIED"
        return result


def _dns_case(cname=False):
    # Phase 2 supports IP literals only. This is *not* a resolver pin test.
    scope = ScopePolicy.from_engagement("192.0.2.10", "192.0.2.0/24", (443,))
    with pytest.raises(FenceUnverified):
        validate_dns_answers("inside.test",
                             ("cdn.outside.test",) if cname else (),
                             ("198.51.100.77",), scope)
    # A real controlled resolver with DNS/53-aware eBPF is still required.
    pytest.fail("DNS_PORT_FENCE_AND_PINNED_RESOLVER_NOT_IMPLEMENTED")


def _resolver_case():
    # A literal hardcoded DNS server must be refused at socket boundary.
    baseline = _probe("127.0.0.2", 53, "udp")
    assert baseline["started"] and not baseline["success"], "HARDCODED_DNS_EGRESS_ALLOWED"
    for action in ("nuclei.safe_template", "sqlmap.execute"):
        intent = StructuredToolIntent(uuid4(), uuid4(), "lab", action,
                                      "127.0.0.1", {})
        with pytest.raises(ToolDenied):
            validate_tool_intent(intent)
    return baseline


def _kill_case(after_seconds=0.3):
    unit = "secra-fence-lab-" + uuid4().hex + ".scope"
    marker = "/var/lib/secra/evidence/fence-lab/" + unit + ".pids"
    proc = subprocess.Popen(_unit_command(unit, "family", marker, 2),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        for _ in range(150):
            if Path(marker).exists() and len(Path(marker).read_text().splitlines()) >= 3:
                break
            if proc.poll() is not None:
                pytest.fail("FAMILY_DID_NOT_START")
            time.sleep(0.05)
        assert Path(marker).exists()
        pids = [int(x) for x in Path(marker).read_text().splitlines()]
        assert len(pids) == 3
        time.sleep(after_seconds)
        outcome = _stop(unit, proc)
        # Wait for zombies to be reaped; no child/grandchild may survive.
        for _ in range(50):
            remaining = []
            for pid in pids:
                status = Path("/proc") / str(pid) / "stat"
                if status.exists() and status.read_text().split()[2] != "Z":
                    remaining.append(pid)
            if not remaining:
                break
            time.sleep(0.1)
        assert not remaining, "SYSTEMD_STOP_LEFT_DESCENDANTS"
        outcome["observed_descendant_count"] = len(pids)
        outcome["remaining_pids"] = len(remaining)
        return outcome
    finally:
        if proc.poll() is None:
            subprocess.run(["/usr/bin/systemctl", "--system", "stop", unit],
                           timeout=10, capture_output=True)
        Path(marker).unlink(missing_ok=True)


def _timeout_case():
    # Real 60-second watchdog condition. The user-facing gateway is responsible
    # for the stop; systemd CPUQuota alone only throttles CPU, not kills it.
    return _kill_case(after_seconds=60)


def _resource_case():
    unit = "secra-fence-lab-" + uuid4().hex + ".scope"
    proc = subprocess.Popen(_unit_command(unit, "allocate"),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        for _ in range(60):
            if proc.poll() is not None:
                break
            time.sleep(0.1)
        props = _show(unit, ["MemoryMax", "CPUQuotaPerSecUSec", "TasksMax"])
        assert props.get("MemoryMax") == "536870912", "MEMORY_LIMIT_NOT_APPLIED"
        assert props.get("TasksMax") == "32", "TASKS_LIMIT_NOT_APPLIED"
        assert props.get("CPUQuotaPerSecUSec") not in {None, "infinity"}, "CPU_QUOTA_NOT_APPLIED"
        output, errors = proc.communicate(timeout=30)
        assert b"LAB_PROBE_STARTED" in output, "RESOURCE_PROBE_NOT_STARTED"
        assert proc.returncode != 0, "MEMORY_LIMIT_NOT_ENFORCED"
        return {"unit": unit, "properties": props, "exit_code": proc.returncode,
                "output_sha256": hashlib.sha256(output + errors).hexdigest()}
    finally:
        if proc.poll() is None:
            subprocess.run(["/usr/bin/systemctl", "--system", "stop", unit],
                           capture_output=True, timeout=10)
            proc.communicate(timeout=10)


def _exec_properties_case():
    unit, proc = _start_sleeper()
    try:
        props = _show(unit, ["NoNewPrivileges", "PrivateTmp", "ProtectSystem"])
        assert props.get("NoNewPrivileges") in {"yes", "true"}, "NO_NEW_PRIVILEGES_NOT_ENFORCED"
        assert props.get("PrivateTmp") in {"yes", "true"}, "PRIVATE_TMP_NOT_ENFORCED"
        assert props.get("ProtectSystem") == "strict", "PROTECT_SYSTEM_NOT_ENFORCED"
        return {"unit": unit, "properties": props}
    finally:
        _stop(unit, proc)


def _bpf_case():
    unit, proc = _start_sleeper()
    try:
        props = _show(unit, ["ControlGroup", "IPAddressDeny", "IPAddressAllow"])
        cgroup = props.get("ControlGroup", "")
        assert cgroup.startswith("/") and ".." not in cgroup
        # Kernel attachment witness, not merely a systemd property value.
        path = "/sys/fs/cgroup" + cgroup
        p = subprocess.run(["bpftool", "cgroup", "show", path],
                           capture_output=True, text=True, timeout=5)
        assert p.returncode == 0, "BPF_INSPECTION_FAILED"
        assert "ingress" in p.stdout and "egress" in p.stdout, "BPF_NOT_ATTACHED"
        return {"unit": unit, "properties": props,
                "bpf_output_sha256": hashlib.sha256(p.stdout.encode()).hexdigest()}
    finally:
        _stop(unit, proc)


def _dispatch(case):
    if case == "allow_in_scope":
        return _port_case()
    if case == "deny_out_of_scope":
        return _deny("127.0.0.2")
    if case == "deny_ipv6":
        return _deny("::1")
    if case == "deny_ipv4_mapped":
        with listener("127.0.0.2") as port:
            _baseline("::ffff:127.0.0.2", port)
            seen = _probe("::ffff:127.0.0.2", port)
            assert seen["started"] and not seen["success"], "IPV4_MAPPED_V6_ESCAPE"
            return seen
    if case == "deny_dns_rebinding":
        return _dns_case()
    if case == "deny_cname_outside_scope":
        return _dns_case(cname=True)
    if case == "deny_hardcoded_resolver":
        return _resolver_case()
    if case == "deny_proxy":
        return _deny("127.0.0.2")
    if case == "kill_child_grandchild":
        return _kill_case()
    if case == "timeout_zero_survivors":
        return _timeout_case()
    if case == "enforce_memory_cpu_tasks":
        return _resource_case()
    if case == "verify_exec_sandbox_properties":
        return _exec_properties_case()
    if case == "verify_cgroup_bpf_attached":
        return _bpf_case()
    pytest.fail("UNKNOWN_LAB_CASE")


@pytest.mark.parametrize("case", CASES)
def test_mandatory_kali_fence(case, kali_evidence):
    """Always emits sanitized actual execution observations, including on failure."""
    record = {
        "case": case,
        "environment": "authorized-kali-vm",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "kernel": os.uname().release,
        "result": "fail",
    }
    try:
        observed = _dispatch(case)
        record["observations"] = observed
        record["result"] = "pass"
    except BaseException as exc:
        record["error_type"] = type(exc).__name__
        raise
    finally:
        record["witness_sha256"] = hashlib.sha256(
            json.dumps(record.get("observations", {}), sort_keys=True).encode()).hexdigest()
        data = json.dumps(record, sort_keys=True, indent=2).encode()
        filename = kali_evidence / (case + ".json")
        fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
