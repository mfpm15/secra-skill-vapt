"""Fail-closed release gate: reject missing/stale/incomplete Kali fence evidence.

Use after the real Kali VM suite, never as a replacement for it:
  python -m tests.fence.verify_lab /var/lib/secra/evidence/fence-lab/<run-id>

The reviewer must independently inspect command output and kernel witnesses.
This gate does NOT issue an attestation on its own.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path

CASES = (
    "allow_in_scope", "deny_out_of_scope", "deny_ipv6", "deny_ipv4_mapped",
    "deny_dns_rebinding", "deny_cname_outside_scope", "deny_hardcoded_resolver",
    "deny_proxy", "kill_child_grandchild", "timeout_zero_survivors",
    "enforce_memory_cpu_tasks", "verify_exec_sandbox_properties",
    "verify_cgroup_bpf_attached",
)


class LabGateError(RuntimeError):
    pass


def verify_lab_evidence(root: str | Path) -> dict:
    root = Path(root)
    if (not str(root).startswith("/var/lib/secra/evidence/fence-lab/")
            or root.is_symlink() or not root.is_dir()):
        raise LabGateError("LAB_DIRECTORY_INVALID")
    st = root.stat()
    if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o077:
        raise LabGateError("LAB_DIRECTORY_UNTRUSTED")
    details = {}
    kernels = set()
    for name in CASES:
        path = root / (name + ".json")
        if path.is_symlink() or not path.is_file():
            raise LabGateError("LAB_MISSING_CASE:" + name)
        info = path.stat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > 65536:
            raise LabGateError("LAB_FILE_UNTRUSTED:" + name)
        try:
            payload = json.loads(path.read_bytes())
        except (OSError, ValueError) as exc:
            raise LabGateError("LAB_CORRUPT_RECORD:" + name) from exc
        observed = payload.get("observations")
        digest = hashlib.sha256(json.dumps(observed, sort_keys=True).encode()).hexdigest()
        if (payload.get("result") != "pass" or payload.get("case") != name
                or payload.get("environment") != "authorized-kali-vm"
                or not isinstance(observed, dict) or not observed
                or payload.get("witness_sha256") != digest
                or not payload.get("timestamp_utc")
                or not payload.get("kernel")):
            raise LabGateError("LAB_INVALID_WITNESS:" + name)
        kernels.add(payload["kernel"])
        if name in {"deny_out_of_scope", "deny_ipv6", "deny_ipv4_mapped",
                    "deny_hardcoded_resolver", "deny_proxy"}:
            if observed.get("success") is not False or observed.get("started") is not True:
                raise LabGateError("LAB_DENIAL_NOT_PROVED:" + name)
        if name == "allow_in_scope":
            if observed.get("success") is not True or observed.get("started") is not True:
                raise LabGateError("LAB_ALLOWED_PATH_NOT_PROVED")
        if name in {"kill_child_grandchild", "timeout_zero_survivors"}:
            if observed.get("remaining_pids") != 0 or observed.get("observed_descendant_count") != 3:
                raise LabGateError("LAB_PROCESS_SURVIVORS:" + name)
        if name == "verify_cgroup_bpf_attached" and not observed.get("bpf_output_sha256"):
            raise LabGateError("LAB_BPF_MISSING")
        details[name] = digest
    if len(kernels) != 1:
        raise LabGateError("LAB_KERNEL_MISMATCH")
    return {"result": "pass", "passed_tests": sorted(details),
            "case_count": len(details), "kernel": next(iter(kernels))}


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("LAB_GATE_FAILED: provide explicit evidence directory", file=sys.stderr)
        return 2
    try:
        result = verify_lab_evidence(argv[0])
    except LabGateError as exc:
        print("LAB_GATE_FAILED: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
