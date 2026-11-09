"""Read-only Kali live execution prerequisites, NEVER a live authorization grant."""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
from pathlib import Path

from app.gateway.fence import WRAPPER, ATTESTATION, read_attestation, FenceUnverified
from app.loop.store import TaskStore

DIGEST = re.compile(r"^[0-9a-f]{64}$")
BINARIES = ("nmap", "curl")


def check_live_prerequisites(store: TaskStore, task_id: str) -> dict:
    task = store.require(task_id)
    checks = {}
    checks["task_is_live"] = task["mode"] == "live"
    checks["backend_requested"] = os.environ.get("SECRA_FENCE_BACKEND") == "systemd"
    checks["systemd_run_present"] = shutil.which("systemd-run") is not None
    checks["wrapper_root_controlled"] = False
    wrapper = Path(WRAPPER)
    try:
        if wrapper.is_file() and not wrapper.is_symlink():
            info = wrapper.stat()
            checks["wrapper_root_controlled"] = (
                info.st_uid == 0 and not (stat.S_IMODE(info.st_mode) & 0o022)
            )
    except OSError:
        pass

    try:
        read_attestation(ATTESTATION)
        checks["root_owned_attestation_metadata_present"] = True
    except (FenceUnverified, OSError):
        checks["root_owned_attestation_metadata_present"] = False

    for name in BINARIES:
        path = shutil.which(name)
        environment = os.environ.get("SECRA_" + name.upper() + "_SHA256", "").lower()
        checks[name + "_present"] = path is not None
        checks[name + "_digest_pinned"] = bool(DIGEST.fullmatch(environment))
        checks[name + "_digest_matches"] = False
        if path and DIGEST.fullmatch(environment):
            try:
                with open(Path(path).resolve(), "rb") as stream:
                    checks[name + "_digest_matches"] = (
                        hashlib.file_digest(stream, "sha256").hexdigest() == environment
                    )
            except OSError:
                pass

    metadata_pass = all(checks.values())
    return {
        "schema": "secra-kali-live-preflight-v1",
        "asset": "ASSET_001",
        "task_id": task_id,
        "prerequisites_detected": metadata_pass,
        # This static check cannot prove active BPF attachment, scoped traffic
        # enforcement, DNS leak resistance or child/grandchild cleanup.
        "live_execution_independently_verified": False,
        "network_tests_performed": 0,
        "kernel_lab_proof_required": True,
        "checks": checks,
        "note": (
            "Static prerequisites are NOT a substitute for the privileged "
            "Kali fence lab suite, root-owned approval, scope and policy checks."
        ),
    }
