"""Root-controlled systemd cgroup fence, inactive until real lab attestation.

systemd IPAddressDeny/Allow are AF_INET+AF_INET6 address filters, not port filters.
--scope inherits caller execution context; sandbox settings may not be applied.
Only IP literals are currently active. DNS/hardcoded-resolver tools denied.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from app.scope_guard import ScopePolicy

WRAPPER = "/usr/local/sbin/secra-run"
ATTESTATION = "/etc/secra/fence-attestation.json"
REQUIRED = frozenset({
    "allow_in_scope", "deny_out_of_scope", "deny_ipv6",
    "deny_ipv4_mapped", "deny_dns_rebinding", "deny_cname_outside_scope",
    "deny_hardcoded_resolver", "deny_proxy", "kill_child_grandchild",
    "timeout_zero_survivors", "enforce_memory_cpu_tasks",
    "verify_exec_sandbox_properties", "verify_cgroup_bpf_attached",
})


class FenceUnverified(RuntimeError):
    pass


def scope_allowlist(scope: ScopePolicy) -> tuple[str, ...]:
    """Permit only the exact pinned target, not the whole authorized CIDR."""
    target = ipaddress.ip_address(scope.target)
    if target.version != 4 or not any(target in n for n in scope.networks):
        raise FenceUnverified("SCOPE_NOT_PINNED")
    return (str(target) + "/32",)


def read_attestation(path: str | Path = ATTESTATION) -> dict:
    """Attestation is a root-owned deployment prerequisite, not lab proof."""
    p = Path(path)
    if p.is_symlink():
        raise FenceUnverified("ATTESTATION_SYMLINK")
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            st = os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0
                    or (stat.S_IMODE(st.st_mode) & 0o022) or st.st_size > 65536):
                raise FenceUnverified("ATTESTATION_PERMISSIONS")
            data = os.read(fd, 65537)
        finally:
            os.close(fd)
        info = json.loads(data)
    except (OSError, ValueError, TypeError) as exc:
        raise FenceUnverified("ATTESTATION_UNAVAILABLE") from exc
    if (not isinstance(info, dict) or info.get("schema") != 1
            or info.get("result") != "pass"
            or not isinstance(info.get("evidence_directory"), str)
            or not info["evidence_directory"].startswith("/var/lib/secra/evidence/fence-lab/")
            or not isinstance(info.get("passed_tests"), list)
            or not REQUIRED.issubset(set(info["passed_tests"]))):
        raise FenceUnverified("ATTESTATION_INCOMPLETE")
    return info


@dataclass(frozen=True)
class SystemdFence:
    """Sudoers permits only the root-owned helper, never a tool binary."""
    wrapper: str = WRAPPER
    attestation: str = ATTESTATION

    def require_ready(self, scope: ScopePolicy) -> None:
        scope_allowlist(scope)
        read_attestation(self.attestation)
        if self.wrapper != WRAPPER:
            raise FenceUnverified("WRAPPER_PATH_REJECTED")
        p = Path(self.wrapper)
        if p.is_symlink():
            raise FenceUnverified("WRAPPER_SYMLINK")
        try:
            st = p.stat()
        except OSError as exc:
            raise FenceUnverified("WRAPPER_NOT_INSTALLED") from exc
        if st.st_uid != 0 or (stat.S_IMODE(st.st_mode) & 0o022) or not p.is_file():
            raise FenceUnverified("WRAPPER_NOT_ROOT_CONTROLLED")

    def wrap(self, argv: tuple[str, ...], engagement_id: UUID,
             run_id: UUID, scope: ScopePolicy) -> tuple[str, ...]:
        self.require_ready(scope)
        if not argv or argv[-1] != scope.target or not isinstance(engagement_id, UUID):
            raise FenceUnverified("SCOPE_COMMAND_MISMATCH")
        return ("sudo", "-n", self.wrapper, "exec", "--engagement", str(engagement_id),
                "--run", str(run_id), "--", *argv)

    def stop(self, run_id: UUID) -> tuple[str, ...]:
        if not isinstance(run_id, UUID):
            raise FenceUnverified("RUN_ID_INVALID")
        return ("sudo", "-n", self.wrapper, "stop", "--run", str(run_id))


def validate_dns_answers(hostname: str, cname_chain: tuple[str, ...],
                         addresses: tuple[str, ...], scope: ScopePolicy) -> tuple[str, ...]:
    """Offline rejector; live DNS is disabled until port-aware kernel fence exists."""
    if not hostname or not re.fullmatch(r"[a-z0-9.-]{1,253}", hostname):
        raise FenceUnverified("DNS_HOST_INVALID")
    if not addresses or len(addresses) > 16 or len(cname_chain) > 16:
        raise FenceUnverified("DNS_ANSWER_INVALID")
    if cname_chain or hostname != scope.target:
        raise FenceUnverified("DNS_CNAME_OR_DOMAIN_NOT_AUTHORIZED")
    pinned = scope_allowlist(scope)[0].split("/")[0]
    for raw in addresses:
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise FenceUnverified("DNS_ANSWER_INVALID") from exc
        if address.version != 4 or str(address) != pinned:
            raise FenceUnverified("DNS_REBIND_OUT_OF_SCOPE")
    return (pinned,)
