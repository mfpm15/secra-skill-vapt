"""Deny-by-default Kali Tool Gateway (Phase 2).

All externally reachable calls accept typed intent, never argv. The only
reviewed active adapters are fixed Nmap TCP and curl HEAD. Live networking is
intentionally BLOCKED until an independently validated OS egress fence is
provided; no Python allowlist alone is represented as network isolation.
"""
from __future__ import annotations

import hashlib
import os
import re
import selectors
import shutil
import signal
import sqlite3
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from .evidence_vault import EvidenceVault, EvidenceError, _private_dir
from .gateway.fence import SystemdFence, FenceUnverified
from .masking import MemoryVault, guard_mask
from .scope_guard import ScopePolicy, ScopeDenied, authorized_target, enforce_scope_per_connection, fixed_http_url
from .tool_registry import (HTTP_PORTS, TOP20_TCP, StructuredToolIntent, ToolDenied,
                            ToolPolicy, REGISTRY, validate_tool_intent)


class GatewayError(RuntimeError):
    pass


class NetworkFenceUnavailable(GatewayError):
    pass


class ToolCancelled(GatewayError):
    pass


class ToolTimedOut(GatewayError):
    pass


class OutputLimitExceeded(GatewayError):
    pass


@dataclass(frozen=True)
class ToolReceipt:
    run_id: UUID
    engagement_id: UUID
    request_id: UUID
    action_id: str
    exit_code: int
    evidence_sha256: str
    bytes_captured: int
    duration_ms: int
    privacy_status: str = "quarantined"


class DenyNetworkFence:
    """No claim of operating-system enforcement is made by this implementation."""

    def require_ready(self, scope: ScopePolicy) -> None:
        raise NetworkFenceUnavailable("OS_EGRESS_FENCE_NOT_VERIFIED")

    def wrap(self, argv: tuple[str, ...]) -> tuple[str, ...]:
        raise NetworkFenceUnavailable("OS_EGRESS_FENCE_NOT_VERIFIED")


class AuditLedger:
    """Durable sanitized event log and at-most-once request reservation."""

    OUTCOMES = frozenset({"REQUESTED", "VALIDATED", "APPROVAL_BLOCKED",
                          "SCOPE_BLOCKED", "POLICY_BLOCKED", "FENCE_BLOCKED",
                          "EXECUTION_STARTED", "EXECUTION_FAILED", "SEALED",
                          "COMPLETED", "CANCELLED", "TIMEOUT", "OUTPUT_LIMIT",
                          "EVIDENCE_FAILED", "ASSET_BUSY"})

    def __init__(self, root: Path):
        _private_dir(root)
        self.path = root / "tool-audit.sqlite3"
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS requests (
                engagement TEXT NOT NULL, request TEXT NOT NULL,
                run TEXT NOT NULL, PRIMARY KEY(engagement,request))""")
            db.execute("""CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement TEXT NOT NULL, request TEXT NOT NULL,
                run TEXT NOT NULL, action TEXT NOT NULL,
                agent TEXT NOT NULL DEFAULT 'unreviewed', approval_id TEXT,
                outcome TEXT NOT NULL, policy_version TEXT NOT NULL,
                scope_version INTEGER NOT NULL,
                evidence_sha256 TEXT, utc TEXT NOT NULL)""")
            existing = {row[1] for row in db.execute("PRAGMA table_info(events)")}
            if "agent" not in existing:
                db.execute("ALTER TABLE events ADD COLUMN agent TEXT NOT NULL DEFAULT 'unreviewed'")
            if "approval_id" not in existing:
                db.execute("ALTER TABLE events ADD COLUMN approval_id TEXT")
        os.chmod(self.path, 0o600)

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.execute("PRAGMA busy_timeout=15000")
        return db

    def reserve(self, engagement: UUID, request: UUID, run: UUID) -> None:
        try:
            with self._connect() as db:
                db.execute("INSERT INTO requests VALUES (?,?,?)",
                           (str(engagement), str(request), str(run)))
        except sqlite3.IntegrityError as exc:
            raise GatewayError("DUPLICATE_REQUEST_NO_REEXECUTION") from exc
        except sqlite3.Error as exc:
            raise GatewayError("AUDIT_UNAVAILABLE") from exc

    def emit(self, engagement: UUID, request: UUID, run: UUID, action: str,
             outcome: str, scope_version: int, sha256: str | None = None,
             *, agent_id: str = "unreviewed", approval_id: str | None = None) -> None:
        if outcome not in self.OUTCOMES:
            raise GatewayError("AUDIT_OUTCOME_UNKNOWN")
        # Action is a hardcoded canonical value, never arbitrary agent content.
        action = action if action in {"nmap.tcp_top20", "curl.http_head"} else "unreviewed"
        agent_id = (agent_id if isinstance(agent_id, str)
                    and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", agent_id)
                    else "unreviewed")
        if approval_id is not None:
            raise GatewayError("UNREVIEWED_APPROVAL_REFERENCE")
        try:
            with self._connect() as db:
                db.execute("""INSERT INTO events
                    (engagement,request,run,action,agent,approval_id,outcome,policy_version,scope_version,evidence_sha256,utc)
                    VALUES (?,?,?,?,?,?,?,?,?,?,strftime('%Y-%m-%dT%H:%M:%fZ','now'))""",
                           (str(engagement), str(request), str(run), action,
                            agent_id, None, outcome, "phase2-v1", scope_version, sha256))
        except sqlite3.Error as exc:
            raise GatewayError("AUDIT_UNAVAILABLE") from exc

    def events(self, engagement: UUID) -> list[dict]:
        with self._connect() as db:
            db.row_factory = sqlite3.Row
            return [dict(row) for row in db.execute(
                "SELECT * FROM events WHERE engagement=? ORDER BY id", (str(engagement),))]


def _verified_binary(name: str) -> str:
    if name not in {"nmap", "curl"}:
        raise GatewayError("BINARY_NOT_ALLOWED")
    env_name = "SECRA_" + name.upper() + "_SHA256"
    expected = os.getenv(env_name, "").lower()
    if not re.fullmatch(r"[a-f0-9]{64}", expected):
        raise GatewayError("BINARY_DIGEST_NOT_PINNED")
    path = shutil.which(name)
    if not path:
        raise GatewayError("BINARY_NOT_INSTALLED")
    path = os.path.realpath(path)
    with open(path, "rb") as fh:
        h = hashlib.file_digest(fh, "sha256").hexdigest()
    if h != expected:
        raise GatewayError("BINARY_DIGEST_MISMATCH")
    return path


def build_fixed_argv(intent: StructuredToolIntent, target: str,
                     scope: ScopePolicy) -> tuple[str, ...]:
    """Fixed reviewed arguments; only already checked IP and port are dynamic."""
    spec = validate_tool_intent(intent)
    if spec.action_id == "nmap.tcp_top20":
        for port in TOP20_TCP:
            enforce_scope_per_connection(target, target, port, scope)
        return (_verified_binary("nmap"), "-sT", "-Pn", "-n", "-T2", "--max-retries",
                "1", "--host-timeout", "45s", "-p",
                ",".join(str(p) for p in TOP20_TCP), "-oX", "-", target)
    port = intent.parameters["port"]
    url = fixed_http_url(target, port, scope)
    return (_verified_binary("curl"), "-q", "--noproxy", "*",
            "--proto", "=http,https", "--max-redirs", "0",
            "--connect-timeout", "3", "--max-time", "7",
            "--silent", "--show-error", "--head", "--insecure", url)


class ToolGateway:
    def __init__(self, evidence_root: str | Path, *, fence=None):
        self.vault = EvidenceVault(evidence_root)
        self.audit = AuditLedger(self.vault.root)
        self.fence = (fence if fence is not None else
                      SystemdFence() if os.getenv("SECRA_FENCE_BACKEND") == "systemd"
                      else DenyNetworkFence())
        self._active: dict[UUID, int] = {}
        self._asset_locks: dict[str, threading.Lock] = {}
        self._lock = threading.RLock()

    def terminate_process_group(self, run_id: UUID, *, grace: float = 0.25) -> None:
        with self._lock:
            pid = self._active.get(run_id)
        if pid is None:
            return
        if isinstance(self.fence, SystemdFence):
            try:
                result = subprocess.run(
                    self.fence.stop(run_id), check=False, timeout=10,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"})
                if result.returncode != 0:
                    raise GatewayError("SYSTEMD_STOP_FAILED")
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise GatewayError("SYSTEMD_STOP_FAILED") from exc
            return
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        time.sleep(grace)
        # Always signal the GROUP even if the parent already exited.
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def _run_fixed_process(self, argv: tuple[str, ...], intent: StructuredToolIntent,
                           spec: ToolPolicy, run_id: UUID, stop: threading.Event) -> ToolReceipt:
        """Internal executor; caller must have validated argv via reviewed adapter."""
        writer = self.vault.begin(intent.engagement_id, run_id)
        process = None
        started = time.monotonic()
        reason = None
        selector = selectors.DefaultSelector()
        try:
            if stop.is_set():
                raise ToolCancelled("TOOL_CANCELLED")
            # No proxy, ssh-agent, user dotfiles, locale-dependent shell or stdin.
            environment = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent",
                           "LC_ALL": "C", "LANG": "C"}
            self.audit.emit(intent.engagement_id, intent.request_id, run_id,
                            spec.action_id, "EXECUTION_STARTED", 1, agent_id=intent.agent_id)
            process = subprocess.Popen(argv, shell=False, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=True, cwd="/", env=environment)
            with self._lock:
                self._active[run_id] = process.pid
            for stream_name, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, stream_name)
            while selector.get_map() or process.poll() is None:
                if stop.is_set():
                    raise ToolCancelled("TOOL_CANCELLED")
                if time.monotonic() - started >= spec.timeout_seconds:
                    raise ToolTimedOut("TOOL_TIMEOUT")
                for key, _ in selector.select(timeout=0.1):
                    raw = os.read(key.fileobj.fileno(), 65536)
                    if not raw:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    limit = (spec.max_stdout_bytes if key.data == "stdout"
                             else spec.max_stderr_bytes)
                    if writer.totals[key.data] + len(raw) > limit:
                        raise OutputLimitExceeded("OUTPUT_QUOTA_EXCEEDED")
                    # Critical ordering: authenticated encryption + fsync before any parser.
                    writer.append(key.data, raw)
            code = process.wait(timeout=1)
            digest, count = writer.finish()
            self.audit.emit(intent.engagement_id, intent.request_id, run_id,
                            spec.action_id, "SEALED", 1, digest, agent_id=intent.agent_id)
            self.audit.emit(intent.engagement_id, intent.request_id, run_id,
                            spec.action_id, "COMPLETED" if code == 0 else "EXECUTION_FAILED",
                            1, digest, agent_id=intent.agent_id)
            return ToolReceipt(run_id, intent.engagement_id, intent.request_id,
                               spec.action_id, code, digest, count,
                               int((time.monotonic() - started) * 1000))
        except BaseException as exc:
            if process is not None:
                self.terminate_process_group(run_id)
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.terminate_process_group(run_id, grace=0)
            writer.abort()
            outcome = ("CANCELLED" if isinstance(exc, ToolCancelled) else
                       "TIMEOUT" if isinstance(exc, ToolTimedOut) else
                       "OUTPUT_LIMIT" if isinstance(exc, OutputLimitExceeded) else
                       "EVIDENCE_FAILED" if isinstance(exc, (EvidenceError, OSError)) else
                       "EXECUTION_FAILED")
            self.audit.emit(intent.engagement_id, intent.request_id, run_id,
                            spec.action_id, outcome, 1, agent_id=intent.agent_id)
            raise
        finally:
            selector.close()
            with self._lock:
                self._active.pop(run_id, None)
            if process is not None:
                for pipe in (process.stdout, process.stderr):
                    if pipe is not None and not pipe.closed:
                        pipe.close()

    def execute(self, intent: StructuredToolIntent, target: str, scope_text: str,
                stop: threading.Event, *, vault=None) -> ToolReceipt:
        if not isinstance(intent, StructuredToolIntent):
            raise ToolDenied("INTENT_TYPE_INVALID")
        run_id = uuid.uuid4()
        self.audit.reserve(intent.engagement_id, intent.request_id, run_id)
        self.audit.emit(intent.engagement_id, intent.request_id, run_id,
                        intent.action_id, "REQUESTED", 1, agent_id=intent.agent_id)
        try:
            spec = validate_tool_intent(intent)
        except ToolDenied:
            decision = ("APPROVAL_BLOCKED" if intent.action_id in REGISTRY
                        and REGISTRY[intent.action_id].risk == "R3"
                        else "POLICY_BLOCKED")
            self.audit.emit(intent.engagement_id, intent.request_id, run_id,
                            intent.action_id, decision, 1, agent_id=intent.agent_id)
            raise
        try:
            ports = TOP20_TCP if intent.action_id == "nmap.tcp_top20" else (intent.parameters["port"],)
            policy = ScopePolicy.from_engagement(target, scope_text, ports)
            resolved = authorized_target(intent.target_ref, policy, vault=vault)
            for port in ports:
                enforce_scope_per_connection(resolved, resolved, port, policy)
            self.audit.emit(intent.engagement_id, intent.request_id, run_id,
                            intent.action_id, "VALIDATED", policy.version, agent_id=intent.agent_id)
        except ScopeDenied:
            self.audit.emit(intent.engagement_id, intent.request_id, run_id,
                            intent.action_id, "SCOPE_BLOCKED", 1, agent_id=intent.agent_id)
            raise
        try:
            # No network operation until a *real* OS egress fence implementation
            # can prove protection. A checkbox or env flag does not authorize it.
            self.fence.require_ready(policy)
            argv = build_fixed_argv(intent, resolved, policy)
            if isinstance(self.fence, SystemdFence):
                argv = self.fence.wrap(argv, intent.engagement_id, run_id, policy)
            else:
                argv = self.fence.wrap(argv)
        except (GatewayError, FenceUnverified, OSError):
            self.audit.emit(intent.engagement_id, intent.request_id, run_id,
                            intent.action_id, "FENCE_BLOCKED", policy.version, agent_id=intent.agent_id)
            raise
        asset_key = str(intent.engagement_id) + ":" + resolved
        with self._lock:
            if len(self._asset_locks) >= 128 and asset_key not in self._asset_locks:
                raise GatewayError("ASSET_LOCK_CAPACITY_EXCEEDED")
            asset_lock = self._asset_locks.setdefault(asset_key, threading.Lock())
        if not asset_lock.acquire(blocking=False):
            self.audit.emit(intent.engagement_id, intent.request_id, run_id,
                            spec.action_id, "ASSET_BUSY", policy.version, agent_id=intent.agent_id)
            raise GatewayError("ASSET_BUSY")
        try:
            return self._run_fixed_process(argv, intent, spec, run_id, stop)
        finally:
            asset_lock.release()

    def parse_nmap_receipt(self, receipt: ToolReceipt) -> list[dict]:
        if receipt.action_id != "nmap.tcp_top20" or receipt.exit_code != 0:
            raise GatewayError("NMAP_RECEIPT_INVALID")
        raw = self.vault.verify_and_read(receipt.engagement_id, receipt.run_id)["stdout"]
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            raise GatewayError("NMAP_XML_INVALID") from exc
        names = {80: "http", 443: "https", 22: "ssh", 25: "smtp", 21: "ftp",
                 53: "domain", 3306: "mysql", 139: "netbios-ssn",
                 445: "microsoft-ds", 3389: "ms-wbt-server", 8080: "http"}
        found = []
        for port_node in root.findall(".//port"):
            state = port_node.find("state")
            try:
                port = int(port_node.get("portid", "0"))
            except ValueError:
                continue
            if (state is not None and state.get("state") == "open" and
                    port in TOP20_TCP and port_node.get("protocol") == "tcp"):
                found.append({"port": port, "service": names.get(port, "unknown")})
        return found

    def parse_http_receipt(self, receipt: ToolReceipt) -> str:
        if receipt.action_id != "curl.http_head" or receipt.exit_code != 0:
            return "unknown"
        raw = self.vault.verify_and_read(receipt.engagement_id, receipt.run_id)["stdout"]
        first = raw.split(b"\n", 1)[0].strip()
        match = re.fullmatch(rb"HTTP/\d(?:\.\d)? ([1-5][0-9]{2})(?: [\x20-\x7e]{0,100})?", first)
        return match.group(1).decode("ascii") if match else "unknown"

    @staticmethod
    def masked_service_summary(receipt: ToolReceipt, count: int) -> str:
        if not isinstance(count, int) or not 0 <= count <= 20:
            raise GatewayError("SUMMARY_INVALID")
        safe = "Tool completed with " + str(count) + " observed service ports."
        masked, _ = guard_mask(safe, vault=MemoryVault())
        return masked
