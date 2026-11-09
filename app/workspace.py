"""Private, idempotent per-engagement workspace and evidence manifests.

Workspaces never include target IP, CIDR, credentials or raw model prompts by
default. Their only identifier is the local, authorized TaskStore UUID.
No shell commands, target connections, or archive-source deletions.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shutil
import stat
import tempfile
from collections import defaultdict
from pathlib import Path
from uuid import UUID

DIRS = (
    "00-authorization", "00-preflight", "01-recon",
    "02-scripts", "03-evidence", "03-evidence/network",
    "03-evidence/web", "03-evidence/api", "03-evidence/findings",
    "03-evidence/screenshots", "03-evidence/cleanup",
    "04-reports", "05-memory", "06-ledger", "07-follow-up",
)
STAGES = (
    "intake", "preflight", "recon", "mapping", "hypothesis",
    "testing", "validation", "evidence", "reporting",
    "cleanup", "retrospective", "archive", "follow-up",
)
EVENTS = frozenset({"started", "completed", "blocked"})
MANIFEST = "06-ledger/manifest.json"
MAX_FILES = 12000
CHUNK = 1024 * 1024


class WorkspaceError(ValueError):
    pass


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def task_id_value(raw: str) -> str:
    try:
        value = str(UUID(raw))
    except (ValueError, TypeError, AttributeError) as exc:
        raise WorkspaceError("WORKSPACE_TASK_ID_INVALID") from exc
    if raw != value:
        raise WorkspaceError("WORKSPACE_TASK_ID_NONCANONICAL")
    return value


def _safe_dir(directory: Path) -> None:
    if directory.is_symlink():
        raise WorkspaceError("WORKSPACE_SYMLINK_DIR")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink() or not directory.is_dir():
        raise WorkspaceError("WORKSPACE_UNSAFE_DIR")
    os.chmod(directory, 0o700)


def _write_new(path: Path, text: str) -> bool:
    if path.is_symlink():
        raise WorkspaceError("WORKSPACE_SYMLINK_FILE")
    if path.exists():
        if not path.is_file():
            raise WorkspaceError("WORKSPACE_NOT_REGULAR_FILE")
        return False  # Never overwrite an operator-managed note.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    return True


def _atomic_write(path: Path, text: str) -> None:
    if path.is_symlink():
        raise WorkspaceError("WORKSPACE_SYMLINK_OUTPUT")
    fd, temp = tempfile.mkstemp(prefix=".secra-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, 0o600)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


class WorkspaceManager:
    def __init__(self, root: str | Path):
        self.root = Path(root)

    def directory(self, tid: str) -> Path:
        return self.root / task_id_value(tid)

    def initialize(self, tid: str) -> Path:
        """Create directories and starter files once; safe to re-run."""
        tid = task_id_value(tid)
        _safe_dir(self.root)
        directory = self.directory(tid)
        _safe_dir(directory)
        marker = directory / "engagement.json"
        if marker.exists():
            if marker.is_symlink():
                raise WorkspaceError("WORKSPACE_MARKER_SYMLINK")
            try:
                previous = json.loads(marker.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise WorkspaceError("WORKSPACE_MARKER_INVALID") from exc
            if previous != {"schema": 1, "task_id": tid, "asset": "ASSET_001"}:
                raise WorkspaceError("WORKSPACE_MARKER_CONFLICT")
        for folder in DIRS:
            _safe_dir(directory / folder)
        _write_new(marker, json.dumps(
            {"schema": 1, "task_id": tid, "asset": "ASSET_001"},
            indent=2) + "\n")
        _write_new(directory / "README.md", (
            "# SECRA private engagement workspace\n\n"
            "Task identity: " + tid + " (no customer IP is written here).\n"
            "The authorized scope remains inside local TaskStore.\n"
            "Do not put credentials, live access tokens, or raw customer data in "
            "Markdown or JSON metadata; use the encrypted SECRA evidence vault.\n"
            "The ledger and findings are distinct: a tool success is not a verified finding.\n"
            "Do not execute scripts merely because they are in 02-scripts/.\n"
        ))
        _write_new(directory / "05-memory/state.json", json.dumps({
            "schema": 1, "asset": "ASSET_001", "phase": "intake",
            "objective": None, "verified_facts": [], "open_questions": [],
            "next_action": None, "cleanup_pending": [],
        }, indent=2) + "\n")
        _write_new(directory / "05-memory/chain.json", json.dumps({
            "schema": 1, "verified_edges": [], "unverified_hypotheses": [],
            "note": "Analyst-supplied evidence references only; no auto-confirmation."
        }, indent=2) + "\n")
        for item in ("05-memory/leads.jsonl", "05-memory/negatives.jsonl",
                     "06-ledger/phases.jsonl"):
            _write_new(directory / item, "")
        _write_new(directory / "03-evidence/cleanup/CHECKLIST.md",
            "# Cleanup verification\n\n"
            "- [ ] Identify every target-side change with operator approval\n"
            "- [ ] Record before/after evidence references\n"
            "- [ ] Validate restoration and list unresolved residual changes\n"
            "- [ ] Obtain operator sign-off\n")
        _write_new(directory / "07-follow-up/REGISTER.md",
            "# Follow-up register\n\n"
            "| Item | Owner | Due (UTC) | State | Closure evidence |\n"
            "|---|---|---|---|---|\n")
        phases = directory / "06-ledger/phases.jsonl"
        if not phases.read_bytes():
            self.record_phase(tid, "intake", "started")
        return directory

    def require(self, tid: str) -> Path:
        directory = self.directory(tid)
        marker = directory / "engagement.json"
        if self.root.is_symlink() or directory.is_symlink() or marker.is_symlink():
            raise WorkspaceError("WORKSPACE_SYMLINK")
        if not directory.is_dir() or not marker.is_file():
            raise WorkspaceError("WORKSPACE_MISSING")
        try:
            record = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise WorkspaceError("WORKSPACE_MARKER_INVALID") from exc
        if record != {"schema": 1, "task_id": tid, "asset": "ASSET_001"}:
            raise WorkspaceError("WORKSPACE_MARKER_CONFLICT")
        return directory

    def record_phase(self, tid: str, stage: str, event: str) -> dict:
        """Append an actual timestamp, without inventing transitions."""
        if stage not in STAGES or event not in EVENTS:
            raise WorkspaceError("WORKSPACE_PHASE_INVALID")
        directory = self.require(tid)
        path = directory / "06-ledger/phases.jsonl"
        if path.is_symlink():
            raise WorkspaceError("WORKSPACE_LEDGER_SYMLINK")
        payload = {"at_utc": utc_now(), "stage": stage, "event": event}
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(payload, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        return payload

    def phases(self, tid: str) -> list[dict]:
        path = self.require(tid) / "06-ledger/phases.jsonl"
        if path.is_symlink():
            raise WorkspaceError("WORKSPACE_LEDGER_SYMLINK")
        events = []
        with path.open("r", encoding="utf-8") as stream:
            for line in stream:
                if line.strip():
                    events.append(json.loads(line))
                if len(events) > 10000:
                    raise WorkspaceError("WORKSPACE_PHASE_LIMIT")
        return events

    def files(self, tid: str) -> list[dict]:
        """Hash the actual on-disk files; never follow symlinks."""
        directory = self.require(tid)
        items = []
        for path in sorted(directory.rglob("*")):
            if path.is_symlink():
                raise WorkspaceError("WORKSPACE_SYMLINK_ENTRY")
            if path.is_dir():
                continue
            if not path.is_file():
                raise WorkspaceError("WORKSPACE_NONREGULAR_ENTRY")
            rel = path.relative_to(directory).as_posix()
            if rel == MANIFEST:
                continue
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                raise WorkspaceError("WORKSPACE_NONREGULAR_ENTRY")
            items.append({"path": rel, "sha256": _hash_file(path), "size": info.st_size})
            if len(items) > MAX_FILES:
                raise WorkspaceError("WORKSPACE_TOO_MANY_FILES")
        return items

    def snapshot(self, tid: str) -> dict:
        files = self.files(tid)
        duplicates = defaultdict(list)
        for item in files:
            duplicates[(item["sha256"], item["size"])].append(item["path"])
        return {
            "schema": 1, "asset": "ASSET_001", "task_id": tid,
            "generated_at_utc": utc_now(),
            "file_count": len(files),
            "total_bytes": sum(item["size"] for item in files),
            "duplicates": [paths for paths in duplicates.values() if len(paths) > 1],
            "files": files,
        }

    def write_manifest(self, tid: str) -> dict:
        info = self.snapshot(tid)
        path = self.require(tid) / MANIFEST
        _atomic_write(path, json.dumps(info, sort_keys=True, indent=2) + "\n")
        return info

    def verify_manifest(self, tid: str) -> dict:
        directory = self.require(tid)
        manifest = directory / MANIFEST
        if manifest.is_symlink() or not manifest.is_file():
            raise WorkspaceError("WORKSPACE_MANIFEST_MISSING")
        existing = json.loads(manifest.read_text(encoding="utf-8"))
        if existing.get("schema") != 1 or existing.get("task_id") != tid:
            raise WorkspaceError("WORKSPACE_MANIFEST_INVALID")
        original = {x["path"]: (x["sha256"], x["size"]) for x in existing["files"]}
        actual = {x["path"]: (x["sha256"], x["size"]) for x in self.files(tid)}
        added = sorted(actual.keys() - original.keys())
        missing = sorted(original.keys() - actual.keys())
        changed = sorted(p for p in original.keys() & actual.keys()
                         if original[p] != actual[p])
        return {
            "status": "verified" if not (added or missing or changed) else "drift",
            "manifest_created_at_utc": existing["generated_at_utc"],
            "added": added, "missing": missing, "changed": changed,
            "expected_files": len(original), "actual_files": len(actual),
        }

    def archive(self, tid: str, destination: str | Path,
                *, dry_run: bool = True) -> dict:
        """Copy-verify and retain source. Dry-run has exactly zero writes."""
        source = self.require(tid)
        dest = Path(destination).expanduser()
        if dest.is_symlink() or dest.exists():
            raise WorkspaceError("WORKSPACE_ARCHIVE_EXISTS")
        if not dest.parent.is_dir() or dest.parent.is_symlink():
            raise WorkspaceError("WORKSPACE_ARCHIVE_PARENT")
        if dest.resolve().is_relative_to(source.resolve()):
            raise WorkspaceError("WORKSPACE_ARCHIVE_INSIDE_SOURCE")
        verification = self.verify_manifest(tid)
        if verification["status"] != "verified":
            raise WorkspaceError("WORKSPACE_MANIFEST_DRIFT")
        if dry_run:
            return {"status": "dry-run", "source_retained": True,
                    "files": verification["actual_files"], "destination": str(dest)}
        # Symlinks were rejected by verify_manifest before copying.
        shutil.copytree(source, dest, symlinks=True)
        for path in dest.rglob("*"):
            if path.is_symlink():
                raise WorkspaceError("WORKSPACE_ARCHIVE_SYMLINK")
            os.chmod(path, 0o700 if path.is_dir() else 0o600)
        os.chmod(dest, 0o700)
        replica = WorkspaceManager(dest.parent)
        # The destination name may be a user-selected archive name, not a UUID.
        expected = {x["path"]: (x["sha256"], x["size"]) for x in self.files(tid)}
        copied = {}
        for path in dest.rglob("*"):
            if path.is_file() and path.relative_to(dest).as_posix() != MANIFEST:
                copied[path.relative_to(dest).as_posix()] = (_hash_file(path), path.stat().st_size)
        if copied != expected:
            raise WorkspaceError("WORKSPACE_ARCHIVE_VERIFY_FAILED_SOURCE_RETAINED")
        return {"status": "verified-copy", "source_retained": True,
                "files": len(copied), "destination": str(dest)}
