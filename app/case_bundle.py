"""Encrypted, task-scoped offline SECRA case export and restore.

Unlike the workspace-only archive, this bundle contains a filtered SQLite
task snapshot, related workspace files, and corresponding AES-GCM evidence
keys/records. It NEVER includes unrelated engagements, never writes an
intermediate plaintext archive to disk, and never changes a live task.

Intended for local retention and operator-controlled recovery. This is not
a backup of any external system or an automatic bug-bounty submission.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import sqlite3
import stat
import tempfile
import zipfile
from pathlib import Path
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.loop.store import TaskStore
from app.workspace import WorkspaceManager

MAGIC = b"SECRA-CASE-v1\n"
MAX_BYTES = 96 * 1024 * 1024
MAX_FILES = 2500
N = 1 << 14
TABLES = {
    "tasks": "id",
    "events": "task_id",
    "approvals": "task_id",
    "tool_runs": "task_id",
    "process_leads": "task_id",
    "process_lead_events": "task_id",
}
GATEWAY_TABLES = {"requests": "engagement", "events": "engagement"}


class BundleError(ValueError):
    pass


def _key(passphrase: str, salt: bytes) -> bytes:
    if not isinstance(passphrase, str) or len(passphrase) < 16:
        raise BundleError("BUNDLE_PASSPHRASE_TOO_SHORT")
    return hashlib.scrypt(
        passphrase.encode("utf-8"), salt=salt, n=N, r=8, p=1,
        maxmem=64 * 1024 * 1024, dklen=32,
    )


def _filtered_sqlite(original: Path, task_id: str,
                     tables: dict[str, str]) -> bytes | None:
    if original.is_symlink():
        raise BundleError("BUNDLE_UNSAFE_DATABASE")
    if not original.is_file():
        return None
    source = sqlite3.connect("file:" + str(original.resolve()) + "?mode=ro", uri=True)
    source.row_factory = sqlite3.Row
    result = sqlite3.connect(":memory:")
    try:
        source.execute("BEGIN")  # one consistent read snapshot
        names = set(row[0] for row in source.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"))
        for table, filter_column in tables.items():
            if table not in names:
                continue
            source_schema = source.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                (table,)
            ).fetchone()[0]
            if not source_schema:
                raise BundleError("BUNDLE_MISSING_SCHEMA")
            result.execute(source_schema)
            # table/column are fixed source-code constants; value is bound.
            values = source.execute(
                "SELECT * FROM " + table + " WHERE " + filter_column + "=?",
                (task_id,),
            ).fetchall()
            if len(values) > 100000:
                raise BundleError("BUNDLE_TABLE_ROW_LIMIT")
            if values:
                placeholder = ",".join("?" for _ in range(len(values[0])))
                result.executemany(
                    "INSERT INTO " + table + " VALUES (" + placeholder + ")",
                    [tuple(row) for row in values],
                )
        result.commit()
        source.commit()
        return result.serialize()
    finally:
        result.close()
        source.close()


def _safe_files(base: Path, archive_prefix: str, *, limit: int = MAX_FILES):
    if base.is_symlink():
        raise BundleError("BUNDLE_SYMLINK")
    if not base.exists():
        return
    if not base.is_dir():
        raise BundleError("BUNDLE_NOT_DIRECTORY")
    for path in sorted(base.rglob("*")):
        if path.is_symlink():
            raise BundleError("BUNDLE_SYMLINK")
        if path.is_dir():
            continue
        if not path.is_file():
            raise BundleError("BUNDLE_NONREGULAR_FILE")
        if not stat.S_ISREG(path.stat().st_mode):
            raise BundleError("BUNDLE_NONREGULAR_FILE")
        rel = path.relative_to(base).as_posix()
        if path.stat().st_size > MAX_BYTES:
            raise BundleError("BUNDLE_FILE_TOO_LARGE")
        yield archive_prefix + "/" + rel, path.read_bytes()


def create_bundle(store: TaskStore, task_id: str, passphrase: str) -> bytes:
    task = store.require(task_id)
    if task["status"] not in {"completed", "stopped", "failed", "refused", "exhausted"}:
        raise BundleError("BUNDLE_TASK_MUST_BE_TERMINAL")
    # Local case-integrity prerequisite prevents a "complete" export with
    # missing referenced evidence, altered workspace files or audit gaps.
    from app.loop.case_integrity import check_case
    report = check_case(store, task_id)
    if report["status"] != "integrity_ok":
        raise BundleError("BUNDLE_CASE_INTEGRITY_REQUIRED")

    payload: dict[str, bytes] = {}
    snapshot = _filtered_sqlite(store.path, task["id"], TABLES)
    if not snapshot:
        raise BundleError("BUNDLE_TASK_DATABASE_REQUIRED")
    payload["data/agent-events.sqlite3"] = snapshot
    gateway = _filtered_sqlite(
        store.root / "evidence" / "tool-audit.sqlite3",
        task["id"], GATEWAY_TABLES
    )
    if gateway:
        payload["data/evidence/tool-audit.sqlite3"] = gateway
    workspace_root = WorkspaceManager(store.root / "engagements").require(task_id)
    for name, data in _safe_files(
        workspace_root, "data/engagements/" + task_id
    ):
        payload[name] = data

    key = store.root / "evidence" / "keys" / (task_id + ".key")
    records = store.root / "evidence" / "records" / task_id
    if key.is_symlink() or records.is_symlink():
        raise BundleError("BUNDLE_SYMLINK")
    if key.is_file():
        if stat.S_IMODE(key.stat().st_mode) != 0o600 or key.stat().st_size != 32:
            raise BundleError("BUNDLE_KEY_UNSAFE")
        payload["data/evidence/keys/" + key.name] = key.read_bytes()
    for name, data in _safe_files(
        records, "data/evidence/records/" + task_id
    ):
        payload[name] = data

    if not 2 <= len(payload) <= MAX_FILES:
        raise BundleError("BUNDLE_FILE_LIMIT")
    total = sum(len(data) for data in payload.values())
    if total > MAX_BYTES:
        raise BundleError("BUNDLE_SIZE_LIMIT")
    manifest = {
        "schema": 1, "task_id": task_id,
        "asset_alias": "ASSET_001",
        "contains_task_filtered_sqlite": True,
        "contains_vault_records_and_key_when_present": True,
        "contains_unrelated_engagements": False,
        "file_sha256": {name: hashlib.sha256(data).hexdigest()
                        for name, data in sorted(payload.items())}
    }
    memory = io.BytesIO()
    with zipfile.ZipFile(memory, "w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=6) as zf:
        for name, data in sorted(payload.items()):
            zf.writestr(name, data)
        zf.writestr("bundle-manifest.json",
                    json.dumps(manifest, sort_keys=True).encode())
    plain = memory.getvalue()
    if len(plain) > MAX_BYTES:
        raise BundleError("BUNDLE_SIZE_LIMIT")
    salt, nonce = os.urandom(16), os.urandom(12)
    ciphertext = AESGCM(_key(passphrase, salt)).encrypt(
        nonce, plain, MAGIC + salt
    )
    return MAGIC + salt + nonce + ciphertext


def restore_bundle(bundle: bytes, passphrase: str, destination: Path) -> dict:
    """Restore into a NEW directory only, with no plaintext intermediate ZIP."""
    destination = Path(destination)
    if (not isinstance(bundle, bytes) or not bundle.startswith(MAGIC)
            or len(bundle) > MAX_BYTES + 1024 or len(bundle) < len(MAGIC) + 44):
        raise BundleError("BUNDLE_FORMAT_OR_SIZE_INVALID")
    if destination.is_symlink() or destination.exists():
        raise BundleError("BUNDLE_DESTINATION_EXISTS")
    if not destination.parent.is_dir() or destination.parent.is_symlink():
        raise BundleError("BUNDLE_DESTINATION_PARENT")
    salt_at = len(MAGIC)
    salt = bundle[salt_at:salt_at + 16]
    nonce = bundle[salt_at + 16:salt_at + 28]
    try:
        plain = AESGCM(_key(passphrase, salt)).decrypt(
            nonce, bundle[salt_at + 28:], MAGIC + salt
        )
    except Exception as exc:
        raise BundleError("BUNDLE_DECRYPT_OR_AUTH_FAILED") from exc
    if len(plain) > MAX_BYTES:
        raise BundleError("BUNDLE_PLAINTEXT_TOO_LARGE")

    with zipfile.ZipFile(io.BytesIO(plain), "r") as zf:
        names = zf.namelist()
        if (len(names) > MAX_FILES + 1 or len(names) != len(set(names))
                or "bundle-manifest.json" not in names):
            raise BundleError("BUNDLE_ENTRY_LIST_INVALID")
        manifest = json.loads(zf.read("bundle-manifest.json"))
        task_id = manifest.get("task_id")
        if (not isinstance(task_id, str) or str(UUID(task_id)) != task_id
                or manifest.get("schema") != 1):
            raise BundleError("BUNDLE_MANIFEST_INVALID")
        expected = manifest.get("file_sha256")
        if not isinstance(expected, dict) or set(expected) != set(names) - {"bundle-manifest.json"}:
            raise BundleError("BUNDLE_FILE_INDEX_INVALID")
        total_uncompressed = sum(
            zf.getinfo(name).file_size for name in names
        )
        if total_uncompressed > MAX_BYTES:
            raise BundleError("BUNDLE_ZIP_EXPANSION_LIMIT")
        prefix = "data/engagements/" + task_id + "/"
        allowed_files = {
            "data/agent-events.sqlite3",
            "data/evidence/tool-audit.sqlite3",
            "data/evidence/keys/" + task_id + ".key",
        }
        staging = Path(tempfile.mkdtemp(prefix=".secra-case-stage-", dir=destination.parent))
        try:
            for name in names:
                if name == "bundle-manifest.json":
                    continue
                parts = Path(name).parts
                if (name.startswith("/") or ".." in parts or
                        not (name in allowed_files
                             or name.startswith(prefix)
                             or name.startswith("data/evidence/records/" + task_id + "/"))):
                    raise BundleError("BUNDLE_UNSAFE_PATH")
                info = zf.getinfo(name)
                if info.file_size > MAX_BYTES or info.is_dir():
                    raise BundleError("BUNDLE_ENTRY_UNSAFE")
                data = zf.read(name)
                if hashlib.sha256(data).hexdigest() != expected[name]:
                    raise BundleError("BUNDLE_HASH_INVALID")
                path = staging / name
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                if path.is_symlink() or path.exists():
                    raise BundleError("BUNDLE_ENTRY_CONFLICT")
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(path, flags, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
            (staging / "bundle-manifest.json").write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8"
            )
            os.chmod(staging / "bundle-manifest.json", 0o600)
            if destination.exists():
                raise BundleError("BUNDLE_DESTINATION_EXISTS")
            staging.rename(destination)
        finally:
            if staging.exists():
                import shutil
                shutil.rmtree(staging)
        return {"status": "restored_offline", "task_id": task_id,
                "file_count": len(expected), "destination": str(destination),
                "secrets_decrypted_only_locally": True,
                "network_execution_authorized": False}


def write_bundle(destination: Path, content: bytes) -> None:
    """Exclusive mode-0600 ciphertext; never overwrite existing backups."""
    destination = Path(destination)
    if (destination.exists() or destination.is_symlink()
            or not destination.parent.is_dir() or destination.parent.is_symlink()):
        raise BundleError("BUNDLE_DESTINATION_INVALID")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(destination, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
