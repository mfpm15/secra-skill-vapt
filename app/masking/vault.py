"""Local, encrypted and engagement-isolated placeholder mapping vault.

AES-256-GCM with authenticated engagement AAD. Stores keys and ciphertext OUTSIDE
the repository. Unix filesystem semantics are required (fcntl.flock, O_EXCL).
This is not an HSM and does not defend against a compromised local OS/root.
"""
from __future__ import annotations

import base64
import fcntl
import json
import os
import re
import stat
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TYPES = frozenset({"HOST", "IP", "EMAIL", "TOKEN", "COOKIE", "HASH", "PATH", "CUSTOMER"})
PLACEHOLDER = re.compile(r"^<(HOST|IP|EMAIL|TOKEN|COOKIE|HASH|PATH|CUSTOMER)_[1-9][0-9]*>$")
MAX_ITEMS = 20000
MAX_VALUE = 65536


class VaultError(RuntimeError):
    """Never include secret values, file data, or encryption keys in messages."""


class KeyMissingError(VaultError):
    pass


class MemoryVault:
    """Non-persistent mapping for local previews/CLI. Not used for live engagements."""

    def __init__(self) -> None:
        self._values: dict[str, tuple[str, str]] = {}
        self._reverse: dict[tuple[str, str], str] = {}
        self._counter: dict[str, int] = {}

    def put(self, kind: str, value: str) -> str:
        if kind not in TYPES or not isinstance(value, str) or not value or len(value) > MAX_VALUE:
            raise VaultError("Invalid entity")
        key = (kind, value)
        if key in self._reverse:
            return self._reverse[key]
        if len(self._values) >= MAX_ITEMS:
            raise VaultError("Mapping quota exceeded")
        index = self._counter.get(kind, 0) + 1
        self._counter[kind] = index
        placeholder = f"<{kind}_{index}>"
        if placeholder in self._values:
            raise VaultError("Placeholder collision")
        self._values[placeholder] = key
        self._reverse[key] = placeholder
        return placeholder

    def get_record(self, placeholder: str) -> tuple[str, str]:
        if not PLACEHOLDER.fullmatch(placeholder):
            raise KeyError("Unknown placeholder")
        if placeholder not in self._values:
            raise KeyError("Unknown placeholder")
        return self._values[placeholder]

    def get(self, placeholder: str) -> str:
        return self.get_record(placeholder)[1]

    def persist(self) -> None:
        raise VaultError("MemoryVault cannot persist; use encrypted Vault for engagements")

    def load(self) -> MemoryVault:
        raise VaultError("MemoryVault cannot load from disk")


class Vault(MemoryVault):
    """A new Vault is created explicitly with Vault.create(...); load never rekeys."""

    def __init__(self, engagement_id: str, *, root: str | Path | None = None) -> None:
        super().__init__()
        try:
            canonical = str(uuid.UUID(str(engagement_id)))
        except (ValueError, TypeError, AttributeError) as exc:
            raise VaultError("Invalid engagement UUID") from exc
        if canonical != str(engagement_id):
            raise VaultError("Noncanonical engagement UUID")
        self.engagement_id = canonical
        self.root = Path(root).expanduser() if root is not None else (
            Path.home() / ".local" / "state" / "secra" / "masking"
        )
        self.root = self.root.resolve()
        project_root = Path(__file__).resolve().parents[2]
        if self.root == project_root or project_root in self.root.parents:
            raise VaultError("Vault location must be outside project directory")
        self.keys_dir = self.root / "keys"
        self.data_dir = self.root / "encrypted_maps"
        self._key_path = self.keys_dir / (self.engagement_id + ".key")
        self._data_path = self.data_dir / (self.engagement_id + ".aesgcm")
        self._lock_path = self.root / (self.engagement_id + ".lock")
        self._key: bytes | None = None
        self._mutex = threading.RLock()

    @classmethod
    def create(cls, engagement_id: str, *, root: str | Path | None = None) -> Vault:
        vault = cls(engagement_id, root=root)
        vault._dirs()
        with vault._exclusive():
            if vault._key_path.exists() or vault._data_path.exists():
                raise VaultError("Vault already exists; call load() instead")
            key = AESGCM.generate_key(bit_length=256)
            vault._atomic_write(vault._key_path, key, replace=False)
            vault._key = key
            vault._persist_unlocked()
        return vault

    def _dirs(self) -> None:
        for path in (self.root, self.keys_dir, self.data_dir):
            if path.is_symlink():
                raise VaultError("Symlink directory not allowed")
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(path, 0o700)

    @staticmethod
    def _atomic_write(path: Path, content: bytes, *, replace: bool = True) -> None:
        if path.is_symlink():
            raise VaultError("Symlink vault file not allowed")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, tmp = tempfile.mkstemp(prefix="._secra_", dir=path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as out:
                out.write(content)
                out.flush()
                os.fsync(out.fileno())
            if not replace and path.exists():
                raise VaultError("Vault key already exists")
            os.replace(tmp, path)
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def _exclusive(self):
        from contextlib import contextmanager

        @contextmanager
        def locked():
            with self._mutex:
                fd = os.open(self._lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                    yield
                finally:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                    os.close(fd)

        return locked()

    def _read_key(self) -> bytes:
        if not self._key_path.is_file() or self._key_path.is_symlink():
            raise KeyMissingError("Vault encryption key missing")
        mode = stat.S_IMODE(self._key_path.stat().st_mode)
        if mode & 0o077:
            raise VaultError("Vault key has insecure permissions")
        key = self._key_path.read_bytes()
        if len(key) != 32:
            raise VaultError("Invalid vault encryption key")
        return key

    def _load_unlocked(self) -> None:
        # Always reread disk on mutation to prevent multi-process alias collisions.
        key = self._read_key()
        if not self._data_path.is_file() or self._data_path.is_symlink():
            raise VaultError("Encrypted map missing")
        try:
            envelope = json.loads(self._data_path.read_text(encoding="utf-8"))
            if envelope.get("version") != 1 or envelope.get("engagement") != self.engagement_id:
                raise VaultError("Vault version/engagement mismatch")
            nonce = base64.b64decode(envelope["nonce"], validate=True)
            ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
            if len(nonce) != 12:
                raise VaultError("Invalid nonce")
            aad = ("secra-vault-v1:" + self.engagement_id).encode()
            decrypted = AESGCM(key).decrypt(nonce, ciphertext, aad)
            records = json.loads(decrypted)
            if not isinstance(records, list) or len(records) > MAX_ITEMS:
                raise VaultError("Invalid map structure")
            values: dict[str, tuple[str, str]] = {}
            reverse: dict[tuple[str, str], str] = {}
            counts: dict[str, int] = {}
            for row in records:
                if not isinstance(row, dict):
                    raise VaultError("Invalid mapping entry")
                placeholder = row.get("placeholder")
                kind, value = row.get("kind"), row.get("value")
                if kind not in TYPES or not isinstance(value, str) or not value or len(value) > MAX_VALUE:
                    raise VaultError("Invalid mapping value")
                if not isinstance(placeholder, str) or not PLACEHOLDER.fullmatch(placeholder):
                    raise VaultError("Invalid mapping placeholder")
                if not placeholder.startswith("<" + kind + "_"):
                    raise VaultError("Mapping type mismatch")
                pair = kind, value
                if placeholder in values or pair in reverse:
                    raise VaultError("Duplicate mapping detected")
                values[placeholder] = pair
                reverse[pair] = placeholder
                counter = int(placeholder.split("_")[-1][:-1])
                counts[kind] = max(counts.get(kind, 0), counter)
            self._key = key
            self._values, self._reverse, self._counter = values, reverse, counts
        except (InvalidTag, ValueError, TypeError, KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VaultError("Encrypted vault failed integrity verification") from exc

    def _persist_unlocked(self) -> None:
        if self._key is None:
            raise KeyMissingError("Vault key not loaded")
        # Key must still exist on disk: never silently write data after its loss.
        if self._read_key() != self._key:
            raise VaultError("Encryption key changed")
        records = [
            {"placeholder": ph, "kind": pair[0], "value": pair[1]}
            for ph, pair in sorted(self._values.items())
        ]
        data = json.dumps(records, separators=(",", ":"), ensure_ascii=False).encode()
        nonce = os.urandom(12)
        ciphertext = AESGCM(self._key).encrypt(nonce, data,
                                               ("secra-vault-v1:" + self.engagement_id).encode())
        envelope = {
            "version": 1,
            "engagement": self.engagement_id,
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
        }
        self._atomic_write(self._data_path, json.dumps(envelope).encode())

    def load(self) -> Vault:
        with self._exclusive():
            self._load_unlocked()
        return self

    def persist(self) -> None:
        with self._exclusive():
            self._load_unlocked()
            self._persist_unlocked()

    def put(self, kind: str, value: str) -> str:
        if kind not in TYPES or not isinstance(value, str) or not value or len(value) > MAX_VALUE:
            raise VaultError("Invalid entity")
        with self._exclusive():
            self._load_unlocked()
            existing = self._reverse.get((kind, value))
            if existing is not None:
                return existing
            placeholder = super().put(kind, value)
            self._persist_unlocked()
            return placeholder

    def get_record(self, placeholder: str) -> tuple[str, str]:
        with self._exclusive():
            self._load_unlocked()
            return super().get_record(placeholder)
