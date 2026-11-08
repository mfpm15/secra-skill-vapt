"""Encrypted local raw tool evidence. No parser sees bytes before the seal is durable.

Each bounded chunk is AES-256-GCM encrypted and fsynced before the next
chunk can be processed. A final authenticated seal binds stream order,
ciphertext chain, byte counts, and plaintext digest. An incomplete spool
is never readable as trusted evidence.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from pathlib import Path
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EvidenceError(RuntimeError):
    pass


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def _private_dir(path: Path) -> None:
    if path.is_symlink():
        raise EvidenceError("EVIDENCE_UNSAFE_DIRECTORY")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise EvidenceError("EVIDENCE_UNSAFE_DIRECTORY")
    os.chmod(path, 0o700)


def _keyfile(path: Path, *, create: bool = False) -> bytes:
    if path.is_symlink():
        raise EvidenceError("EVIDENCE_KEY_UNSAFE")
    fd = None
    if create:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            fd = None
    if fd is not None:
        try:
            key = AESGCM.generate_key(bit_length=256)
            os.write(fd, key)
            os.fsync(fd)
        finally:
            os.close(fd)
    flags = os.O_RDONLY | os.O_NOFOLLOW
    try:
        handle = os.open(path, flags)
        try:
            info = os.fstat(handle)
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_nlink != 1 or info.st_size != 32):
                raise EvidenceError("EVIDENCE_KEY_UNSAFE")
            key = os.read(handle, 33)
        finally:
            os.close(handle)
    except OSError as exc:
        raise EvidenceError("EVIDENCE_KEY_MISSING") from exc
    if len(key) != 32:
        raise EvidenceError("EVIDENCE_KEY_INVALID")
    return key


class EvidenceVault:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        _private_dir(self.root)
        _private_dir(self.root / "keys")
        _private_dir(self.root / "records")

    def _paths(self, engagement_id: UUID, run_id: UUID) -> tuple[Path, Path]:
        if not isinstance(engagement_id, UUID) or not isinstance(run_id, UUID):
            raise EvidenceError("EVIDENCE_ID_INVALID")
        directory = self.root / "records" / str(engagement_id)
        _private_dir(directory)
        return self.root / "keys" / (str(engagement_id) + ".key"), directory / (str(run_id) + ".jsonl")

    def begin(self, engagement_id: UUID, run_id: UUID) -> "EvidenceWriter":
        key_path, record_path = self._paths(engagement_id, run_id)
        key = _keyfile(key_path, create=True)
        return EvidenceWriter(record_path, key, engagement_id, run_id)

    def verify_and_read(self, engagement_id: UUID, run_id: UUID) -> dict[str, bytes]:
        key_path, record_path = self._paths(engagement_id, run_id)
        key = _keyfile(key_path)
        try:
            fd = os.open(record_path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
                    raise EvidenceError("EVIDENCE_UNSAFE_FILE")
                if info.st_size > 4_000_000:
                    raise EvidenceError("EVIDENCE_TOO_LARGE")
                lines = stream.readlines()
        except OSError as exc:
            raise EvidenceError("EVIDENCE_MISSING") from exc
        if len(lines) < 1 or len(lines) > 1000:
            raise EvidenceError("EVIDENCE_UNSEALED")
        prev = "0" * 64
        digest = hashlib.sha256()
        output: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
        totals = {"stdout": 0, "stderr": 0}
        prefix = ("secra-evidence-v1:" + str(engagement_id) + ":" + str(run_id) + ":").encode()
        try:
            for index, line in enumerate(lines):
                record = json.loads(line)
                if index == len(lines) - 1:
                    if set(record) != {"kind", "nonce", "ciphertext"} or record["kind"] != "seal":
                        raise EvidenceError("EVIDENCE_UNSEALED")
                    sealed = AESGCM(key).decrypt(_unb64(record["nonce"]),
                                _unb64(record["ciphertext"]), prefix + b"seal:" + prev.encode())
                    manifest = json.loads(sealed)
                    if manifest != {"chunks": index, "chain": prev, "sha256": digest.hexdigest(),
                                    "bytes": totals}:
                        raise EvidenceError("EVIDENCE_SEAL_MISMATCH")
                    return {k: bytes(v) for k, v in output.items()}
                if (set(record) != {"kind", "seq", "stream", "nonce", "ciphertext"}
                        or record["kind"] != "chunk" or record["seq"] != index
                        or record["stream"] not in output):
                    raise EvidenceError("EVIDENCE_CHUNK_INVALID")
                aad = prefix + (str(index) + ":" + record["stream"] + ":" + prev).encode()
                raw = AESGCM(key).decrypt(_unb64(record["nonce"]), _unb64(record["ciphertext"]), aad)
                if not raw or len(raw) > 65536:
                    raise EvidenceError("EVIDENCE_CHUNK_SIZE")
                output[record["stream"]].extend(raw)
                totals[record["stream"]] += len(raw)
                digest.update(raw)
                prev = hashlib.sha256(prev.encode() + line).hexdigest()
            raise EvidenceError("EVIDENCE_UNSEALED")
        except (InvalidTag, ValueError, TypeError, KeyError, UnicodeError, json.JSONDecodeError) as exc:
            raise EvidenceError("EVIDENCE_INTEGRITY_FAILURE") from exc


class EvidenceWriter:
    def __init__(self, path: Path, key: bytes, engagement_id: UUID, run_id: UUID):
        self.path = path
        self.key = key
        self.prefix = ("secra-evidence-v1:" + str(engagement_id) + ":" + str(run_id) + ":").encode()
        self.prev = "0" * 64
        self.digest = hashlib.sha256()
        self.count = 0
        self.totals = {"stdout": 0, "stderr": 0}
        self.finished = False
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            self.file = os.fdopen(fd, "wb")
        except OSError as exc:
            raise EvidenceError("EVIDENCE_CREATE_FAILED") from exc

    def _durable(self, record: dict) -> bytes:
        line = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
        self.file.write(line)
        self.file.flush()
        os.fsync(self.file.fileno())
        return line

    def append(self, stream: str, raw: bytes) -> None:
        if self.finished or stream not in self.totals or not isinstance(raw, bytes) or not 1 <= len(raw) <= 65536:
            raise EvidenceError("EVIDENCE_CHUNK_REJECTED")
        nonce = os.urandom(12)
        aad = self.prefix + (str(self.count) + ":" + stream + ":" + self.prev).encode()
        sealed = AESGCM(self.key).encrypt(nonce, raw, aad)
        line = self._durable({"kind": "chunk", "seq": self.count, "stream": stream,
                             "nonce": _b64(nonce), "ciphertext": _b64(sealed)})
        self.prev = hashlib.sha256(self.prev.encode() + line).hexdigest()
        self.digest.update(raw)
        self.totals[stream] += len(raw)
        self.count += 1

    def finish(self) -> tuple[str, int]:
        if self.finished:
            raise EvidenceError("EVIDENCE_ALREADY_SEALED")
        manifest = {"chunks": self.count, "chain": self.prev,
                    "sha256": self.digest.hexdigest(), "bytes": self.totals}
        nonce = os.urandom(12)
        sealed = AESGCM(self.key).encrypt(
            nonce, json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode(),
            self.prefix + b"seal:" + self.prev.encode())
        self._durable({"kind": "seal", "nonce": _b64(nonce), "ciphertext": _b64(sealed)})
        self.file.close()
        self.finished = True
        directory_fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return self.digest.hexdigest(), sum(self.totals.values())

    def abort(self) -> None:
        if not self.finished:
            self.file.close()
            self.finished = True
            # A broken/unsealed spool MUST NOT be emitted as valid evidence.
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
