import json
import os
import stat
from uuid import uuid4

import pytest

from app.evidence_vault import EvidenceVault, EvidenceError


def test_encrypted_evidence_chunk_and_verified_manifest(tmp_path):
    vault = EvidenceVault(tmp_path / "private")
    eid, rid = uuid4(), uuid4()
    writer = vault.begin(eid, rid)
    raw = b"Authorization: Bearer fake-secret-token\r\nSet-Cookie: sid=topsecret\r\n"
    writer.append("stdout", raw)
    writer.append("stderr", b"nmap error: hidden customer info")
    digest, size = writer.finish()
    assert size == len(raw) + len(b"nmap error: hidden customer info")
    assert len(digest) == 64
    path = vault.root / "records" / str(eid) / (str(rid) + ".jsonl")
    encrypted = path.read_bytes()
    assert raw not in encrypted and b"topsecret" not in encrypted
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE((vault.root / "keys" / (str(eid) + ".key")).stat().st_mode) == 0o600
    out = vault.verify_and_read(eid, rid)
    assert out["stdout"] == raw
    assert out["stderr"] == b"nmap error: hidden customer info"


def test_unsealed_and_tampered_evidence_never_read(tmp_path):
    vault = EvidenceVault(tmp_path)
    eid, rid = uuid4(), uuid4()
    writer = vault.begin(eid, rid)
    writer.append("stdout", b"private")
    path = writer.path
    with pytest.raises(EvidenceError):
        vault.verify_and_read(eid, rid)
    writer.finish()
    lines = path.read_bytes().splitlines(keepends=True)
    line = json.loads(lines[0])
    line["stream"] = "stderr"
    lines[0] = (json.dumps(line) + "\n").encode()
    path.write_bytes(b"".join(lines))
    with pytest.raises(EvidenceError):
        vault.verify_and_read(eid, rid)


def test_lost_key_must_not_be_automatically_recreated(tmp_path):
    vault = EvidenceVault(tmp_path)
    eid, rid = uuid4(), uuid4()
    writer = vault.begin(eid, rid)
    writer.append("stdout", b"proof")
    writer.finish()
    path = vault.root / "keys" / (str(eid) + ".key")
    path.unlink()
    with pytest.raises(EvidenceError):
        vault.verify_and_read(eid, rid)
    assert not path.exists()


def test_evidence_writer_write_failure_aborts(tmp_path, monkeypatch):
    vault = EvidenceVault(tmp_path)
    eid, rid = uuid4(), uuid4()
    writer = vault.begin(eid, rid)
    def fail(_record):
        raise OSError("disk full")
    monkeypatch.setattr(writer, "_durable", fail)
    with pytest.raises(OSError):
        writer.append("stdout", b"private")
    writer.abort()
    assert not writer.path.exists()
    with pytest.raises(EvidenceError):
        vault.verify_and_read(eid, rid)
