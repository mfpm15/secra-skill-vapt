"""Isolated complete-case bundle tests: encryption, privacy and restoration."""
from __future__ import annotations

import json
import sqlite3
from uuid import UUID, uuid4

import pytest

from app.case_bundle import BundleError, create_bundle, restore_bundle, write_bundle, MAGIC
from app.evidence_vault import EvidenceVault
from app.loop.store import TaskStore
from app.workspace import WorkspaceManager


def scenario(tmp_path):
    store = TaskStore(tmp_path / "data")
    first = store.create("127.0.0.1", "127.0.0.1/32",
                         mode="local", authorized=True)
    second = store.create("127.0.0.1", "127.0.0.1/32",
                          mode="local", authorized=True)
    vault = EvidenceVault(store.root / "evidence")
    rid = uuid4()
    writer = vault.begin(UUID(first), rid)
    writer.append("stdout", b"private evidence fixture for first task")
    writer.finish()
    receipt = "evidence://" + first + "/" + str(rid)
    audit = store.begin_tool_run(first, "local.http_head")
    store.finish_tool_run(first, audit, "completed", 0, 1, receipt)
    store.append(first, "tool", "local.http_head", "done", "Local synthetic fixture.", receipt)
    store.append(second, "task", "", "done", "UNRELATED ENGAGEMENT PRIVATE MARKER")
    WorkspaceManager(store.root / "engagements").write_manifest(first)
    return store, first, second, rid


def test_encrypted_bundle_is_scope_filtered_and_offline_restorable(tmp_path):
    store, first, second, rid = scenario(tmp_path)
    secret = "long passphrase - generated for offline unit tests"
    bundle = create_bundle(store, first, secret)
    assert bundle.startswith(MAGIC)
    assert first.encode() not in bundle
    assert second.encode() not in bundle
    assert b"private evidence fixture" not in bundle
    output = tmp_path / "private.case"
    write_bundle(output, bundle)
    assert output.stat().st_mode & 0o777 == 0o600
    dest = tmp_path / "recovered"
    result = restore_bundle(output.read_bytes(), secret, dest)
    assert result["status"] == "restored_offline"
    assert result["task_id"] == first
    assert (dest / "data" / "agent-events.sqlite3").is_file()
    assert (dest / "data" / "evidence" / "keys" / (first + ".key")).is_file()
    recovered = TaskStore(dest / "data")
    assert recovered.require(first)["mode"] == "local"
    with pytest.raises(Exception):
        recovered.require(second)
    assert len(recovered.tool_runs(first)) == 1
    vault = EvidenceVault(dest / "data" / "evidence")
    assert vault.verify_and_read(UUID(first), rid)["stdout"] == (
        b"private evidence fixture for first task"
    )
    assert not (dest / "data" / "evidence" / "records" / second).exists()
    assert WorkspaceManager(dest / "data" / "engagements").verify_manifest(first)["status"] == "verified"


def test_wrong_password_or_modified_ciphertext_cannot_restore(tmp_path):
    store, first, second, rid = scenario(tmp_path)
    cipher = create_bundle(store, first, "correct passphrase with enough characters")
    with pytest.raises(BundleError, match="DECRYPT"):
        restore_bundle(cipher, "wrong passphrase but valid length", tmp_path / "wrong")
    assert not (tmp_path / "wrong").exists()
    corrupted = bytearray(cipher)
    corrupted[-12] ^= 0x40
    with pytest.raises(BundleError, match="DECRYPT"):
        restore_bundle(bytes(corrupted), "correct passphrase with enough characters",
                       tmp_path / "corrupted")
    assert not (tmp_path / "corrupted").exists()


def test_missing_manifest_or_damaged_seal_fail_closed(tmp_path):
    store, first, second, rid = scenario(tmp_path)
    workspace = store.root / "engagements" / first
    (workspace / "01-recon" / "drift.txt").write_text("unexpected")
    with pytest.raises(BundleError, match="CASE_INTEGRITY"):
        create_bundle(store, first, "long passphrase for test only")
    (workspace / "01-recon" / "drift.txt").unlink()
    path = store.root / "evidence" / "records" / first / (str(rid) + ".jsonl")
    path.write_bytes(b"tampered encrypted evidence")
    with pytest.raises(BundleError, match="CASE_INTEGRITY"):
        create_bundle(store, first, "long passphrase for test only")


def test_restore_exclusivity_and_minimum_passphrase(tmp_path):
    store, first, second, rid = scenario(tmp_path)
    with pytest.raises(BundleError, match="TOO_SHORT"):
        create_bundle(store, first, "short")
    secret = "a long private test passphrase"
    bundle = create_bundle(store, first, secret)
    dest = tmp_path / "existing"
    dest.mkdir()
    with pytest.raises(BundleError, match="DESTINATION_EXISTS"):
        restore_bundle(bundle, secret, dest)
    output = tmp_path / "case.bin"
    write_bundle(output, bundle)
    with pytest.raises(BundleError, match="DESTINATION_INVALID"):
        write_bundle(output, bundle)
