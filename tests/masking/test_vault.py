import os
import stat
from uuid import uuid4

import pytest

from app.masking import Vault, VaultError, KeyMissingError, guard_unmask


def test_encrypted_vault_roundtrip_and_directory_permissions(tmp_path):
    eid = str(uuid4())
    root = tmp_path / "external_state"
    v = Vault.create(eid, root=root)
    a = v.put("HOST", "api.corp.internal")
    b = v.put("IP", "10.9.8.7")
    assert a == "<HOST_1>" and b == "<IP_1>"
    v.persist()
    restored = Vault(eid, root=root).load()
    assert restored.get(a) == "api.corp.internal"
    assert restored.get(b) == "10.9.8.7"
    assert restored.put("HOST", "api.corp.internal") == a
    assert b"api.corp.internal" not in (root / "encrypted_maps" / (eid + ".aesgcm")).read_bytes()
    assert b"10.9.8.7" not in (root / "encrypted_maps" / (eid + ".aesgcm")).read_bytes()
    assert stat.S_IMODE((root / "keys" / (eid + ".key")).stat().st_mode) == 0o600
    assert stat.S_IMODE((root / "encrypted_maps" / (eid + ".aesgcm")).stat().st_mode) == 0o600


def test_missing_key_load_fails_hard(tmp_path):
    eid = str(uuid4())
    root = tmp_path / "state"
    v = Vault.create(eid, root=root)
    v.put("TOKEN", "verysecret")
    (root / "keys" / (eid + ".key")).unlink()
    with pytest.raises(KeyMissingError):
        Vault(eid, root=root).load()
    with pytest.raises(KeyMissingError):
        v.put("TOKEN", "anothersecret")


def test_tampered_ciphertext_fails_hard(tmp_path):
    eid = str(uuid4())
    root = tmp_path / "store"
    v = Vault.create(eid, root=root)
    v.put("EMAIL", "private@example.com")
    path = root / "encrypted_maps" / (eid + ".aesgcm")
    path.write_bytes(b'{"version":1,"engagement":"' + eid.encode() + b'","nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AA=="}')
    with pytest.raises(VaultError):
        Vault(eid, root=root).load()


def test_cross_engagement_isolation_and_scope(tmp_path):
    first_id, second_id = str(uuid4()), str(uuid4())
    first = Vault.create(first_id, root=tmp_path)
    second = Vault.create(second_id, root=tmp_path)
    assert first.put("HOST", "a.corp.internal") == "<HOST_1>"
    assert second.put("HOST", "b.corp.internal") == "<HOST_1>"
    assert first.get("<HOST_1>") == "a.corp.internal"
    assert second.get("<HOST_1>") == "b.corp.internal"
    with pytest.raises(Exception):
        guard_unmask("<HOST_1>", second, allowed_targets=["a.corp.internal"])


def test_create_existing_vault_must_not_rotate_key(tmp_path):
    eid = str(uuid4())
    first = Vault.create(eid, root=tmp_path)
    key = (tmp_path / "keys" / (eid + ".key")).read_bytes()
    with pytest.raises(VaultError):
        Vault.create(eid, root=tmp_path)
    assert (tmp_path / "keys" / (eid + ".key")).read_bytes() == key


def test_vault_put_dedupes_across_independent_instances(tmp_path):
    eid = str(uuid4())
    first = Vault.create(eid, root=tmp_path)
    second = Vault(eid, root=tmp_path).load()
    assert first.put("HOST", "one.corp.internal") == "<HOST_1>"
    assert second.put("HOST", "one.corp.internal") == "<HOST_1>"
    assert second.put("HOST", "two.corp.internal") == "<HOST_2>"
    assert first.put("HOST", "two.corp.internal") == "<HOST_2>"
