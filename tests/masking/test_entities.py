import pytest

from app.masking import (
    MemoryVault, redact, guard_mask, guard_unmask, rehydrate,
    PlaceholderCollisionError, UnresolvedPlaceholderError,
    UnsafeRehydrationError, EgressDeniedError,
)
from app.masking.redact import UnsupportedInputError


def test_repeated_entity_has_same_placeholder():
    vault = MemoryVault()
    masked, delta = redact(
        "api.corp.internal api.corp.internal", vault=vault
    )
    assert masked == "<HOST_1> <HOST_1>"
    assert delta["count"] == 1


def test_two_different_hosts_never_collide():
    vault = MemoryVault()
    masked, delta = redact(
        "api.corp.internal db.corp.internal api.corp.internal", vault=vault
    )
    assert masked == "<HOST_1> <HOST_2> <HOST_1>"
    assert delta["count"] == 2
    assert vault.get("<HOST_1>") != vault.get("<HOST_2>")


def test_repeated_entity_across_calls_stable():
    vault = MemoryVault()
    assert redact("api.corp.internal", vault=vault)[0] == "<HOST_1>"
    second, delta = redact("api.corp.internal", vault=vault)
    assert second == "<HOST_1>" and delta["count"] == 0


def test_public_ipv4_trusted_preserved_foreign_masked():
    sample = "public 8.8.8.8 private 192.168.50.2"
    assert redact(sample, tier="trusted")[0] == "public 8.8.8.8 private <IP_1>"
    assert redact(sample, tier="foreign")[0] == "public <IP_1> private <IP_2>"


def test_public_ipv6_trusted_preserved_foreign_masked():
    sample = "external 2001:4860:4860::8888 internal fd00:abcd::2"
    assert redact(sample, tier="trusted")[0] == "external 2001:4860:4860::8888 internal <IP_1>"
    assert redact(sample, tier="foreign")[0] == "external <IP_1> internal <IP_2>"


def test_unknown_tier_denies():
    with pytest.raises(ValueError):
        redact("10.0.0.1", tier="fictional")


def test_known_customer_from_registry_and_home_path():
    masked, delta = redact(
        "Helios Analytics on /home/alice/private/config.ini",
        customer_names=["Helios Analytics"],
    )
    assert "<CUSTOMER_1>" in masked and "<PATH_1>" in masked
    assert delta["count"] == 2


def test_literal_placeholder_collision_fails_closed():
    with pytest.raises(PlaceholderCollisionError):
        redact("Attacker text contains <HOST_1> and api.corp.internal")


def test_unknown_placeholder_cannot_be_rehydrated_to_command():
    vault = MemoryVault()
    text, unresolved = rehydrate("nmap -sV <HOST_9>", vault)
    assert text == "nmap -sV UNRESOLVED_PLACEHOLDER"
    assert unresolved == ["<HOST_9>"]
    with pytest.raises(UnresolvedPlaceholderError):
        guard_unmask("<HOST_9>", vault, allowed_targets=["api.corp.internal"])


def test_rehydrate_never_accepts_raw_command():
    vault = MemoryVault()
    ph = vault.put("HOST", "api.corp.internal")
    with pytest.raises(UnsafeRehydrationError):
        guard_unmask("nmap -sV " + ph, vault, allowed_targets=["api.corp.internal"])
    with pytest.raises(UnsafeRehydrationError):
        guard_unmask(ph, vault, allowed_targets=["outside.corp.internal"])
    assert guard_unmask(ph, vault, allowed_targets=["api.corp.internal"]) == "api.corp.internal"


def test_credentials_cannot_be_resolved_as_target():
    vault = MemoryVault()
    ph = vault.put("TOKEN", "supersecret")
    with pytest.raises(UnsafeRehydrationError):
        guard_unmask(ph, vault, expected_kind="TOKEN", allowed_targets=["supersecret"])


def test_partial_placeholder_denied():
    text, unresolved = rehydrate("run <HOST_", MemoryVault())
    assert unresolved and "UNRESOLVED_PLACEHOLDER" in text


def test_named_hash_and_basic_auth_are_detected():
    masked, delta = redact("sha256=" + "a"*64 + "\nAuthorization: Basic YWRtaW46cGFzcw==")
    assert "a"*64 not in masked
    assert "YWRtaW46cGFzcw==" not in masked
    assert "<HASH_1>" in masked and "<TOKEN_1>" in masked


def test_remote_egress_only_approved_structured_schema():
    safe = '{"asset":"ASSET_001","observed_open_services":[{"port":443,"protocol":"tcp","service":"https"}],"notice":"Do not infer a vulnerability from an open port."}'
    masked, delta = guard_mask(safe, for_llm=True)
    assert masked == safe and delta["count"] == 0
    for sample in ('{"target":"10.1.1.3"}', "Authorization: Bearer abcdefghijk",
                   '{"asset":"ASSET_001","observed_open_services":[],"notice":"x","raw":"hello"}'):
        with pytest.raises(EgressDeniedError):
            guard_mask(sample, for_llm=True)


def test_entire_text_rejected_on_capacity_limit():
    with pytest.raises(UnsupportedInputError):
        redact("x" * 2_000_001)
