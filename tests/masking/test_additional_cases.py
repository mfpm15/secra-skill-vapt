import ipaddress
import pytest

from app.masking import MemoryVault, redact, guard_unmask, UnsafeRehydrationError


def test_labeled_customer_masked_without_registry():
    original = "Customer: Helios Analytics\nHost: api.corp.internal\n"
    masked, delta = redact(original, vault=MemoryVault())
    assert masked == "Customer: <CUSTOMER_1>\nHost: <HOST_1>\n"
    assert delta["count"] == 2


def test_query_token_and_email_inside_nested_url():
    text = "GET https://portal.corp.internal/a?email=team@example.com&access_token=Abcde123456 HTTP/1.1"
    masked, delta = redact(text, tier="foreign")
    assert masked == "GET https://<HOST_1>/a?email=<EMAIL_1>&access_token=<TOKEN_1> HTTP/1.1"
    assert delta["count"] == 3


def test_header_cookie_values_mask_and_dedupe():
    text = "Set-Cookie: SID=secret1; HttpOnly\nCookie: SID=secret1; preference=light\n"
    masked, delta = redact(text)
    assert "secret1" not in masked
    assert "<COOKIE_1>" in masked
    assert "<COOKIE_2>" in masked
    assert delta["count"] == 2


def test_trusted_and_foreign_differ_only_on_public_ip():
    text = "8.8.8.8 192.168.2.2 2001:4860:4860::8888 fd00::1"
    trusted = redact(text, tier="trusted")[0]
    foreign = redact(text, tier="foreign")[0]
    assert "8.8.8.8" in trusted
    assert "2001:4860:4860::8888" in trusted
    assert "192.168.2.2" not in trusted
    assert "fd00::1" not in trusted
    assert all(v not in foreign for v in ("8.8.8.8", "2001:4860:4860::8888",
                                          "192.168.2.2", "fd00::1"))


def test_rehydration_does_not_authorize_extra_scope():
    v = MemoryVault()
    ph = v.put("IP", "10.10.1.15")
    with pytest.raises(UnsafeRehydrationError):
        guard_unmask(ph, v, expected_kind="IP", allowed_targets=["10.10.1.16"])
