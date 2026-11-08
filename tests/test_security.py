import pytest
from app.security import assert_no_sensitive_payload, llm_safe_payload, redact, safe_gateway, safe_model, validate_scope

def test_scope_requires_target_in_cidr():
    ip, nets = validate_scope("192.0.2.10", "192.0.2.0/24")
    assert ip == "192.0.2.10" and len(nets) == 1
    with pytest.raises(ValueError, match="tidak berada"):
        validate_scope("192.0.2.10", "198.51.100.0/24")

@pytest.mark.parametrize("ip", ["127.0.0.1", "169.254.169.254", "0.0.0.0", "224.0.0.1"])
def test_special_addresses_blocked(ip):
    with pytest.raises(ValueError):
        validate_scope(ip, ip + "/32")

def test_reject_hostname_and_ipv6():
    with pytest.raises(ValueError):
        validate_scope("example.test", "192.0.2.0/24")
    with pytest.raises(ValueError):
        validate_scope("::1", "::1/128")

def test_redaction():
    value = "admin@example.com 192.0.2.10 Authorization: Bearer abcdefghijkl password=hello"
    result = redact(value)
    assert "admin@example.com" not in result
    assert "192.0.2.10" not in result
    assert "abcdefghijkl" not in result
    assert "hello" not in result

def test_minimal_llm_context():
    raw = [{"port": 443, "service": "https", "ip": "192.0.2.10",
            "authorization": "Bearer secret"}, {"port": 22, "service": "ssh"},
           {"port": 443, "service": "unknown-evil"}]
    clean = llm_safe_payload(raw)
    assert clean["asset"] == "ASSET_001"
    assert "192.0.2.10" not in str(clean)
    assert "secret" not in str(clean)
    assert_no_sensitive_payload(clean)

def test_fail_closed_llm_schema():
    with pytest.raises(ValueError):
        assert_no_sensitive_payload({"asset": "192.0.2.10", "observed_open_services": [], "notice": "x"})

def test_gateway_rules():
    assert safe_gateway("http://127.0.0.1:20128/v1").endswith("/v1")
    assert safe_gateway("https://9router.com/v1").endswith("/v1")
    for url in ["http://example.com/v1", "file:///v1", "https://user:pass@example.com/v1", "https://example.com/admin"]:
        with pytest.raises(ValueError):
            safe_gateway(url)
    assert safe_model("glm/glm-5.3") == "glm/glm-5.3"
    with pytest.raises(ValueError):
        safe_model("x\nother")
