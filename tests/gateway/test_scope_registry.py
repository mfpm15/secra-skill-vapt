import ipaddress
from uuid import uuid4

import pytest

from app.scope_guard import (ScopeDenied, ScopePolicy, authorized_target,
                             enforce_scope_per_connection, fixed_http_url,
                             reject_untrusted_url)
from app.tool_registry import (REGISTRY, TOP20_TCP, StructuredToolIntent,
                               ToolDenied, validate_tool_intent)
from app.masking import MemoryVault


TARGET = "192.0.2.10"
SCOPE = "192.0.2.0/24"


def policy():
    return ScopePolicy.from_engagement(TARGET, SCOPE, (80, 443))


def test_only_exact_target_and_approved_port():
    enforce_scope_per_connection(TARGET, TARGET, 80, policy())
    for peer, port in [("198.51.100.4", 80), ("192.0.2.11", 80),
                       ("127.0.0.1", 80), (TARGET, 22),
                       ("::ffff:192.0.2.10", 80), ("::1", 80)]:
        with pytest.raises(ScopeDenied):
            enforce_scope_per_connection(TARGET, peer, port, policy())


def test_no_hostname_dns_rebinding_or_unapproved_urls():
    for value in ["example.test", "api.example.test", "192.0.2.10.evil.test",
                  "http://192.0.2.10/", "::ffff:192.0.2.10", "169.254.169.254"]:
        with pytest.raises(ScopeDenied):
            authorized_target(value, policy())
    valid = fixed_http_url(TARGET, 80, policy())
    assert valid == "http://192.0.2.10:80/"
    reject_untrusted_url(valid, policy())
    for url in ["http://192.0.2.10:80/@outside", "http://192.0.2.10:80/?next=evil",
                "http://192.0.2.10:80/redirect", "http://user@192.0.2.10:80/",
                "http://192.0.2.11:80/", "file:///etc/passwd"]:
        with pytest.raises(ScopeDenied):
            reject_untrusted_url(url, policy())


def test_placeholders_are_typed_and_authorized():
    vault = MemoryVault()
    valid = vault.put("IP", TARGET)
    assert authorized_target(valid, policy(), vault=vault) == TARGET
    for value in ["<IP_999>", "<HOST_1>", "<TOKEN_1>", "<IP_1>tail"]:
        with pytest.raises(ScopeDenied):
            authorized_target(value, policy(), vault=vault)


def test_unknown_actions_and_unreviewed_parameters_denied():
    eid, rid = uuid4(), uuid4()
    def make(action, parameters=None):
        return StructuredToolIntent(eid, rid, "agent_1", action, TARGET,
                                    {} if parameters is None else parameters)
    assert validate_tool_intent(make("nmap.tcp_top20")).risk == "R2"
    assert validate_tool_intent(make("curl.http_head", {"port": 443})).risk == "R2"
    for intent in [make("rm -rf /"), make("nmap.tcp_top20", {"flags": "-A"}),
                   make("curl.http_head", {"port": 22}), make("curl.http_head", {"port": True}),
                   make("http.authenticated_test"), make("prohibited.r4"),
                   make("zap.passive_import"), make("asset_inventory.read")]:
        with pytest.raises(ToolDenied):
            validate_tool_intent(intent)


def test_reviewed_port_list_and_registry():
    assert len(TOP20_TCP) == 20
    assert REGISTRY["http.authenticated_test"].risk == "R3"
    assert REGISTRY["prohibited.r4"].risk == "R4"
    with pytest.raises(ScopeDenied):
        ScopePolicy.from_engagement(TARGET, "198.51.100.0/24", (80,))
