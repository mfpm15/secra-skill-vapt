"""Verify actual serialized transport bytes, not just pre-wire Python objects."""
import importlib
import json

import pytest

from app.masking import EgressDeniedError, guard_mask

main = importlib.import_module("app.main")


def _safe_payload():
    return main.llm_safe_payload([{"port": 443, "service": "https"}])


def _request(system_extra="", user_override=None):
    payload = _safe_payload()
    user = json.dumps(payload, separators=(",", ":"))
    _, methods = main.safe_skill_context(payload["observed_open_services"])
    return {
        "model": "glm/mock",
        "temperature": 0.1,
        "max_tokens": 320,
        "messages": [
            {"role": "system", "content": main.LLM_SYSTEM_PREFIX + methods + system_extra},
            {"role": "user", "content": user if user_override is None else user_override},
        ],
    }


def test_wire_interceptor_drops_untrusted_raw_context(monkeypatch):
    called = []
    def blocked_network(*args, **kwargs):
        called.append(True)
        raise AssertionError("Network should never be called")
    monkeypatch.setattr(main.urllib.request, "urlopen", blocked_network)
    with pytest.raises(EgressDeniedError):
        main.gateway_request("/chat/completions", "POST",
                             _request(system_extra=" customer-secret-do-not-send"))
    with pytest.raises(EgressDeniedError):
        main.gateway_request("/chat/completions", "POST",
                             _request(user_override='{"host":"10.9.8.7"}'))
    with pytest.raises(EgressDeniedError):
        main.gateway_request("/chat/completions", "POST",
                             {**_request(), "extra_field": "secret"})
    assert called == []


def test_wire_rejects_duplicate_keys_and_freeform_notice():
    original = json.dumps(_safe_payload(), separators=(",", ":"))
    tampered = original.replace('"asset":"ASSET_001"', '"asset":"ASSET_001","asset":"ASSET_001"')
    with pytest.raises(EgressDeniedError):
        guard_mask(tampered, for_llm=True)
    with pytest.raises(EgressDeniedError):
        guard_mask(original.replace("Do not infer", "Client Account Do not infer"), for_llm=True)


def test_valid_request_serialized_without_original_secrets(monkeypatch):
    monkeypatch.setattr(main, "LLM_KEY", "local-test-key")
    requests = []
    class MockHTTP:
        def __init__(self, req):
            self.req = req
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def read(self, size=0):
            return b'{"choices":[{"message":{"content":"Review certificate settings."}}]}'
    def capture(req, timeout=7):
        requests.append(req)
        return MockHTTP(req)
    monkeypatch.setattr(main.urllib.request, "urlopen", capture)
    answer = main.llm_assessment("glm/mock", [{
        "port": 443,
        "service": "https",
        "ip": "10.20.30.40",
        "hostname": "private.corp.internal",
        "Authorization": "Bearer TopSecretData123",
        "customer": "Helios Analytics"
    }])
    assert "certificate" in answer
    assert len(requests) == 1
    wire = requests[0].data.decode("utf-8")
    for sensitive in ("10.20.30.40", "private.corp.internal",
                      "TopSecretData123", "Helios Analytics"):
        assert sensitive not in wire
    assert "ASSET_001" in wire
    assert "443" in wire
