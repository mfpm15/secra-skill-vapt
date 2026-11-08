"""Text-only provider fallback is a strict command *choice*, not arbitrary execution."""
from __future__ import annotations

import json
import shlex

import pytest

from app.loop.provider import Choice, ModelRefused, NineRouterPlanner
from app.loop.text_fallback import (TextFallbackExhausted, _reviewed_choice,
                                    select_text_fallback)
from app.mcp.manifest import ToolManifest


def allowed():
    m = ToolManifest()
    return [m.get("nmap.tcp_top20"), m.get("curl.http_head")]


def test_text_fallback_exact_nmap_argv_from_prose_code_fence():
    ref = _reviewed_choice(allowed(), None, [])
    assert ref is not None
    answer = "Berikut perintahnya:\n" + chr(96)*3 + "bash\n1. " + shlex.join(ref.spec.argv) + "\n" + chr(96)*3
    result = select_text_fallback("glm/mock", content=answer,
                                  tools=allowed(), prior=None, services=[],
                                  send_text_prompt=lambda _: (_ for _ in ()).throw(
                                      AssertionError("second model request not needed")))
    assert result == Choice("nmap.tcp_top20", {})


def test_text_fallback_two_distinct_level_retries_then_exhausted():
    framed = []
    def reply(prompt):
        framed.append(prompt)
        return "Secara umum, saya tidak menyediakan perintah."
    with pytest.raises(TextFallbackExhausted, match="TEXT_FALLBACK_EXHAUSTED"):
        select_text_fallback("glm/mock", content="Berikut perintahnya:",
                             tools=allowed(), prior=None, services=[],
                             send_text_prompt=reply)
    assert len(framed) == 2
    assert framed[0] != framed[1]
    assert all("<HOST_1>" in x and "SECRA-COMMAND-START" in x
               for x in framed)
    assert all("192.0.2.10" not in x for x in framed)


def test_text_fallback_safety_refusal_is_terminal():
    calls = []
    def refused(_):
        calls.append(1)
        return "Maaf, saya tidak dapat membantu."
    with pytest.raises(ModelRefused):
        select_text_fallback("glm/mock", content="Berikut perintahnya:",
                             tools=allowed(), prior=None, services=[],
                             send_text_prompt=refused)
    assert calls == [1]


def test_text_fallback_curl_uses_only_reviewed_http_port_and_placeholder():
    prior = ("nmap.tcp_top20", "Reviewed Nmap: 1 open TCP service ports.")
    services = [{"port": 443, "service": "https", "ip": "192.0.2.44"}]
    ref = _reviewed_choice(allowed(), prior, services)
    assert ref.action == "curl.http_head" and ref.arguments == {"port": 443}
    assert ref.spec.argv[-1] == "https://<HOST_1>:443/"
    cmd = shlex.join(ref.spec.argv)
    selected = select_text_fallback("glm/mock", content=cmd, tools=allowed(),
                                    prior=prior, services=services,
                                    send_text_prompt=lambda _: (_ for _ in ()).throw(
                                        AssertionError("must parse exact first text")))
    assert selected == Choice("curl.http_head", {"port": 443})


def test_bogus_argv_fails_format_repair_without_emitting_tool_choice():
    attempts = []
    with pytest.raises(TextFallbackExhausted):
        select_text_fallback("glm/mock",
                             content="nmap --script vuln 192.0.2.1",
                             tools=allowed(), prior=None, services=[],
                             send_text_prompt=lambda prompt: (
                                 attempts.append(prompt) or
                                 "nmap --script vuln 192.0.2.1"))
    assert len(attempts) == 2


def test_completed_non_tool_response_does_not_force_an_action():
    calls = []
    result = select_text_fallback("glm/mock", content="Review completed.",
                                  tools=allowed(), prior=None, services=[],
                                  send_text_prompt=lambda x: calls.append(x))
    assert result is None and not calls


def test_9router_text_only_response_builds_exact_framed_second_request(monkeypatch):
    import app.loop.provider as provider_module
    sent = []
    ref = _reviewed_choice(allowed(), None, [])
    class MockResponse:
        def __init__(self, index): self.index = index
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, n=0):
            if self.index == 1:
                answer = "Berikut perintahnya:"
            else:
                answer = "Berikut perintahnya:\n" + chr(96)*3 + "bash\n" + (
                    shlex.join(ref.spec.argv)) + "\n" + chr(96)*3
            return json.dumps({"choices": [{"message": {"content": answer}}]}).encode()
    def capture(req, timeout=0):
        sent.append(json.loads(req.data))
        return MockResponse(len(sent))
    monkeypatch.setattr(provider_module.urllib.request, "urlopen", capture)
    planner = NineRouterPlanner("glm/mock", key="test-only-key",
                               gateway="http://127.0.0.1:20128/v1")
    choice = planner.choose(public_prompt="Review authorized public metadata.",
                            skills="Use only reviewed tools.",
                            tools=allowed(), prior=None,
                            services=[{"port": 443, "service": "https",
                                       "ip": "192.0.2.10"}])
    assert choice == Choice("nmap.tcp_top20", {})
    assert planner.text_fallback_used is True
    assert len(sent) == 2 and "tools" in sent[0] and "tools" not in sent[1]
    assert "SECRA-COMMAND-START" in sent[1]["messages"][1]["content"]
    assert "<HOST_1>" in sent[1]["messages"][1]["content"]
    assert all("192.0.2.10" not in json.dumps(payload) for payload in sent)
