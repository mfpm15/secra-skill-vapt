"""9Router tool selection uses only public schemas and canonical masked metadata."""
import json

import pytest

from app.loop.provider import NineRouterPlanner, ModelError
from app.mcp.manifest import ToolManifest


def test_real_model_request_wire_never_contains_raw_target(monkeypatch):
    import app.loop.provider as provider_module
    requests = []
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, n=0):
            return json.dumps({"choices": [{"message": {"tool_calls": [{
                "type": "function",
                "function": {"name": "demo__httpx_probe",
                             "arguments": '{"port":80}'},
            }]}}]}).encode()
    monkeypatch.setattr(provider_module.urllib.request, "urlopen",
                        lambda req, timeout=0: (requests.append(req), Response())[1])
    planner = NineRouterPlanner("glm/mock", key="ci-fake-model-key",
                               gateway="http://127.0.0.1:20128/v1")
    definitions = ToolManifest().visible("demo")
    outcome = planner.choose(public_prompt="You are a defensive metadata reviewer.",
                             skills="Public static skill: inspect HTTP status.",
                             tools=[t for t in definitions if t.name != "prohibited.r4"],
                             prior=("demo.nmap_scan",
                                    "SIMULATED Nmap: HTTP services observed on ports 80 and 443."),
                             services=[{"port": 80, "service": "http",
                                        "ip": "10.9.8.7",
                                        "Authorization": "Bearer TopSecretData"}])
    assert outcome.tool == "demo.httpx_probe"
    assert outcome.arguments == {"port": 80}
    assert len(requests) == 1
    raw = requests[0].data.decode()
    for private in ("10.9.8.7", "TopSecretData", "127.0.0.1/32", "<HOST_1>", "api_key"):
        assert private not in raw
    body = json.loads(raw)
    assert body["messages"][1]["content"].startswith('{"asset":"ASSET_001"')
    assert "task_id" not in raw
    assert all("target" not in x["function"]["parameters"]["properties"]
               for x in body["tools"])


def test_model_unreviewed_tool_name_is_terminal(monkeypatch):
    import app.loop.provider as provider_module
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, n=0):
            return b'{"choices":[{"message":{"tool_calls":[{"function":{"name":"shell__execute","arguments":"{}"}}]}}]}'
    monkeypatch.setattr(provider_module.urllib.request, "urlopen",
                        lambda *a, **k: Response())
    planner = NineRouterPlanner("glm/mock", key="ci-key",
                               gateway="http://127.0.0.1:20128/v1")
    defs = [ToolManifest().get("demo.nmap_scan")]
    with pytest.raises(ModelError, match="UNREVIEWED_TOOL"):
        planner.choose(public_prompt="Review public metadata.", skills="Public skill",
                       tools=defs, prior=None, services=[])


def test_unsanitized_previous_summary_blocked_before_http(monkeypatch):
    import app.loop.provider as provider_module
    monkeypatch.setattr(provider_module.urllib.request, "urlopen",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("HTTP must not be called")))
    planner = NineRouterPlanner("glm/mock", key="ci-key",
                               gateway="http://127.0.0.1:20128/v1")
    with pytest.raises(ModelError):
        planner.choose(public_prompt="Review public metadata.", skills="Public skill",
                       tools=[ToolManifest().get("demo.nmap_scan")],
                       prior=("demo.nmap_scan", "secret@private.internal token=abc"),
                       services=[])
