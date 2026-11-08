import importlib
import json
import stat
from uuid import uuid4

import pytest
from app.framing import frame
from app.framing.audit import record_framing, FramingAuditError
from app.masking import EgressDeniedError

main = importlib.import_module("app.main")


def safe():
    return json.dumps(main.llm_safe_payload([{"port": 443, "service": "https"}]),
                      separators=(",", ":"))


def request(user):
    _, methods = main.safe_skill_context(
        main.llm_safe_payload([{"port": 443, "service": "https"}])["observed_open_services"])
    return {"model": "glm/mock", "temperature": 0.1, "max_tokens": 320,
            "messages": [{"role": "system", "content": main.LLM_SYSTEM_PREFIX + methods},
                         {"role": "user", "content": user}]}


def test_tampered_frame_never_reaches_network(monkeypatch):
    monkeypatch.setattr(main.urllib.request, "urlopen",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("unexpected HTTP")))
    normal = frame(safe(), 2, "glm/mock")
    for bad in [normal.replace("ASSET_001", "10.20.30.40"),
                normal + " extra",
                frame('{"host":"private.customer.internal"}', 2, "glm/mock"),
                normal.replace("OUTPUT CONTRACT", "DISABLED"),
                normal.replace("verification checklist", "arbitrary freeform")]:
        with pytest.raises(EgressDeniedError):
            main.gateway_request("/chat/completions", "POST", request(bad))


def test_wire_bytes_and_audit_example(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "LLM_KEY", "local-test-key")
    monkeypatch.setattr(main, "DATA", tmp_path)
    requests = []

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, size=0):
            return b'{"choices":[{"message":{"content":"- [ ] Review HTTP response status"}}]}'

    def capture(req, timeout=7):
        requests.append(req)
        return Response()

    monkeypatch.setattr(main.urllib.request, "urlopen", capture)
    result = main.llm_assessment("glm/mock", [
        {"port": 443, "service": "https", "ip": "10.20.30.40",
         "hostname": "private.customer.internal",
         "Authorization": "Bearer supersecret", "customer": "SYNTHETIC ACME CLIENT"}
    ], str(uuid4()))
    assert "Review HTTP" in result
    assert len(requests) == 1
    wire = requests[0].data.decode()
    for secret in ["10.20.30.40", "private.customer.internal",
                   "supersecret", "SYNTHETIC ACME CLIENT"]:
        assert secret not in wire
    obj = json.loads(wire)
    assert obj["messages"][1]["content"] == frame(safe(), 2, "glm/mock")
    logs = list((tmp_path / "framing-events").glob("*.jsonl"))
    assert len(logs) == 1
    records = [json.loads(line) for line in logs[0].read_text().splitlines()]
    assert [x["outcome"] for x in records] == ["prepared", "completed"]
    assert records[1]["result_reason"] == "ARTIFACT_PRESENT"
    assert records[1]["pre_frame_masked"] == safe()
    assert records[1]["framed_prompt"] == obj["messages"][1]["content"]
    assert stat.S_IMODE(logs[0].stat().st_mode) == 0o600


def test_explicit_refusal_does_not_retry(monkeypatch, tmp_path):
    from dataclasses import replace
    monkeypatch.setattr(main, "LLM_KEY", "local-test-key")
    monkeypatch.setattr(main, "DATA", tmp_path)
    original = main.get_profile
    monkeypatch.setattr(main, "get_profile",
                        lambda provider: replace(original(provider), max_format_retries=1))
    sent = []
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, size=0):
            return b'{"choices":[{"message":{"content":"Maaf, tidak bisa membantu."}}]}'
    monkeypatch.setattr(main.urllib.request, "urlopen",
                        lambda req, timeout=7: (sent.append(req), Response())[1])
    assert "Maaf" in main.llm_assessment("glm/mock", [{"port": 443, "service": "https"}])
    assert len(sent) == 1


def test_non_safety_format_retry_limited_to_two(monkeypatch, tmp_path):
    from dataclasses import replace
    monkeypatch.setattr(main, "LLM_KEY", "local-test-key")
    monkeypatch.setattr(main, "DATA", tmp_path)
    original = main.get_profile
    monkeypatch.setattr(main, "get_profile",
                        lambda provider: replace(original(provider),
                                                 level=1, max_format_retries=1))
    sent = []
    class Response:
        def __init__(self, n): self.n = n
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, size=0):
            text = ("Secara umum, berikut beberapa hal." if self.n == 1
                    else "- [ ] Verify service metadata")
            return json.dumps({"choices": [{"message": {"content": text}}]}).encode()
    monkeypatch.setattr(main.urllib.request, "urlopen",
                        lambda req, timeout=7: (sent.append(req), Response(len(sent)))[1])
    assert "Verify" in main.llm_assessment("glm/mock", [{"port": 443, "service": "https"}])
    assert len(sent) == 2


def test_audit_rejects_unmasked_customer_data(tmp_path):
    raw = '{"customer":"Private Client","Authorization":"Bearer secret"}'
    with pytest.raises(FramingAuditError):
        record_framing(tmp_path, task_id=str(uuid4()), provider="glm/mock", level=2,
                       masked_brief=raw, framed_prompt=frame(raw, 2, "glm/mock"))
    assert not list(tmp_path.iterdir())
