import importlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

main = importlib.import_module("app.main")

def test_llm_never_receives_raw_target_data(monkeypatch):
    captured = {}
    def fake_gateway(path, method="GET", payload=None, timeout=7):
        captured["path"] = path
        captured["payload"] = payload
        return {"choices": [{"message": {"content": "Check whether HTTPS is configured properly."}}]}
    monkeypatch.setattr(main, "LLM_KEY", "local-test-key")
    monkeypatch.setattr(main, "gateway_request", fake_gateway)
    ports = [{"port": 443, "service": "https", "host": "customer.example.com",
              "raw_http": "Authorization: Bearer credentialdata",
              "ip": "192.0.2.10"}, {"port": 22, "service": "ssh"}]
    answer = main.llm_assessment("glm/mock", ports)
    assert "HTTPS" in answer
    assert captured["path"] == "/chat/completions"
    outbound = json.dumps(captured["payload"])
    for secret in ("192.0.2.10", "customer.example.com", "credentialdata", "Authorization", "raw_http"):
        assert secret not in outbound
    assert "ASSET_001" in outbound

@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_dashboard_javascript_parses():
    source = (Path(__file__).resolve().parents[1] / "app/static/index.html").read_text()
    script = source.split("<script>")[1].split("</script>")[0]
    result = subprocess.run(["node", "--check", "--input-type=commonjs"], input=script,
                            text=True, capture_output=True, timeout=6)
    assert result.returncode == 0, result.stderr
