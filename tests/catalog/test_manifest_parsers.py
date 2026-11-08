"""Every Kali catalog entry must be closed-schema and genuinely blocked."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import UUID

import pytest

from app.agents.loader import load_profile, progressive_skills
from app.loop.store import TaskStore
from app.mcp.dispatcher import ToolDispatcher
from app.mcp.manifest import ToolManifest, ManifestError
from app.mcp.parsers import parse_tool_output, ParseError

HERE = Path(__file__).with_name("fixtures")


def test_full_manifest_covers_expected_security_categories():
    manifest = ToolManifest()
    assert len(manifest.tools) == 45
    catalog = [tool for tool in manifest.tools.values()
               if tool.adapter == "catalog_only"]
    assert len(catalog) == 36
    for category in {"recon","web","api","tls","data","auth","other"}:
        assert any(tool.metadata["category"] == category for tool in catalog)
    for tool in manifest.tools.values():
        assert tool.metadata is not None
        assert 0 <= tool.metadata["timeout_seconds"] <= 1200
        assert tool.metadata["output_pattern"]
        assert tool.metadata["kali_package"]
        assert tool.metadata["argv_pattern"]
        assert "task_id" in tool.input_schema["required"]
        assert tool.input_schema["additionalProperties"] is False


def test_catalog_tools_are_not_executable_even_when_binary_is_installed(tmp_path, monkeypatch):
    import app.mcp.manifest as manifest_module
    monkeypatch.setattr(manifest_module.shutil, "which", lambda name: "/usr/bin/" + name)
    manifest = ToolManifest()
    for name, definition in manifest.tools.items():
        if definition.adapter != "catalog_only":
            continue
        probe = manifest.probe(name)
        assert probe["installed"] is True
        assert probe["executable"] is False
        assert probe["status"] == "BLOCKED_ADAPTER_UNAVAILABLE"
    store = TaskStore(tmp_path)
    engine = ToolDispatcher(tmp_path, store=store, manifest=manifest)
    tid = store.create("192.0.2.10","192.0.2.0/24",
                       authorized=True, mode="live")
    store.start(tid)
    for name in ("web.nuclei","recon.nmap_syn","data.sqlmap","auth.hydra"):
        result = engine.call(name, {"task_id": tid})
        assert result["status"] == "blocked"
        assert result["masked"] is True and result["output_ref"] is None
    assert not list((tmp_path / "evidence" / "records" / tid).glob("*.jsonl")) if (
        tmp_path / "evidence" / "records" / tid).exists() else True


def test_missing_binary_probed_as_blocked(monkeypatch):
    import app.mcp.manifest as manifest_module
    monkeypatch.setattr(manifest_module.shutil, "which", lambda _: None)
    p = ToolManifest().probe("web.httpx")
    assert p["status"] == "BLOCKED_MISSING_BINARY"
    assert p["installed"] is False and p["executable"] is False


@pytest.mark.parametrize("file,name,expected", [
    ("nmap.xml","nmap.tcp_top20","nmap_xml"),
    ("httpx.jsonl","web.httpx","httpx_jsonl"),
    ("nuclei.jsonl","web.nuclei","nuclei_jsonl"),
    ("tls.txt","tls.sslscan","tls_text"),
    ("auth.txt","auth.netexec","auth_summary"),
])
def test_parser_reads_synthetic_realistic_formats_without_private_fields(file, name, expected):
    raw=(HERE/file).read_bytes()
    result=parse_tool_output(name, raw)
    assert result["format"] == expected
    assert result["parse_status"] == "parsed"
    assert result["masked"] is True
    assert result["raw_sha256"] == hashlib.sha256(raw).hexdigest()
    safe=json.dumps(result,sort_keys=True)
    for forbidden in ("192.0.2.10","private.invalid","TopSecret","SuperSecret",
                      "admin@", "Bearer", "CANARY", "/login"):
        assert forbidden not in safe


def test_nmap_status_and_service_are_allowlisted():
    out=parse_tool_output("nmap.tcp_top20", (HERE/"nmap.xml").read_bytes())
    assert out["entries"] == [
        {"asset":"ASSET_001","port":443,"protocol":"tcp","state":"open","service":"https"},
        {"asset":"ASSET_001","port":22,"protocol":"tcp","state":"filtered","service":"ssh"}]


def test_httpx_and_nuclei_normalize_without_raw_url():
    http=parse_tool_output("web.httpx",(HERE/"httpx.jsonl").read_bytes())
    nuclei=parse_tool_output("web.nuclei",(HERE/"nuclei.jsonl").read_bytes())
    assert [x["status"] for x in http["entries"]] == [200,404]
    assert [x["template_id"] for x in nuclei["entries"]] == [
        "http-missing-security-header","http-custom-legacy-check"]
    assert nuclei["entries"][0]["severity"] == "low"
    assert nuclei["entries"][1]["verified"] is False


def test_all_tool_output_parsers_have_safe_fallback():
    manifest=ToolManifest()
    raw=b"user=admin password=SuperSecretLongValue host=192.0.2.10\n"
    for name in manifest.tools:
        result=parse_tool_output(name,raw,manifest=manifest)
        assert result["masked"] is True
        assert result["parse_status"] in {"parsed","metadata_only","rejected"}
        assert result["raw_sha256"] == hashlib.sha256(raw).hexdigest()
        output=json.dumps(result)
        assert "admin" not in output and "SuperSecret" not in output
        assert "192.0.2.10" not in output
    with pytest.raises(ParseError):
        parse_tool_output("web.httpx", b"x" * 1_000_001)


def test_nmap_xml_entity_is_rejected_without_raw_leak():
    payload=b'<!DOCTYPE nmaprun [<!ENTITY secret SYSTEM "file:///etc/passwd">]><nmaprun></nmaprun>'
    result=parse_tool_output("nmap.tcp_top20",payload)
    assert result["parse_status"] == "rejected"
    assert not result["entries"]


def test_skill_content_is_operational_and_progressive():
    root=Path(__file__).resolve().parents[2]
    for name in ("recon","web","api","tls","ad","privesc","network","reporting"):
        text=(root/"skills"/name/"SKILL.md").read_text()
        assert 60 <= len(text.splitlines()) <= 120
        assert "## Urutan tindakan" in text
        assert "## Cara membaca keluaran" in text
        assert "## Kondisi stop" in text
    profile=load_profile("recon")
    names0, content0=progressive_skills(profile,step=0)
    names1, content1=progressive_skills(profile,step=1)
    names2, content2=progressive_skills(profile,step=2)
    assert names0 == names1 == names2 == ("recon",)
    assert content0 != content1 and content1 != content2
    assert all(len(x) <=1800 for x in (content0,content1,content2))


def test_kali_lab_script_is_syntax_valid_and_requires_real_kali(tmp_path):
    root=Path(__file__).resolve().parents[2]
    script=root/"deploy"/"lab-verify.sh"
    assert script.is_file()
    subprocess.run(["bash","-n",str(script)],check=True,timeout=5)
    env={**os.environ,"SECRA_FENCE_MODE":"dev"}
    # Strict gate must fail even before root/Kali inspection.
    run=subprocess.run(["bash",str(script),"--require-strict"],env=env,
                       capture_output=True,text=True,timeout=5)
    assert run.returncode != 0
    assert "require-strict refuses" in run.stderr
    assert "--junitxml=" in script.read_text()
    assert "tests.fence.verify_lab" in script.read_text()


def test_three_tool_parser_transcript_matches_fixture_without_network():
    trace=json.loads((HERE/"triage_transcript.json").read_text())
    assert trace["synthetic"] is True
    assert trace["outcome"]["real_network_requests"] == 0
    assert trace["outcome"]["provider_calls"] == 0
    assert trace["kernel_fence_attested"] is False
    for entry in trace["tools"]:
        parsed=parse_tool_output(entry["tool"], (HERE/entry["source"]).read_bytes())
        assert parsed["format"] == entry["format"]
        assert parsed["entries"] == entry["observations"]
        assert parsed["masked"] is True
        assert parsed["parse_status"] == "parsed"
