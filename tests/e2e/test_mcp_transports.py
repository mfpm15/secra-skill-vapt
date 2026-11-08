"""Real MCP stdio and Streamable HTTP transports, using official SDK Client."""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

from mcp import Client
from mcp.client.stdio import StdioServerParameters
from mcp.client.streamable_http import streamable_http_client
import httpx2


@pytest.mark.anyio
async def test_real_mcp_stdio_process_tools_list_and_call(tmp_path):
    env = {"SECRA_DATA_DIR": str(tmp_path),
           "SECRA_DASHBOARD_TOKEN": "ci-stdio-operator-token-123456"}
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "app.mcp.server", "--transport", "stdio"],
        env=env)
    async with Client(params) as client:
        listing = await client.list_tools()
        names = {x.name for x in listing.tools}
        assert {"demo.nmap_scan", "demo.httpx_probe", "local.http_head",
                "nmap.tcp_top20", "curl.http_head"} <= names
        # Without an authenticated, running task ID no process executes.
        refused = await client.call_tool("demo.nmap_scan",
                                         {"task_id": "00000000-0000-0000-0000-000000000000"})
        assert refused.structured_content["status"] == "denied"


@pytest.mark.anyio
async def test_real_streamable_http_process_tools_list_and_auth(tmp_path):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    token = "ci-http-operator-token-123456"
    env = dict(os.environ)
    env.update({"SECRA_DATA_DIR": str(tmp_path), "SECRA_DASHBOARD_TOKEN": token})
    process = subprocess.Popen([
        sys.executable, "-m", "app.mcp.server",
        "--transport", "http", "--port", str(port)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    url = f"http://127.0.0.1:{port}/mcp"
    try:
        listening = False
        for _ in range(100):
            try:
                urllib.request.urlopen(url, timeout=0.5)
            except urllib.error.HTTPError as exc:
                if exc.code in {400, 401, 403, 405, 406}:
                    listening = True
                    break
            except (OSError, TimeoutError):
                if process.poll() is not None:
                    break
                time.sleep(0.08)
        assert listening, "MCP HTTP server did not start on localhost"
        async with httpx2.AsyncClient(
            headers={"Authorization": "Bearer " + token},
            timeout=httpx2.Timeout(30.0, read=30.0)) as http:
            async with Client(streamable_http_client(url, http_client=http)) as client:
                listing = await client.list_tools()
                names = {tool.name for tool in listing.tools}
                assert "demo.nmap_scan" in names and "local.http_head" in names
                denied = await client.call_tool("curl.http_head", {
                    "task_id": "00000000-0000-0000-0000-000000000000", "port": 443})
                assert denied.structured_content["status"] == "denied"
    finally:
        process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=3)
