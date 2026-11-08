"""Official MCP SDK v2 low-level server (stdio + Streamable HTTP).

The low-level Server lets the manifest supply the exact JSON schemas.
HTTP listens on localhost and requires an operator bearer token; stdio is
intended only for an authenticated, locally launched MCP client process.
"""
from __future__ import annotations

import argparse
import asyncio
import hmac
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server
from mcp.types import (CallToolRequestParams, CallToolResult, ListToolsResult,
                       PaginatedRequestParams, TextContent, Tool)

from .dispatcher import ToolDispatcher
from .manifest import ToolManifest, OUTPUT_SCHEMA

DATA = Path(os.environ.get("SECRA_DATA_DIR", str(Path(__file__).resolve().parents[2] / "data")))


def create_server(dispatcher: ToolDispatcher | None = None,
                  manifest: ToolManifest | None = None) -> Server:
    reviewed = manifest or ToolManifest()
    engine = dispatcher or ToolDispatcher(DATA, manifest=reviewed)

    async def list_tools(ctx: ServerRequestContext,
                         params: PaginatedRequestParams | None) -> ListToolsResult:
        return ListToolsResult(tools=[
            Tool(name=definition.name, description=definition.description,
                 input_schema=definition.input_schema, output_schema=OUTPUT_SCHEMA)
            for definition in reviewed.visible()
        ])

    async def call_tool(ctx: ServerRequestContext,
                        params: CallToolRequestParams) -> CallToolResult:
        # The low-level MCP SDK does NOT validate arbitrary tool input schemas.
        # The dispatcher validates both name and arguments, including task ACL.
        outcome = await asyncio.to_thread(engine.call, params.name, params.arguments or {})
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(outcome, sort_keys=True))],
            structured_content=outcome,
            is_error=outcome["status"] in {"blocked", "denied", "cancelled"},
        )

    return Server("SECRA", version="0.2.0",
                  on_list_tools=list_tools, on_call_tool=call_tool)


class LocalHTTPAuth:
    """ASGI authentication and DNS-rebinding protection at the HTTP boundary."""
    def __init__(self, wrapped):
        self.wrapped = wrapped

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.wrapped(scope, receive, send)
            return
        headers = {key.decode("latin1").lower(): val.decode("latin1")
                   for key, val in scope.get("headers", [])}
        hostname = headers.get("host", "").split(":")[0]
        origin = headers.get("origin")
        token = os.environ.get("SECRA_DASHBOARD_TOKEN", "")
        auth = headers.get("authorization", "")
        verified = (bool(token) and len(token) >= 16 and
                    hmac.compare_digest(auth, "Bearer " + token))
        if hostname not in {"localhost", "127.0.0.1"}:
            await self._deny(send, 403)
            return
        if origin:
            parsed = urlsplit(origin)
            if parsed.hostname not in {"localhost", "127.0.0.1"} or parsed.scheme != "http":
                await self._deny(send, 403)
                return
        if not token or len(token) < 16:
            await self._deny(send, 503)
            return
        if not verified:
            await self._deny(send, 401)
            return
        await self.wrapped(scope, receive, send)

    @staticmethod
    async def _deny(send, status: int):
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"),
                                (b"cache-control", b"no-store")]})
        await send({"type": "http.response.body", "body": b'{"error":"MCP access denied"}'})


def build_http_app(dispatcher: ToolDispatcher | None = None):
    server = create_server(dispatcher=dispatcher)
    # Preserve SDK transport lifecycle; the ASGI wrapper is intentionally thin.
    return LocalHTTPAuth(server.streamable_http_app(
        streamable_http_path="/mcp", stateless_http=True,
        json_response=True))


app = build_http_app()


async def run_stdio() -> None:
    server = create_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--transport", choices=("stdio", "http"), default="stdio")
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args(argv)
    if args.transport == "stdio":
        asyncio.run(run_stdio())
        return
    if not (os.environ.get("SECRA_DASHBOARD_TOKEN") and
            len(os.environ["SECRA_DASHBOARD_TOKEN"]) >= 16):
        raise SystemExit("Set SECRA_DASHBOARD_TOKEN (>=16 characters) before HTTP MCP.")
    import uvicorn
    uvicorn.run("app.mcp.server:app", host="127.0.0.1", port=args.port,
                workers=1, log_level="warning")


if __name__ == "__main__":
    main()
