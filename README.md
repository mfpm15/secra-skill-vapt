# SECRA — Local-first Agentic VAPT Operations

A local-first, scoped VAPT operations MVP with a reviewed gateway, encrypted evidence, a bounded model-to-tool loop, a localhost MCP/agent console, synthetic offline demo, pinned Sapper-v2 graph memory and an optional privacy-controlled 9Router model connection.

**Current scope:** single IPv4 target per engagement, top-20 TCP ports via Nmap, optional curl HTTP header checks, and advisory-only LLM analysis. **No automatic exploitation or confirmed vulnerability claims.** Demo results are clearly labeled SIMULATED. Never expose this single-user MVP directly to the internet.

## New agent console and MCP integration (developer preview)

The new single-page console is a separate localhost app; it does **not** activate the unverified Phase-2 network fence. Demo is offline, with synthetic Nmap and HTTPX observations. Use Python 3.12+, then:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export SECRA_DASHBOARD_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
export SECRA_DATA_DIR="$PWD/data"
python -m app
```

Open `http://127.0.0.1:8765` and enter the operator token. For the built-in **offline** loop, set target `127.0.0.1`, scope `127.0.0.1/32`, mode **demo**, leave model empty, confirm authorization, and click **Start task**. This dispatches two local no-network stub adapters and streams masked receipt events via SSE. Each raw stub result is stored as authenticated encrypted local evidence. Click **Stop** to prevent more work.

To issue a **real, bounded local HTTP HEAD** from the same UI, select **Local 127.0.0.1 HTTP HEAD**, set target `127.0.0.1` and exact scope `127.0.0.1/32`, supply an accessible 9Router model ID and API key, and authorize the engagement. A reviewed `local.http_head` (R2) tool opens a socket from loopback to loopback on a validated high port (1024–65535), verifies the peer, does not follow redirects or use a proxy, then seals the minimal status observation locally. This is an explicit local-only self-test exception, **not** a substitute for the Kali kernel egress fence. Start a deliberately owned local HTTP service before using it; model tool selection depends on the chosen provider supporting OpenAI-compatible function calling.

To use an actual configured model **only for selecting reviewed tools** (not unverified live network execution), set `SECRA_9ROUTER_BASE_URL` and `SECRA_9ROUTER_API_KEY` on the server, then enter its provider/model ID in the demo form. The request contains only canonical sanitized service metadata, public reviewed skill text and reduced tool schemas. The actual 9Router/provider integration has **not been independently tested with real credentials** in this repository's CI.

The standalone MCP server reads `app/mcp/manifest.json`, and supports the official MCP protocol (tools/list and tools/call) through two transports:

```bash
python -m app.mcp.server --transport stdio
python -m app.mcp.server --transport http --port 8766
```

For stdio, let a trusted MCP client spawn the process and speak protocol over stdin/stdout (do not type interactive shell commands into it). For Streamable HTTP, use `http://127.0.0.1:8766/mcp` with `Authorization: Bearer $SECRA_DASHBOARD_TOKEN`; remote exposure, DNS-rebinding origins, and missing tokens are blocked. MCP tool schemas are exact manifest JSON Schemas. Outputs are `{status, exit_code, summary, output_ref, masked}`. `output_ref` is an `evidence://<engagement UUID>/<run UUID>` local reference—not an outbound download URL.

Reviewed tools currently advertised: `inventory.read` (R0); `demo.nmap_scan` (R0, offline); `demo.httpx_probe` (R0, offline); `report.summary` (R0, offline); `local.http_head` (R2, real loopback-only HEAD); `nmap.tcp_top20` (R2, live gateway); `curl.http_head` (R2, live gateway); `http.authenticated_test` (R3, approval queue only); `prohibited.r4` (R4, always blocked). Add a new tool through an independently reviewed manifest entry and adapter stub. Agents cannot directly run arbitrary argv, install templates, use shells, or bypass the existing typed gateway.

The agent loop is bounded to **25 tool steps and 20 minutes**; a stopped, refused or exhausted task cannot silently restart. Every selected tool and masked result is written to a sequenced local event ledger. R3 approvals are review-only until a separate audited adapter is installed, and R4 stays forbidden. The existing gateway still denies live network operations **until a real Kali kernel egress attestation is present**. The real local-loopback HEAD route is implemented and tested with a fake 9Router response and a genuine localhost HTTP server, but **no live 9Router model credentials or actual provider response were available for verification**. Genuine Kali Nmap/curl execution also remains gated by kernel attestation.

For regression testing install `requirements-dev.txt` and run `python -m pytest tests/e2e -q -ra` and `python -m pytest -m "not lab" -q`. Privileged `tests/fence/ -m lab` requires an independently provisioned Kali VM; no lab proofs have been provided.

## Quick start on Kali Linux or Linux

Requires Python 3.11+, Nmap, and curl. In the repository root:

~~~bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export SECRA_DASHBOARD_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(30))')"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8765 --workers 1
~~~

Open http://127.0.0.1:8765 and enter the access token from the terminal. If you have not set a token, the app generates and prints a temporary one at startup.

1. Provide engagement name, target IPv4 address and authorized IP/CIDR scope which contains the target.
2. Choose Demo for offline UI testing. Live Nmap and curl remain blocked until independently verified OS egress attestation and approved deployment configuration are available.
3. Confirm written authorization and click Create & Launch Assessment.
4. Monitor seven agent stages, scrubbed logs and service observations.
5. Download the local Markdown report when finished.

Only assess assets you own or have explicit written authorization to test.

## Local pentester skills and genuine sapper-v2 memory

- **12 original, curated SKILL.md files** in knowledge/skills/, with a searchable dashboard knowledge panel and versioned metadata in knowledge/catalog.json.
- Deterministic service-based routing selects suitable specialist methodology (HTTP/TLS/API, network, scope governance, verification, reporting).
- Knowledge selections are recorded in the operator log and report. Skill content is static/public and included as a bounded advisory system prompt; target outputs are never inserted as trusted instructions.
- **Actual sapper-v2 graph CLI** is vendored under vendor/sapper_v2, pinned to commit 697b30f77ebedf5e551a0595b3e883f9c25f9e73 under MIT. Each engagement persists its own graph in data/sapper_graphs/<engagement UUID>/.sapper/.
- Every approved workflow stage creates an intent and closes it with a locally verified status fact. View these edges in the dashboard or authenticated GET /api/engagements/{id}/graph.
- Sapper **auto / dispatch / arena / CTF commander and watchdog are intentionally not enabled**: their autonomous shell and credential flows are unsuitable for customer environments without a separately audited sandbox and approval system.
- No customer IP, hostname, credential or raw evidence is written into the Sapper graph or sent through its CLI by the SECRA integration.

## 9Router and model selection

9Router supports an OpenAI-compatible API. Start and configure 9Router separately using https://docs.9router.com and set:

~~~bash
export SECRA_9ROUTER_BASE_URL=http://127.0.0.1:20128/v1
export SECRA_9ROUTER_API_KEY="YOUR_LOCAL_9ROUTER_KEY"
# Restart SECRA after changing the environment.
~~~

The model dropdown discovers exact IDs via GET /v1/models. Select a listed ID or type a provider/model identifier manually (Claude, DeepSeek, GLM, Muse or any model supported in your gateway). POST /v1/chat/completions is used for advisory suggestions only. There is no hidden agent-generated shell execution.

### Important privacy boundary

- Kali tools receive the real target IP locally so they can function.
- External LLM requests receive only ASSET_001 and positive-allowlisted numeric ports and service labels.
- Raw HTTP responses, headers, source IPs, hostnames, credentials, scan output and full reports are **never** forwarded to the LLM in this MVP.
- If no model or 9Router API key is configured, LLM analysis is skipped.
- A remote gateway must use HTTPS; the default local 9Router endpoint is loopback.
- Masking regex is only an extra safety layer for UI logs; strict outbound field allowlisting is the actual LLM data-minimization boundary.
- Upstream provider/gateway metadata processing, logging and fallback behavior are outside SECRA's control. Use a local model and egress restrictions for stringent confidentiality.

## Safety constraints and honest limitations

- Scope is enforced by backend twice: on create and immediately before tool execution.
- Fixed argument arrays, no shell interpolation, no unrestricted command execution.
- Restricted tool execution: Nmap top 20 TCP ports with T2 pacing and timeouts, HTTP header-only probes, max two concurrent runs, cancel support.
- No brute forcing, authenticated attacks, exploitation, C2, persistence, or lateral movement.
- Evidence is not automatically turned into findings. Open ports are observations only.
- Local SQLite persists engagement target IPs and reports **in plaintext**. Use restrictive filesystem permissions and full-disk encryption.
- One local operator only: the access token is not production RBAC, and the server must bind to 127.0.0.1.
- The UI uses 1.35-second polling for near-real-time updates, not a distributed event-stream backend.
- Workers are in-process; interrupted runs require operator restart, not durable queue recovery.

## Test

~~~bash
pip install -r requirements-dev.txt
python -m pytest -q
~~~

Tests cover scope, masking, LLM payload schema, authentication, knowledge selection, genuine sapper-v2 graph operations, demo mode and report generation. CI runs on PRs.

## Architecture and next steps

See docs/ARCHITECTURE.md for the roadmap toward resilient agent orchestration, Kali containers, scope policy, adapter integrations, OWASP skills, encryption, RBAC, and proper observability.

## Attribution and licensing

SECRA's initial source is independently written. Other named projects are research references only. Check AGPL, GPL and CC-BY-SA obligations before copying or embedding third-party code or content.
