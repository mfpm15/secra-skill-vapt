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

Reviewed tools currently advertised (**12 total, with several demo/blocked or approval-only**): `inventory.read` (R0); `demo.nmap_scan` (R0, offline); `demo.httpx_probe` (R0, offline); `report.summary` (R0, offline); `local.http_head` (R2, real loopback-only HEAD); `nmap.tcp_top20` (R2, live gateway); `curl.http_head` (R2, live gateway); `http.authenticated_test` (R3, approval queue only); `prohibited.r4` (R4, always blocked); and `workflow.handoff` (R0, read-only sealed continuity checkpoint). `workflow.lead_propose` (R0, unverified, sanitized hypothesis proposal only). `workflow.capabilities` (R0, offline mode-aware readiness; never attests the kernel fence). Add a new tool through an independently reviewed manifest entry and adapter stub. Agents cannot directly run arbitrary argv, install templates, use shells, or bypass the existing typed gateway.

The agent loop is bounded to **25 tool steps and 20 minutes**; a stopped, refused or exhausted task cannot silently restart. Every selected tool and masked result is written to a sequenced local event ledger. R3 approvals are review-only until a separate audited adapter is installed, and R4 stays forbidden. The existing gateway still denies live network operations **until a real Kali kernel egress attestation is present**. The real local-loopback HEAD route is implemented and tested with a fake 9Router response and a genuine localhost HTTP server, but **no live 9Router model credentials or actual provider response were available for verification**. Genuine Kali Nmap/curl execution also remains gated by kernel attestation.

For regression testing install `requirements-dev.txt` and run `python -m pytest tests/e2e -q -ra` and `python -m pytest -m "not lab" -q`. Privileged `tests/fence/ -m lab` requires an independently provisioned Kali VM; no lab proofs have been provided.

## Bug bounty casework and model evaluation (v0.6 preview)

SECRA now includes **operator-only**, offline bug bounty report quality checks, a **per-task encrypted case bundle** that includes filtered SQLite plus the corresponding AES-GCM vault evidence, a synthetic model tool-choice benchmark (optional local 9Router model), and non-intrusive Kali live fence prerequisite diagnostics.

- `scripts/secra_bounty_report.py`: requires a locally signed lead, sealed evidence, actual human-reproduced PoC and current program-rule confirmations; creates a private draft, **never submits**.
- `scripts/secra_case_bundle.py`: encrypts one completed engagement's workspace, SQLite and task vault into one passphrase-protected bundle; restores only to a new directory.
- `scripts/secra_model_eval.py`: 3 fixed synthetic tool-choice scenarios; **does not measure real VAPT exploit success**.
- `scripts/secra_live_preflight.py`: checks Kali setup prerequisites but intentionally **does not certify kernel network enforcement**.

See [docs/BUGBOUNTY-OPERATIONS.md](docs/BUGBOUNTY-OPERATIONS.md). Existing production limits remain: a single IPv4 target, very few reviewed live adapters, and no unrestricted shell or generalized bug-bounty wildcard domain scope. Confirm each program's scope and human-in-the-loop testing rules before live use.

## Complete offline agent smoke (v0.5 preview)

Run a temporary, network-free synthetic workflow from any directory:

~~~bash
python3 /absolute/path/to/secra/scripts/secra_smoke.py
~~~

It exercises operator-style task creation, capability preflight, unverified lead proposal, the bounded FakeDemoModel→reviewed demo MCP adapters→vault loop, handoff, workspace manifest, and multi-source case-integrity check. It reports simulation-only results and never tests real external model correctness or Kali network execution. The backend also enforces SQLite-atomic call ceilings across model/MCP sessions to avoid unlimited retry loops.

## Reliability and evidence-integrity preflight (v0.5 preview)

New read-only MCP `workflow.capabilities` tells the agent which reviewed tools match the current task mode and status, distinguishing offline fixtures, loopback-only, proposals, approval-only, blocked and live-gated capabilities. It never connects to a target or claims fence attestation. OpenCode `secra-vapt` requests this before choosing a tool.

New `scripts/secra_casecheck.py` validates the workspace SHA-256 manifest against files, each referenced AES-GCM evidence seal, and unfinished SQLite tool-run audit rows. Outputs are metadata only; decrypted evidence, scope, credentials and target IP are not returned. Use `--strict` for a nonzero exit if integrity requires review. A successful integrity check does **not** independently verify findings or turn the workspace-only archive into a full-case backup; SQLite and encrypted vault are still retained separately.

The localhost operator console has **Tool readiness** and **Case integrity** controls. See [docs/AGENT-RELIABILITY.md](docs/AGENT-RELIABILITY.md) for commands and operational limits.

## Versioned operator lead registry (v0.4 preview)

The localhost console now includes a **Hypothesis & verification board**. Short sanitized hypotheses, active/negative review states, reason-coded transitions, and immutable UTC history persist in SQLite across OpenCode model/context switches. The model receives only safe lead IDs/statuses and evidence references in `workflow.handoff`, never raw titles or targets. Stale updates are rejected by version checks; promotion to `verified` requires authenticated operator sign-off and **two distinct completed, non-simulated sealed tool receipts** (not a guarantee of independent human verification). `demo` findings cannot be verified.

Do not regard empty `05-memory/leads.jsonl` as the definitive registry: the new SQLite lead tables are authoritative. The engagement workspace archive excludes the separate local TaskStore database and encrypted evidence vault; back up those explicitly if a complete case archive is needed. See [docs/PROCESS-CONTINUITY.md](docs/PROCESS-CONTINUITY.md).

## Automatic private engagement workspace (v0.3 preview)

Every new authorized task now creates an idempotent private directory at `<SECRA_DATA_DIR>/engagements/<task-UUID>/`, with authorization, offline preflight, recon, evidence, reports, memory, phase ledger, cleanup and follow-up scaffolds. Files are owner-only; target/scope are never used as paths. A local tool-presence snapshot is captured without executing scanners or checking the target network.

The localhost console now includes **Workspace status**, **Create SHA-256 manifest**, **Verify integrity** and **Handoff checkpoint** controls. A CLI works globally from any working folder:

~~~bash
python3 scripts/secra_workspace.py status --task-id TASK_UUID
python3 scripts/secra_workspace.py manifest --task-id TASK_UUID
python3 scripts/secra_workspace.py verify --task-id TASK_UUID
~~~

Archive uses a zero-write dry-run and stages a hash-verified copy before publishing; the source is never deleted. Task run start/completion/stop automatically records explicit UTC testing-phase transitions. Other stages remain operator-recorded. See [docs/PROCESS-CONTINUITY.md](docs/PROCESS-CONTINUITY.md).

## Audited process continuity (v0.3 preview)

SECRA records each valid MCP invocation in a local UTC-started audit row **before dispatch**, then records its completion status, elapsed milliseconds and sealed evidence reference. No argv, real target or raw tool output is placed into the continuity record. Read-only MCP `workflow.handoff` (R0; both modes) creates a local AES-GCM-sealed, privacy-minimized checkpoint even after a task ends; the model receives only a short summary and an `evidence://` reference.

- Local operator endpoint: authenticated `GET /api/tasks/{task_id}/handoff`.
- Offline CLI from any working directory: `python3 /path/to/secra/scripts/secra_handoff.py --task-id UUID --data-dir /path/to/secra/data --output /private/HANDOFF.md` (creates file mode 0600).
- Global skill `secra-agent-continuity` describes checkpoint discipline and how to treat unknown facts.

This does **not** claim independently verified findings, TTFV, model fidelity or automatic cleanup. Legacy tasks with no process-audit rows are identified as unmeasured. See [docs/PROCESS-CONTINUITY.md](docs/PROCESS-CONTINUITY.md).

## OpenCode V2 global installation (Kali Linux)

**Recommended:** install native OpenCode V2 skills and 13 agent profiles globally under `~/.config/opencode/`. Use `secra-vapt` and `secra-ctf` from **any working directory**; the repository checkout is needed only for installation and the optional MCP backend. Operators configure each engagement's authorized target/scope inside the local SECRA UI, not through hardcoded agent settings.

~~~bash
python3 scripts/opencode_global.py install --major 2 --dry-run
python3 scripts/opencode_global.py install --major 2
python3 scripts/opencode_global.py verify --major 2
python3 scripts/opencode_toolcheck.py
opencode --agent secra-vapt
~~~

Installation **does not** grant unrestricted shell or live network access. SECRA MCP is opt-in and reviewed live tools remain subject to scope and kernel egress attestation. To enable MCP globally and optionally install externally reviewed knowledge see [docs/OPENCODE-V2-GLOBAL.md](docs/OPENCODE-V2-GLOBAL.md).

## OpenCode (Kali Linux) — curated VAPT/CTF knowledge

SECRA includes a **no-execution Python installer** for OpenCode skills and two project agents. Read [docs/OPENCODE-KALI.md](docs/OPENCODE-KALI.md) for scoped Kali setup, optional pre-reviewed third-party knowledge imports and version-aware MCP configuration.

~~~bash
python3 scripts/opencode_security.py install --scope project --dry-run
python3 scripts/opencode_security.py install --scope project
python3 scripts/opencode_security.py verify --scope project
opencode --agent secra-vapt
~~~

This installs **21 SECRA-authored skill references**. Another **14 allowlisted references** from Claude-Red, CTF Skills and Trail of Bits can be installed only after separate checkout/review and explicit opt-in. Third-party scripts and executable files are never copied. OpenCode skills do **not** bypass SECRA's approval, data-minimization or Kali kernel egress gates; live target operations remain unavailable until the independent attestation is satisfied.

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
