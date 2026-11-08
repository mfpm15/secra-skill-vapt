# SECRA — Local-first Agentic VAPT Operations

A functional, scoped VAPT dashboard MVP with near-real-time agent progress, local Kali tooling, structured service inventory, privacy-controlled optional LLM advice through 9Router, and a downloadable Markdown report.

**Current scope:** single IPv4 target per engagement, top-20 TCP ports via Nmap, optional curl HTTP header checks, and advisory-only LLM analysis. **No automatic exploitation or confirmed vulnerability claims.** Demo results are clearly labeled SIMULATED. Never expose this single-user MVP directly to the internet.

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
2. Choose Demo for UI testing or Live to run locally installed Nmap and curl.
3. Confirm written authorization and click Create & Launch Assessment.
4. Monitor six agent stages, scrubbed logs and service observations.
5. Download the local Markdown report when finished.

Only assess assets you own or have explicit written authorization to test.

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

Tests cover scope, masking, LLM payload schema, authentication, demo mode and report generation. CI runs on PRs.

## Architecture and next steps

See docs/ARCHITECTURE.md for the roadmap toward resilient agent orchestration, Kali containers, scope policy, adapter integrations, OWASP skills, encryption, RBAC, and proper observability.

## Attribution and licensing

SECRA's initial source is independently written. Other named projects are research references only. Check AGPL, GPL and CC-BY-SA obligations before copying or embedding third-party code or content.
