# audit-existing.md — SECRA baseline audit

Scope: exact main commit 707c25f6747c641e33cfd3f2dd0422daf8bf7e76, dated 2026-11-08. All line numbers below refer to files at this commit, not later revisions. Verified against the complete Git tree (44 regular files), including the source, HTML, tests and CI workflow. Status legend: EXISTS = source is present; CALLED = execution path is wired; PROPOSED = absent from this baseline.

## 1. Entrypoint, API and persistence — existing code

| Status | Evidence by path:line | Observed behavior |
|---|---|---|
| EXISTS + CALLED | README.md:9-17; app/main.py:40,350-353 | Uvicorn starts FastAPI app.main:app; GET / serves app/static/index.html. Runtime is localhost by documented invocation, not enforced by FastAPI itself. |
| EXISTS + CALLED | app/main.py:35-42,80-82; app/static/index.html:42-46,130-134 | One environment/token-header check (X-Secra-Token); browser stores token in sessionStorage; no multi-user identity/RBAC. |
| EXISTS + CALLED | app/main.py:55-78 | Local SQLite database; engagement, event, and service tables; restart marks running engagements interrupted. Raw report text and target are stored plaintext. |
| EXISTS + CALLED | app/main.py:427-442; app/security.py:27-50 | Create engagement validates a single IPv4 target against IP/CIDR scope; user must attest authorized=true. Attestation is not independently authenticated written authorization. |
| EXISTS + CALLED | app/main.py:444-468 | List/detail/event endpoints; GET engagement exposes literal target and scope, not placeholders. |
| EXISTS + CALLED | app/main.py:469-493 | Start launches local worker thread, cancel sets an in-memory threading.Event. Two engagements may run, but one engagement's seven stages are sequential. |
| EXISTS + CALLED | app/main.py:495-502 | Download local Markdown report. |
| EXISTS + CALLED | app/main.py:91-95; app/security.py:16-25 | Logged event text receives best-effort regex redaction, not reversible tokenization. No entity map, collision handling or streaming carryover. |

## 2. Runner, Kali tools and HTTP boundary

| Status | Evidence by path:line | Observed behavior |
|---|---|---|
| EXISTS + CALLED | app/main.py:117-129,131-152,267-283 | run_argv() uses subprocess.Popen with argv and shell disabled; Nmap TCP connect top-20, T2, host timeout, XML parse. No general tool registry or per-risk policy. |
| EXISTS + CALLED | app/main.py:154-181,286-296 | curl HEAD checks for selected ports; redirects disabled; -k skips certificate verification. Only status summary is kept. |
| EXISTS + CALLED | app/main.py:117-129 | Timeout and cancel kill the immediate process only with proc.kill(), not the whole new process session/group. No durable process kill-switch ledger. |
| EXISTS, NOT USED AS EVIDENCE VAULT | app/main.py:119-129,132-150,169-180 | Raw stdout/stderr is held in memory and discarded/truncated; no append-only encrypted raw-output spool to disk before masking. |
| RISK, NOT A VERIFIED INCIDENT | app/main.py:119-129 | stdout/stderr pipes are not drained while polling; chatty subprocesses could block if pipe buffers fill. |
| EXISTS + CALLED | app/main.py:227-348 | Single pipeline walks Scope Guardian -> Recon -> HTTP Analyst -> Knowledge Curator -> LLM Advisor -> Verification -> Report Builder sequentially. Displaying seven labels does not mean seven concurrent agents. |
| EXISTS + CALLED | app/main.py:269-278,286-293,309-310 | Demo simulates service records and does not invoke the LLM; Live invokes bounded Nmap, curl and optional LLM. No Kali worker container, job queue or true autonomous agent tool calls. |
| MISSING | app/main.py:117-181,469-493; entire baseline Git tree | No server-enforced egress firewall, DNS pinning, runtime tool approval endpoint, risk-class registry, leased asset locks or durable cancellation. Scope currently guards one initial IP and fixed tool args. |

## 3. LLM adapter and privacy

| Status | Evidence by path:line | Observed behavior |
|---|---|---|
| EXISTS + CALLED | app/main.py:38-39,183-223,409-425 | 9Router-compatible GET /models and POST /chat/completions; optional model ID; one globally configured endpoint and API key. |
| EXISTS + CALLED | app/security.py:52-66 | Model string validation; remote gateway must use HTTPS, loopback can use HTTP. |
| EXISTS + CALLED | app/security.py:68-98; app/main.py:200-223 | LLM payload uses ASSET_001 plus strictly allowed port numbers and service labels; local static skills are appended to a system prompt. |
| EXISTS + CALLED | app/knowledge.py:15-75; app/main.py:297-305,362-384 | 12 reviewed skills and deterministic routing from service labels. Local skill docs become LLM context through safe_skill_context(). |
| MISSING | app/security.py:7-25,68-98; app/main.py:183-223; baseline tree | No reversible placeholder mapping, rehydration, per-provider tier policy, no-mixed-provider fallback gate, model budget accounting, redacted structured tool-output channel or arbitrary text DLP. |
| HIGH-PRIORITY GAP | app/main.py:183-193 | gateway_request() sends supplied payload directly to configured gateway with no universal mandatory outbound sanitizer. The sole current llm_assessment call uses the safe serializer, but future callers could bypass it. |
| HIGH-PRIORITY GAP | app/main.py:203-223; README.md:49-59 | Current code does not enforce 9Router's effective upstream route / fallback policy. A model ID alone is not sufficient evidence of final provider. |
| PROPOSED | masking.md, router.md | Pre-LLM schema validator + deterministic redactor + local map vault + typed, fail-closed rehydration, and provider-specific egress policy. |

## 4. Sapper graph (DO NOT MODIFY)

| Status | Evidence by path:line | Observed behavior |
|---|---|---|
| EXISTS + CALLED | app/sapper_integration.py:18-21,29-73 | Verbatim pinned upstream graph CLI via restricted subprocess allowed verbs only. |
| EXISTS + CALLED | app/sapper_integration.py:83-131; app/main.py:257-263,266-339 | initialize_graph, stage_begin and stage_end are called from pipeline; stage status facts are persisted. |
| EXISTS + CALLED | app/sapper_integration.py:133-175; app/main.py:386-404 | Public graph serialization and upstream read-only frontier resolver exposed through API. |
| EXISTS + CALLED | app/static/index.html:113-115,158-182 | Read-only graph visualization with fact -> intent -> fact rows. |
| OUT OF SCOPE | vendor/sapper_v2/sapper.py; app/sapper_integration.py | No changes to graph core, frontier, or node/edge schema are required by this work. Runtime metadata lives in separate new tables. |

## 5. Dashboard and CI — existence versus calls

| Status | Evidence by path:line | Observed behavior |
|---|---|---|
| EXISTS + CALLED | app/static/index.html:68-101,184-187 | Engagement form, simulated/live selection, model input, authorization checkbox, stop button, service chips, log panel, Markdown download. |
| EXISTS + CALLED | app/static/index.html:122-141,183-191 | Authenticated fetch calls; UI polls /api/engagements/{eid} and /events every ~1350ms; no SSE or WebSocket. |
| EXISTS + CALLED | app/static/index.html:105-115,144-182 | Skill browser + graph viewer; dynamic refresh every ~4300ms. |
| PRESENTATION GAP | app/static/index.html:70-80,140-141 | Operator sees literal target IP; not a placeholder-only UI. Agent cards depict pipeline statuses, not actual parallel worker processes. |
| EXISTS | .github/workflows/ci.yml:1-24 | Ubuntu/Python 3.12 checkout; dependency installation; compileall app and vendor; pytest -q. |
| EXISTS + CI CALLED | tests/test_api.py:8-46 | Auth, initial scope validation, demo lifecycle, basic email/IP masking tests. |
| EXISTS + CI CALLED | tests/test_privacy_boundary.py:11-36 | Sanitized service metadata mock and optional JS syntax parse. |
| EXISTS + CI CALLED | tests/test_sapper_integration.py:9-45 | Pinned graph CLI, frontier and traversal/secret-field checks. |
| MISSING | .github/workflows/ci.yml:16-24; tests/ | No phase-1 leakage corpus, split-token streaming test, reversibility test, cross-provider route test, OS-level network isolation test, child-process kill test, crash-resume/replay test, or SSE resume test. |

## 6. Factual gap statement

Baseline works as a small local sequential assessment dashboard with a real Sapper fact/intent graph, a limited Kali runner, local skills and advisory-only LLM calls. It is **not** a parallel autonomous VAPT runtime with a reversible privacy gateway or audited execution sandbox. The seven new design files specify the seams to build, without retroactively claiming those features are operational.

Contracts to retain unchanged:

    from app.sapper_integration import (
        initialize_graph, stage_begin, stage_end, public_graph, resolve_frontier
    )
    from app.security import validate_scope, llm_safe_payload, assert_no_sensitive_payload

[ASUMSI] All audit line numbers are tied to immutable baseline 707c25f, rather than moving main. Reason: later merges change file offsets.

References: Git tree and code from the immutable SECRA commit above; .github/workflows/ci.yml for configured tests.
