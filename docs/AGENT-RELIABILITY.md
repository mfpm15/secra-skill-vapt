# SECRA Agent Reliability — v0.5 preview

This release improves a bounded, operator-authorized assistant. It does not make the system an autonomous exploitation framework or attest the Kali kernel egress fence.

## Research basis

- OpenCode v2: agent permissions are ordered, and each subagent has separate permissions. https://opencode.ai/v2/docs/permissions/
- MCP: server-side input validation, access controls, output sanitization, rate limits and logging are required. https://modelcontextprotocol.io/specification/2026-07-28/server/tools
- OWASP: agent tools and skills need an independently enforced trust boundary. https://genai.owasp.org/initiatives/agentic-security-initiative/
- PentAGI: specialized agents, sandbox, memory and observability are complementary; a manifest entry is not an installed executable. https://pentagi.com/docs/concepts/architecture/
- OWASP WSTG v4.2: preserve reproducible testing evidence and independently support conclusions. https://wstg.owasp.org/v4.2/5-Reporting/

## New capability preflight

The reviewed R0 MCP tool workflow.capabilities accepts an opaque authorized task ID. It never opens sockets or runs a scanner. It reports task mode, status and tool classifications:

- read_only: process/status reading
- local_metadata: local reviewed metadata
- simulated: offline fixture only, never a live finding
- proposal_only: unverified hypothesis; no test execution
- local_only: loopback action with operator permissions
- gated: live adapter exists, but fence, scope, binary pinning are NOT attested
- operator_review: approval-only, no executable adapter
- blocked: prohibited or mismatched mode/status

OpenCode secra-vapt should request this preflight before selecting a tool. The localhost operator API also exposes GET /api/tasks/{id}/capabilities, and the UI has a Tool readiness control.

Preflight is not a grant of execution. The independent dispatcher must still validate each actual call.

## New full-case integrity check

The SECRA workspace-only archive intentionally excludes the separate SQLite task database and encrypted evidence vault. To avoid mistaking a workspace checksum for a complete case, run an offline case audit.

Commands from any directory (the repo is only a source path):

~~~bash
REPO="$HOME/.local/share/secra/repo"
TASK_ID="PUT-YOUR-VALID-TASK-UUID-HERE"

python3 "$REPO/scripts/secra_workspace.py" manifest \
  --task-id "$TASK_ID"

python3 "$REPO/scripts/secra_casecheck.py" \
  --task-id "$TASK_ID" --strict
~~~

The check compares workspace SHA-256 manifest state, unfinished tool-audit records and task-scoped evidence:// references, including AES-GCM seal verification. It reads but never returns decrypted evidence. It never sends customer IPs, credentials or raw tool results to an external model. It bounds the inspection window and reports when that window is truncated.

- Exit 0: covered integrity checks passed; not a claim of a verified vulnerability.
- Exit 2: incomplete, corrupt, truncated or drifted evidence.
- Exit 1: invalid task, unavailable database, or an execution error.

Authenticated operator endpoint: GET /api/tasks/{id}/case-integrity. The UI includes a Case integrity control. Reports explicitly indicate that workspace archive copies exclude TaskStore SQLite and the encrypted evidence vault.

Do not use this check as the sole backup or evidence-retention policy. Full offline case backup design requires separate protection of the SQLite DB, AES vault, per-engagement keys, and the operator review record.

## Model working contract

1. Operator creates the engagement and supplies only its task UUID to a remote model.
2. Read workflow.capabilities before action. Reject unsafe or wrong-mode tool suggestions.
3. Load only the relevant reviewed skills and carry operator-approved lead UUIDs through handoffs.
4. Use the smallest reviewed observation needed. Do not retry failed kernel fence checks.
5. Label simulated, denied or blocked results accurately. Never call a tool receipt a confirmed vulnerability.
6. Request workflow.handoff at model/phase transitions. Only the local operator board can verify findings.
7. Inspect full-case integrity before finalizing reports; unresolved case-review failures must be disclosed.
8. Never force a specific model. Preserve the user's provider, reasoning effort and local runtime settings.

## Durable restart of the internal 9Router model loop

The internal SECRA AgentLoop now resumes after an interrupted model/process session using the committed tool audit instead of starting with an empty history. It restores only a bounded, sanitized last tool summary and recognized synthetic demo service metadata; it does **not** retrieve raw target data or pretend all analyst reasoning was saved.

- Already committed tool actions count toward the same maximum step budget across restarts.
- Existing completed demo observations allow a new model to continue without redoing the initial scan.
- Pending/incomplete audit records or a truncated audit window cause a fail-closed operator review, not automatic re-execution.
- Process-only actions such as capability preflight, checkpoint and hypothesis proposal do not consume the main execution step budget.
- AgentLoop is a separate internal path from OpenCode's direct MCP tool use. Full provider sessions, token usage and reasoning traces are not replayed by this change.

Existing live tool approval, scope and kernel checks remain independent of this continuity feature.

## Benchmark design (not yet implemented as a live model harness)

For comparing GPT-5.6 Thinker or other models, use identical isolated labs or official CTF environments, identical initial state, approved tools and time budgets, and independent grading. Report success against actual ground truth, evidence completeness, wrong-mode actions, rejected calls, model latency and repeat-work ratios. Current backend CI cannot prove general model superiority or real Kali live readiness.

## One-command isolated end-to-end smoke

After updating the Kali checkout, this checks the full safe control plane without requiring a model API key or connecting to a target:

~~~bash
REPO="$HOME/.local/share/secra/repo"
"$REPO/.venv/bin/python" "$REPO/scripts/secra_smoke.py"
~~~

Expected output states: preflight completed, hypothesis proposal completed, AgentLoop completed with two simulated tool steps, handoff completed, and evidence integrity integrity_ok. The script uses a fresh temporary demo task and deletes it on exit. This **does not** test real GPT-5.6 inference, CTF success, kernel egress attestation or live target coverage.

The SQLite tool-run audit also enforces fixed backend limits (2,000 invocations per task, 400 per tool), independently from OpenCode and the AgentLoop 25-step planning limit. Exceeding limits blocks new calls; restarting a model does not replenish the budget. Operators should create a new authorized engagement rather than disabling safeguards.

## Offline regression

~~~bash
REPO="$HOME/.local/share/secra/repo"
(cd "$REPO" && .venv/bin/python -m pytest \
  tests/process tests/continuity tests/workspace tests/opencode -q)
~~~
