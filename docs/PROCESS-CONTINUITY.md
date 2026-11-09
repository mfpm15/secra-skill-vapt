# SECRA Process Continuity & Automatic Workspace — v0.3 Preview

This implementation incorporates lessons from the operator's HTB Takeoff retrospective (2026-11-09), but it does **not** import the separate `vapt/` scripts. SECRA retains its existing SQLite task store, encrypted AES-GCM evidence vault, reviewed MCP adapters, scope guard, and kernel fence. No changes to Sapper graph-core, frontier resolver, or node/edge schemas.

The implementation follows the evidence/reproducibility emphasis in OWASP WSTG 4.2 and the planning–execution–analysis–mitigation cycle in NIST SP 800-115.

## Automatically initialized engagement folders

As soon as a task passes authorization/scope validation and is created, its workspace is initialized under `<SECRA_DATA_DIR>/engagements/<task_uuid>/`, with directory mode 0700 and starter files mode 0600:

~~~text
<SECRA_DATA_DIR>/
├── agent-events.sqlite3
├── engagements/
│   └── <task-uuid>/
│       ├── engagement.json                # task UUID + ASSET_001 alias, no IP
│       ├── README.md
│       ├── 00-authorization/
│       ├── 00-preflight/
│       │   └── local-readiness.json       # installed tools, route/VPN: not checked
│       ├── 01-recon/
│       ├── 02-scripts/
│       ├── 03-evidence/
│       │   ├── network/
│       │   ├── web/
│       │   ├── api/
│       │   ├── findings/
│       │   ├── screenshots/
│       │   └── cleanup/CHECKLIST.md
│       ├── 04-reports/
│       ├── 05-memory/
│       │   ├── state.json
│       │   ├── chain.json
│       │   ├── leads.jsonl
│       │   └── negatives.jsonl
│       ├── 06-ledger/
│       │   ├── phases.jsonl
│       │   └── manifest.json              # generated on demand
│       └── 07-follow-up/REGISTER.md
└── evidence/                               # encrypted raw evidence; separate
~~~

These are **scaffolds**, not claims that a scan, cleanup or finding was completed. The private target/scope stays in the local task database, not in the directory name or starter notes. Never place raw credentials in plaintext workspace notes.

Initialization is idempotent and preserves existing operator notes. It never creates nested `recon/recon` from moves, never copies untrusted scripts, and refuses symlinked workspace files during manifest generation.

## Operator workflow

1. Fill the authorized target and scope in the SECRA localhost operator UI. No global target is preconfigured.
2. The task receives a UUID and an automatic private workspace with live `intake` and `preflight` phase-start events.
3. An offline preflight records which binaries are on PATH but **does not execute them**. Route and VPN readiness remain explicitly unverified until locally checked.
4. Agent loads reviewed knowledge on demand. Every schema-valid MCP invocation is durably audited **before** dispatch with real UTC timestamps, outcome, elapsed milliseconds and sealed evidence references.
5. Operator or coordinating agent records explicit phase transitions; unrecorded phase times remain unknown, not backfilled from file mtimes.
6. When the task starts/stops/completes, SECRA also automatically records testing-phase UTC events. At a model switch, stage transition or session end, invoke read-only `workflow.handoff`. It creates an AES-GCM sealed checkpoint; the model gets only an abbreviated receipt.
7. Review suspected findings independently and maintain negative hypotheses, cleanup evidence and follow-up register as **operator-reviewed notes**. The checkpoint never invents these.
8. Generate a SHA-256 manifest before reporting/archiving; verify it after any changes. Archive stages the copy in the destination parent, verifies hashes, then publishes it; failure leaves no finalized partial archive and never deletes the source.

## Using the CLI without changing OpenCode working directory

~~~bash
REPO="$HOME/.local/share/secra/repo"
TASK_ID="PUT-AN-EXISTING-AUTHORIZED-TASK-UUID-HERE"

python3 "$REPO/scripts/secra_workspace.py" status --task-id "$TASK_ID"
python3 "$REPO/scripts/secra_workspace.py" preflight --task-id "$TASK_ID"
python3 "$REPO/scripts/secra_workspace.py" phase --task-id "$TASK_ID" \
    --stage recon --event started

python3 "$REPO/scripts/secra_handoff.py" \
    --task-id "$TASK_ID" --output "$HOME/HANDOFF-secra.md"

python3 "$REPO/scripts/secra_workspace.py" manifest --task-id "$TASK_ID"
python3 "$REPO/scripts/secra_workspace.py" verify --task-id "$TASK_ID"

# Preview does not create any archive files or directories:
python3 "$REPO/scripts/secra_workspace.py" archive \
    --task-id "$TASK_ID" --destination "$HOME/archives/secra-TASK" 

# After the manifest is verified and the destination parent exists:
python3 "$REPO/scripts/secra_workspace.py" archive \
    --task-id "$TASK_ID" --destination "$HOME/archives/secra-TASK" --apply
~~~

All commands above use the repository's default `data/`. Specify `--data-dir /private/secra-data` before the subcommand when `SECRA_DATA_DIR` is set differently. Outputs contain UUIDs, timestamps, paths, hashes or sanitized metadata. They do not print raw target addresses.

The operator UI also exposes authenticated local routes:

- `GET /api/tasks/{uuid}/workspace` — stage/preflight/manifest readiness.
- `POST /api/tasks/{uuid}/phase` — explicit `{"stage":"recon","event":"started"}`.
- `POST /api/tasks/{uuid}/manifest` — regenerate manifest after changes.
- `GET /api/tasks/{uuid}/manifest/verify` — compare current files with manifest.
- `GET /api/tasks/{uuid}/handoff` — privacy-safe checkpoint.

The CLI and REST endpoints only work with valid existing authorized task UUIDs. They do not grant permission to send traffic or bypass the tool dispatcher.

## v0.4 Process lead registry (new)

The Takeoff retrospective identified an operational gap: an empty `leads.jsonl` scaffold is not a durable source of truth for active hypotheses, negative results or independent review. SECRA now adds an **operator-owned, versioned SQLite registry** in the existing private `agent-events.sqlite3` (new tables `process_leads` and immutable `process_lead_events`, separate from the Sapper graph).

Each lead has an opaque UUID, category, sanitized short title, status, version, reference to a completed/sealed real observation (optional until review), reason code and UTC history.

Status transitions are constrained:

~~~text
open --> testing --> review_requested --> verified --> closed
  |       |                 |
  v       v                 v
negative <--               rejected
  |
  +--> testing (only with reason "reopened")
~~~

`verified` is a **local operator sign-off status**; it requires two *distinct*, completed, non-simulated, approved observation receipts from the same task, with valid AES-GCM seals. This does not replace an independent human verifier or automatically prove exploitability. `demo` tasks can never produce operator-verified findings. The model cannot promote a lead directly: no lead-writing MCP tool is exposed. Invalid states, missing seals, cross-engagement references, stale version updates, or simulated receipts are denied.

The local operator UI has a **Hypothesis & verification board** to create, inspect and transition leads. All REST endpoints require the existing local operator token:

- `GET /api/tasks/{uuid}/leads` — operator-only titles, statuses, versions and references.
- `POST /api/tasks/{uuid}/leads` — `{"category":"web","title":"Header control review"}`.
- `GET /api/tasks/{uuid}/leads/{lead_id}/events` — ordered decision history.
- `POST /api/tasks/{uuid}/leads/{lead_id}/transition` — version-controlled update, e.g. `{"next_status":"testing","reason":"started","expected_version":1}`.

`workflow.handoff` and `GET .../handoff` include the compact lead status/count and opaque IDs, **not lead titles, raw descriptions, target values or credentials**. Model-switch context can identify the unresolved work without reading unrelated evidence.

The old `05-memory/leads.jsonl` and `negatives.jsonl` files remain **legacy scaffolds**, not automatically synchronized authoritative data sources. The SQL lead registry is authoritative until a separately audited export function is added. This avoids concurrent agent writes to JSONL and removes the ambiguity that caused Takeoff's post-hoc reconstruction.

### Operational cautions

- The lead registry is stored in the local SQLite file (0600) without field-level encryption. Do not put sensitive findings, IPs, passwords, tokens, personal data or live payloads in titles; the API rejects patterns known to contain sensitive material, but cannot guarantee perfect DLP.
- The operator is responsible for confirming what was actually tested. An unsuccessful gateway call is **not** automatically a negative finding.
- A reviewed lead is a tracked process decision; the independent verifier process remains separate.
- Reports should use actual evidence references and a reviewer note, not treat an arbitrary tool receipt as conclusive proof of a vulnerability.
- Archives created by `secra_workspace.py` include the per-engagement workspace only. The **encrypted evidence vault and TaskStore SQLite database are stored outside it** and are not bundled; retain/back up those separately under your own data retention policy.

## What can be measured now

- Audited invocation count, completed/simulated versus blocked/denied, unfinished audit records.
- Actual UTC start/finish timestamps and durations for reviewed tool requests.
- Repeated tool *names* as an approximation. Identical commands and identical arguments are **not** available, because sensitive argument logging is deliberately omitted.
- File count/size and SHA-256 of all workspace files, with duplicate hashes and manifest drift.
- Explicit phase event timestamps (not retrospectively inferred from mtimes).

Not yet measured: independent verified finding count, TTFV, handoff fidelity, real model latency, quality of hypothesis pivots or cleanup effectiveness. The model cannot infer those from tool receipts alone.

## Known limitations and next increments

- The previously created engagement DB and raw evidence live locally; the generated files have no automatic full-disk encryption. The AES-GCM vault remains the trusted storage for secret-bearing tool results.
- This first increment captures **offline** tool presence only; a verified Kali VPN route and privileged egress attestation must be provided separately before live assessment.
- Phase transitions are explicit and local; no vulnerable hypothesis is automatically confirmed, no notes are promoted as trusted knowledge, and cleanup is never executed without operator approval.
- Metadata-only checkpoints cannot reconstruct complete chains unless analysts separately preserve verified facts, negative leads and cleanup proofs.
- The archive command verifies SHA-256, stages before publish, and retains the source; any unexpected source drift causes refusal. Review path permissions on the destination filesystem.

## Suggested evaluations

Run `tests/continuity` and `tests/workspace` on each CI change. Next evaluate E4 (secret-safe redaction) and E5 (handoff fidelity) against deterministic, synthetic fixtures, then evaluate E1–E3 in isolated authorized labs with equal budgets, fixed seeds and independent finding verification. Do not claim one model outperforms another from a single HTB run.

References:
- https://owasp.org/www-project-web-security-testing-guide/v42/
- https://csrc.nist.gov/pubs/sp/800/115/final
- https://opencode.ai/docs/agents/
