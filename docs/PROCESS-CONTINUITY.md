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
6. At a model switch, stage transition or session end, invoke read-only `workflow.handoff`. It creates an AES-GCM sealed checkpoint; the model gets only an abbreviated receipt.
7. Review suspected findings independently and maintain negative hypotheses, cleanup evidence and follow-up register as **operator-reviewed notes**. The checkpoint never invents these.
8. Generate a SHA-256 manifest before reporting/archiving; verify it after any changes. Archive uses a checked copy and leaves the original intact.

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
- The archive command verifies SHA-256 and retains the source; any unexpected source drift causes refusal. Review path permissions on the destination filesystem.

## Suggested evaluations

Run `tests/continuity` and `tests/workspace` on each CI change. Next evaluate E4 (secret-safe redaction) and E5 (handoff fidelity) against deterministic, synthetic fixtures, then evaluate E1–E3 in isolated authorized labs with equal budgets, fixed seeds and independent finding verification. Do not claim one model outperforms another from a single HTB run.

References:
- https://owasp.org/www-project-web-security-testing-guide/v42/
- https://csrc.nist.gov/pubs/sp/800/115/final
- https://opencode.ai/docs/agents/
