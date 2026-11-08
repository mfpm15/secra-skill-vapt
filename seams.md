# seams.md — five SECRA integration seams

## 1. Input — scope-checked job to graph initialization

Signature: initialize_graph(eid: str, data_dir: pathlib.Path) -> str

Direction: SECRA canonical engagement UUID -> validated local graph directory -> upstream CLI init / fact -> initial fact ID.

Contract: validate_scope(target, scope) must run first, along with operator authorized attestation. Only a canonical UUID crosses to the graph adapter; IP/CIDR, headers, credentials and prompt content do not.

Disable competition: allowlisted init / fact operations only. No auto, dispatch, arena or flag operations.

## 2. State — fact -> intent -> fact

Signatures:
- stage_begin(eid: str, data_dir: Path, title: str, parent_id: str) -> str
- stage_end(eid: str, data_dir: Path, title: str, intent_id: str, observation: str) -> str

Direction: SECRA stage label -> upstream intent --from f### -> i###; locally validated status -> upstream fact --from-intent i### -> result f###.

Contract: stage names and result descriptions are restricted to short schema-controlled strings. Graph facts are non-sensitive progress summaries, not raw tool output. Upstream node/edge semantics remain intact.

Disable competition: Python constructs fixed argument arrays without shell invocation; model output cannot become a subprocess command.

## 3. Persistence — UUID-scoped filesystem graph

Signature: graph_store(eid: str, data_dir: Path) -> Path

Direction: local SECRA engagement ID -> data/sapper_graphs/<UUID>/.sapper -> upstream JSON files and locking. SQLite remains separate for engagement and events.

Contract: enforce canonical UUID; invoke python -I with minimized environment; preserve upstream atomic JSON writes and file lock.

Disable competition: do not run setup/hooks, tmux, watchdog, key rotation or global state. Graph exists only under the local per-engagement directory.

## 4. Approval hook — SECRA checks, not competition confirmation

Current signatures:
- CreateEngagement.authorized: bool
- validate_scope(target: str, scope: str) -> tuple[str, list[str]]

Direction: operator attestation -> FastAPI scope check -> bounded stage runner -> graph status facts.

Contract: authorized is only an attestation, not cryptographically verified written permission. No high-risk graph-mutating approval API exists in this version.

Disable competition: do not allow upstream confirm or --skip-permissions through the adapter.

[ASUMSI] Next approval contract is a signed decision bound to actor, action class, scope and expiry. Reason: a multi-user identity model has not been specified.

## 5. Output — filtered visualization and resolver

Signatures:
- public_graph(eid: str, data_dir: Path) -> dict
- resolve_frontier(eid: str, data_dir: Path) -> dict

Direction: upstream graph --format json plus frontier / validate -> filtered SECRA objects -> authenticated dashboard.

Contract: GET /api/engagements/{eid}/graph returns allowlisted title, ID, status, edge relationships; GET /frontier returns ready_ids and integrity verdict only. No raw graph docs are transferred to the model gateway.

Disable competition: output is read-only; no execution dispatcher, pengiriman hasil, or langkah verifikasi otomatis is triggered.
