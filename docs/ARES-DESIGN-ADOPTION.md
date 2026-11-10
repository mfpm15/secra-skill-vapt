# ARES research adoption — SECRA offline plan preflight

This work is an **original SECRA implementation inspired by architectural
patterns**, not a vendored or installed copy of ARES. Kali Linux rollout and
live network validation remain postponed.

## Upstream research

- Project: https://github.com/Mafifrizi/ARES (MIT; reviewed Nov 10, 2026,
  main commit `d09251374a82042f2d8069818febcb08289aa3d5`)
- `docs/engine_design.md`: goal-directed stages and explicit module inventory
- `ares/modules/ai/plan_validator.py`: reject hallucinated module IDs and
  require validated parameters before execution
- `ares/modules/descriptors.py`: first-party contract metadata / readiness
- `ares/core/execution_policy.py` and `docs/execution-policy.md`: separate
  **static candidate evaluation** from authenticated durable admission
- `ares/sdk/testing/harness.py`: synthetic validation and provenance checks

**Important upstream caveat:** ARES documents that legacy adaptive execution
is inactive in C-LIVE-v1 and its static policy/descriptors alone do not
authorize live execution. The presence of a catalog entry is not proof of
production readiness. ARES' offensive module implementations, EDR-bypass
techniques, and attack graph are **not** imported.

## What SECRA now implements

The existing MCP manifest remains the only inventory of reviewed callable
tools; the new `workflow.plan_preview` R0 adapter accepts **only** an operator
task UUID and 1-8 ordered manifest tool IDs. It validates the request with
closed JSON Schema, resolves current task mode/status from the local TaskStore,
then classifies each step using `inspect_capabilities` and the existing risk
and adapter metadata. It rejects unknown IDs and disallows duplicates,
raw parameters, target data, argv, scope or self-recursive previews.

Its output is a bounded, redacted summary with **0 child tool executions**;
one audit entry records the preview invocation itself. There is no execution
token, scheduler, queued job, shortcut to approve R3, scope attestation or
kernel fence proof. In particular:

- R4, R3, missing/unknown, incompatible-mode and stopped-task steps fail closed.
- Nmap/curl live gateway steps remain `blocked` without independently
  validated kernel enforcement, even if a separate plan has clean metadata.
- Local artifact and demo steps may be classified as local/simulation
  **candidates**; that is not an authorization to execute them.
- Existing Sapper graph-core, frontier resolver and node/edge schema are
  unchanged. OpenCode model/provider and 9Router configurations are unchanged.
- The global user entrypoint remains `secra` (OpenCode v2).
- The new tool adds **one** MCP entry (20 -> 21). It adds no offensive adapter.

## Manual, offline-only verification

```bash
python -m pytest tests/process/test_ares_plan_preview.py -q
python -m pytest tests/opencode tests/process tests/e2e -q
python -m pytest -m "not lab" -q
```

After registering SECRA MCP on a locally authorized demo task, the model can
call `workflow.plan_preview` with:

```json
{
  "task_id": "OPERATOR_SUPPLIED_CANONICAL_UUID",
  "steps": ["inventory.read", "demo.nmap_scan", "nmap.tcp_top20"]
}
```

Expected: metadata and simulation candidates, plus the live Nmap step blocked
in demo mode. This is **not** a network scan.

## Later adoption (not shipped)

1. Typed parameter contracts and provenance-aware local-only module SDK.
2. Operator-reviewable DAG plan proposals mapped to the existing *sanitized*
   Sapper bridge **without** touching graph core/frontier/schema.
3. Durable per-attempt operator approval, role and budget authority binding,
   replay-safe receipts, stop/timeout settlement and actual kernel fence lab
   attestation **before** any multi-tool execution.
4. UI campaign planner, graph exploration, and report improvements after
   backend policy and provenance tests.
