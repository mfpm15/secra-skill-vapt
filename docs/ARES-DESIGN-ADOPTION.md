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
task UUID plus either 1-8 ordered manifest tool IDs or one of five fixed
offline goal templates (`engagement_overview`, `demo_web_baseline`,
`artifact_triage`, `sapper_graph_review`, `live_recon_review`). It validates the request with
closed JSON Schema, resolves current task mode/status from the local TaskStore,
then classifies each step using `inspect_capabilities` and the existing risk
and adapter metadata. It rejects unknown IDs and disallows duplicates,
raw parameters, target data, argv, scope or self-recursive previews. Exactly
one of `steps` and `goal` is required; there is no free-form LLM-generated
command, network destination, or tool argument.

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

Or use a fixed reviewed goal instead of a free-form step list:

```json
{"task_id": "OPERATOR_SUPPLIED_CANONICAL_UUID", "goal": "demo_web_baseline"}
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

## Stability checkpoint and safe rollout (deferred Kali stage)

The existing Kali installation is not remotely accessible from this GitHub
workflow. CI on Ubuntu 3.12 does not demonstrate that the currently-installed
Kali revision, OpenCode model or 9Router config work. The proven GitHub
compatibility anchor is `main@302be31` with a green CI; the **actual Kali**
commit must be captured locally before applying any changes.

**Before an upgrade, without touching the installed checkout:**

1. Record Kali VM snapshot/backup of the existing user config, engagement DB
   and encrypted evidence store using operator-approved secure storage.
   The metadata checkpoint below is NOT a content backup or rollback image.
2. Checkout the reviewed *candidate* to a separate non-executing staging
   directory, e.g. `$HOME/.local/share/secra/staging`. Never run its
   installer or change active `~/.config/opencode` at this stage.
3. Run the candidate's metadata tool against the still-running old location:

```bash
STAGE="$HOME/.local/share/secra/staging"
ACTIVE="$HOME/.local/share/secra/repo"
mkdir -p "$HOME/.local/state/secra/upgrade"
python3 "$STAGE/scripts/secra_upgrade_checkpoint.py" capture \
  --repo "$ACTIVE" \
  --output "$HOME/.local/state/secra/upgrade/before.json"
```

The `--data-dir` option is REQUIRED if the active SECRA database/vault uses
a non-default location not set in `SECRA_DATA_DIR`. No credentials or evidence
are included in the checkpoint; it records only file digests, source revision,
the legacy manifest contracts, installed agent/skill names and data presence.
The checkpoint is created with permission `0600` and refuses to overwrite.

**Do NOT deploy the candidate until all GitHub CI gates pass.** When a
maintenance window has been approved, perform a dry run and controlled install,
then capture a new local snapshot and compare with the old one:

```bash
python3 "$STAGE/scripts/secra_upgrade_checkpoint.py" compare \
  --repo "$ACTIVE" \
  --baseline "$HOME/.local/state/secra/upgrade/before.json"
```

Exit `0` means checked metadata are compatible, exit `2` indicates
differences requiring operator review, exit `1` means checkpoint error.
For security, modifying an existing OpenCode provider/model config hash is
treated as a failure even if the change was planned; any such change must
be manually inspected and separately approved. Never print config contents.

**CI release criteria:**

- The first **20** MCP schemas must match the baseline Git blob
  `5c79ed120f4a82d06d0506f13e79f487128f4d98`, and 9
  gateway/security/installer files must match reviewed baseline digests.
- All prior smoke, masking, 9Router transport/privacy, agent, MCP, vault,
  continuity and Sapper unit/integration tests must pass.
- The ARES-inspired plan preview must perform zero child execution and never
  classify gated/live/R3/R4 or unknown tools as execution-ready.
- The offline latency benchmark must report p50/p95/max; CI doesn't enforce
  an absolute runtime bound (shared runners are noisy). Actual improvements
  require repeated measurements on the SAME Kali host/load and comparable
  task/model conditions.
- No 9Router live correctness or Kali kernel fence proof is claimed by CI.

**Rollback:** stop the rollout if the comparison fails; keep the original
Kali VM snapshot and user-owned encrypted backups. Never use blind
`git reset --hard` or destructive DB replacement. This PR adds no
database migrations, but future database changes need explicit
expand/contract rollback compatibility testing.

Benchmark command for staging/CI (pure offline policy overhead):

```bash
python3 "$STAGE/scripts/secra_plan_benchmark.py" --iterations 250 --warmup 20
```

Do not extrapolate this p95 to model inference, tool execution or network
scans. Live deployment remains deferred.

## OpenCode v2 launcher compatibility (verified from upstream CLI)

OpenCode v2's root full-screen `opencode` command does **not** accept
`--agent`. Use `opencode mini --agent secra` for the single-command
interactive launcher, or `opencode run --agent secra "..."` for one-shot
scripted calls. The SECRA-owned launcher has been corrected to invoke
`opencode mini --agent secra` while preserving the existing managed V1
marker, so the reviewed `--replace` installer can safely back up and upgrade
an already installed managed script. Do not change model/provider or 9Router.

For the full-screen TUI, launch `opencode` and choose an available agent
inside the interface; do not use the unsupported root `--agent` flag.
Check `opencode mini --help`, `opencode run --help`, and
`opencode debug agents` on the actual Kali version before updating.

See upstream https://opencode.ai/docs/cli/commands and
https://github.com/anomalyco/opencode/issues/53728.

## Full-screen OpenCode v2 is the SECRA default (post-PR correction)

`mini` is only OpenCode's reduced interactive interface. SECRA's default
one-command `secra` now launches **full-screen `opencode`**, selecting the
SECRA primary agent through the process-local `OPENCODE_CONFIG_CONTENT`
`default_agent` override. When the operator has existing inline JSON config,
the launcher merges just the default-agent field and preserves the selected
provider, model, 9Router configuration and all other inline settings. It
refuses malformed inline settings instead of silently overriding them.
The launcher's override is not persisted to the global OpenCode config.
Already selected agents in resumed sessions may remain selected; `/agents`
lets the operator choose `secra` as needed. For maintenance, use normal
`opencode` and choose `build` in `/agents`. Never confuse `mini` with the
full TUI, and never pass unsupported `--agent` to the root command.
