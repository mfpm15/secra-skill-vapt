# Pinned sapper-v2 upstream source

- Upstream project: https://github.com/N1nEmAn/sapper-v2
- Pinned source commit: 697b30f77ebedf5e551a0595b3e883f9c25f9e73
- Source path: lib/sapper.py (copied into sapper.py without modifications)
- License: MIT (see LICENSE; retain original attribution)
- Integration: app/sapper_integration.py invokes only allowed graph CLI verbs:
  init, fact, intent, graph (read), validate.

The included upstream CLI has additional competition-oriented verbs. SECRA
does not expose them through its backend or dashboard. SECRA does not invoke
sapper auto, dispatch, arena, flag, worker shell, --skip-permissions, or
any competing CTF-specific functionality.

Use of the actual graph engine is distinct from integrating its full Tencent
competition commander/watchdog/worker swarm. No claim is made that SECRA
inherits the upstream benchmark score or fully autonomous offensive ability.

## SECRA Unified MCP adapter (post-v0.7)

The upstream MIT-licensed CLI in `sapper.py` is still unchanged. The SECRA bridge now also exposes two separately reviewed task-scoped MCP tools:

- `workflow.graph_initialize`: explicitly initialize a private graph for an existing authorized running task; no network, tmux, worker, flag, credential or model gateway access.
- `workflow.graph_frontier`: safely read graph validity, limited ready-intent IDs, and bounded fact/intent counts without leaking raw graph content to the model.

This is a **partial functional integration of the original graph engine**, not the Tencent competition commander/watchdog/worker swarm. The full swarm requires a benchmark arena API, model gateways, isolated workers and a different operator authorization policy; do not expose it as an unrestricted OpenCode command. SECRA graph-core, node/edge schemas and original frontier implementation are not changed. The unified OpenCode primary `secra` selects relevant specialists and handles the Sapper metadata through these reviewed tools.
