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
