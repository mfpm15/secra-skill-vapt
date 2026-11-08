# diff-risk.md — upstream divergence and upgrade risk

## Delta to pinned upstream

| Surface | Upstream | SECRA delta |
|---|---|---|
| Graph source | Executable lib/sapper.py (mode 100755) | Byte-identical vendor/sapper_v2/sapper.py (mode 100644); invoked through Python |
| Runtime | Full CLI and general optional agent orchestration | Only init, fact, intent, graph, frontier, validate reachable in app adapter |
| State root | Project .sapper directory | data/sapper_graphs/<UUID>/.sapper per engagement |
| Graph content | Arbitrary facts, kinds, data and docs | Short, allowlisted progress facts with sensitive-pattern rejection |
| Resolver | frontier and mutating work operations | frontier/validate read-only; no claim/confirm/dispatch routes |
| Model boundary | Optional agent CLI and templates | SECRA 9Router advice independent of Sapper graph, with positive allowlist |
| Dashboard | Upstream generated HTML view | Authenticated SECRA graph view with bounded fields |
| Knowledge | Competition knowledge/templates | 12 original versioned SKILL.md packs with references |

**No edits are made to upstream sapper.py bytes.** The fork-like behavior changes are implemented only by the SECRA adapter, knowledge router and dashboard.

## Upgrade risks and controls

1. CLI argument/response drift: pin immutable source SHA; rerun command-level integration tests.
2. Graph schema evolution: diff fact, intent, source_intent and to fields; add versioned migrations before loading old graphs.
3. Interrupted writes or incomplete intents: keep upstream validation and atomic-write behavior; add durable recovery and reconciliation.
4. File-lock portability: upstream uses fcntl.flock; Linux/Kali baseline supported; document other operating systems separately.
5. Source exposure: the vendored CLI still contains competition commands even though SECRA denies them. Never install it globally or expose raw command invocation via HTTP.
6. Unstructured data exposure: reject token-like or IP/email content in graph status text; keep the full graph out of LLM messages and avoid logging upstream stderr.
7. Supply-chain and licensing: preserve MIT LICENSE; compare upstream tree and reviewed source blobs; no automatic unreviewed upstream updates.

## Required upgrade gate

- Update pin.md with new upstream commit/date/license and compare Git blob IDs.
- Review source diff, particularly Store, node schema, parser and allowed command contracts.
- Verify all privacy and resolver tests, including invalid graph and interrupted intent cases.
- Confirm no new CLI verbs reachable through SECRA HTTP or model output.
- Record rollback SHA and decide how old graph files are migrated.
- Run full CI before merge.

[ASUMSI] The production target is Linux-compatible. Reason: the current SECRA stack and upstream file locking rely on Linux/Unix semantics.
