# plan.md — ordered 10-step implementation plan

Status legend: DONE = implemented, VERIFY = requires CI confirmation, OPEN = additional engineering.

| # | Step | Testable Definition of Done | State |
|---|---|---|---|
| 1 | Freeze upstream provenance | pin.md distinguishes SECRA baseline SHA from upstream SHA; blob hashes are reproducible | DONE |
| 2 | Inventory graph-core, memory, resolver and excluded modes | inventory.md lists exact imported and nonexposed module paths | DONE |
| 3 | Vendor upstream graph engine and MIT license | Git hash-object matches pinned source/LICENSE; compileall passes | DONE |
| 4 | Implement bounded adapter | Invalid UUID/path and unsupported commands are rejected; no shell=True or model command execution | DONE |
| 5 | Connect pipeline state to graph facts and intents | Synthetic test shows f### -> i### -> f### and persisted to reference | DONE |
| 6 | Expose resolver and graph read APIs | Frontier returns upstream ready IDs before completion and none after; validate returns valid | DONE |
| 7 | Keep approval boundary explicit | Dynamic approve/confirm/dispatch are not in adaptor allowlist; attestation remains checked before pipeline | DONE for bounded workflow; OPEN for signed approvals |
| 8 | Integrate skills and visualization | Catalog loads 12 SKILL.md files; UI lists them and draws work graph | DONE |
| 9 | Verify confidentiality and node constraints | Synthetic fields with IP/token are not forwarded to LLM; graph fact rejects sensitive strings | DONE |
| 10 | Validate and release main | pytest and compileall CI succeed; documentation and code merged to main | VERIFY |

## Executable checks

    python -m pip install -r requirements-dev.txt
    python -m compileall -q app vendor/sapper_v2
    python -m pytest -q
    git hash-object vendor/sapper_v2/sapper.py
    git hash-object vendor/sapper_v2/LICENSE

## Synthetic resolver acceptance sequence

1. Generate a random UUID and empty temporary data directory.
2. Call initialize_graph -> fact ID.
3. Call stage_begin with that fact -> open intent ID.
4. Call resolve_frontier and require that ID to be ready.
5. Call stage_end with a controlled status summary -> result fact ID.
6. Verify intent.to matches the produced fact and resolver reports no ready intents.
7. Require graph validation to return valid.
8. Verify path traversal, unexpected titles and Bearer-token-shaped fact descriptions are rejected.
9. Verify separate engagement UUIDs cannot share one graph directory.
10. Confirm all validations run in CI without contacting a live target.

This is software integration testing only. It does not claim a completed security assessment.
