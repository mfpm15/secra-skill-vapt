# inventory.md — import classification

## graph-core (imported and used)

| Upstream file / symbol | SECRA use | Runtime mode |
|---|---|---|
| lib/sapper.py, class Store | vendor/sapper_v2/sapper.py | Imported verbatim |
| Store.init, Store.add_fact, Store.add_intent | app/sapper_integration.py | init / fact / intent |
| build_graph_view | app/sapper_integration.py, public_graph | graph --format json |
| Typed facts and intents (goal, f###, i###, from, to) | Local schema and visualization | Imported |
| validate_graph | Read-only integrity inspection | validate |

## memory (imported and used)

| Upstream component | Local mapping | Status |
|---|---|---|
| Filesystem persistence (.sapper) | data/sapper_graphs/<UUID>/.sapper | Wired |
| atomic_write_json and fcntl.flock | Retained inside verbatim source | Imported |
| Title / description / doc layers | Status facts use short title and description | Partial consumption |
| Multi-session graph persistence | Local graph files survive process restarts | Wired |
| Recall / semantic search in upstream | No exposed SECRA API | Not wired |

## resolver (imported and read-only)

| Upstream API | SECRA seam | Status |
|---|---|---|
| frontier / is_ready | resolve_frontier + GET /api/engagements/{eid}/frontier | Wired |
| validate_graph | resolve_frontier integrity verdict | Wired |
| claim, pick, release | No SECRA HTTP route | Disabled |
| confirm | No SECRA HTTP route | Disabled |

## competition-only (excluded from the SECRA runtime)

| Component | Decision |
|---|---|
| docker/commander and watchdog/worker scripts | Not vendored |
| lib/arena.py, scoring integration | Not vendored or used; pengiriman hasil disabled |
| Competition prompt templates | Not vendored |
| auto, dispatch, sweep, flag | Still exist as symbols inside verbatim CLI, but blocked by adaptor allowlist |
| Permission-skipping interactive modes | Not exposed; persetujuan implisit disabled |
| install.sh, tmux, Claude hooks | Never run |
| kb/entries | Not vendored; SECRA uses its curated knowledge catalog |

The verbatim upstream CLI still contains unused competition functionality. Only the approved graph operations are reachable through SECRA's subprocess adapter. This is runtime isolation, not a source-code deletion.
