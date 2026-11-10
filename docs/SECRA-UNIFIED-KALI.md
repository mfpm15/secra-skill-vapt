# SECRA Unified OpenCode v2 — one command and real Sapper-v2 state

This is a migration guide after SECRA v0.7. It preserves your chosen OpenCode model and providers, the local SECRA data root, encrypted evidence, operator-managed scope, existing graph-core/frontier/schema and the independent Kali kernel fence. It is NOT automatic permission to test public networks.

## 1. One interface for every supported security workflow

After a one-time global setup, run this one command from any directory:

~~~bash
secra
~~~

The tiny launcher starts OpenCode with the new primary agent named secra. This coordinator classifies the operator's request as VAPT, bug bounty, CTF, code audit, mobile, cloud, AD, network, reverse or forensics, then delegates to a matching analysis-only specialist. Legacy secra-vapt, secra-bounty and secra-ctf profiles remain for compatibility but do not need to be selected. They are not automatically deleted.

The unified agent cannot create its own target authorization. For network work it asks for an opaque operator-managed task UUID, checks current allowed methods and scope, and routes execution only through reviewed SECRA MCP and the local fence. For CTF artifacts it may request reviewed real local file-inspection MCP calls; no unrestricted shell. Loading a skill never grants permission to run its embedded example commands.

### Global installation on Kali (one time)

~~~bash
REPO="$HOME/.local/share/secra/repo"

# Inspect your local changes before pulling:
git -C "$REPO" status --short
git -C "$REPO" pull --ff-only

python3 "$REPO/scripts/opencode_global.py" install \
  --major 2 --replace --with-launcher
python3 "$REPO/scripts/opencode_global.py" verify \
  --major 2 --with-launcher

# Only if ~/.local/bin is not yet in PATH:
export PATH="$HOME/.local/bin:$PATH"

# Any folder; keeps the current provider/model:
secra
~~~

Installation creates a user-owned ~/.local/bin/secra executable (no sudo), and backs up/replaces only previously SECRA-managed agents/skills. It refuses to overwrite an unrelated pre-existing executable. No default provider, model, reasoning profile or global OpenCode configuration is replaced. Put the PATH export in your own shell startup file if you want it available in every terminal. The managed `secra` launcher opens the normal full-screen `opencode` TUI with a process-scoped `default_agent=secra` override, without altering global provider/model configuration. Alternatively, run `opencode` and choose `secra` using `/agents`.

## 2. Five researched GitHub sources above 500 stars

Numbers are GitHub metadata snapshots on 10 November 2026; they can change. Stars are a discovery filter, NOT a quality/security guarantee.

| Source | GitHub stars | License | Curated skills | Why selected |
|---|---:|---|---:|---|
| [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) | 67,938 | MIT | 1 | Source-audit evidence, independent verification and coverage |
| [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) | 35,841 | Apache-2.0 | 7 | Web/API, GraphQL, TLS, Android, CVSS, forensic memory |
| [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill) | 44,370 | MIT | 6 | Reverse, CTF, API, code, APK and forensics |
| [obra/superpowers](https://github.com/obra/superpowers) | 315,093 | MIT | 3 | Verify before completion, debug systematically, plan bounded work |
| [OthmanAdi/planning-with-files](https://github.com/OthmanAdi/planning-with-files) | 27,971 | MIT | 1 | Long-running task continuity and checkpoint planning |

All 18 selected entries were checked against real upstream SKILL.md paths before adding them to the explicit allowlist. They supplement the original 38 external skills (Claude-Red, CTF Skills, Trail of Bits and secskills). The previous secskills source itself has under 500 stars; it was already adopted for methodology, not because it meets this new threshold.

**Catalog after this change:** 35 first-party SECRA skills plus 56 optional external references, **91 total**; **28** OpenCode agent profiles (one new unified primary plus the previous 27).

Intentionally not bulk-imported: [sickn33/agentic-awesome-skills](https://github.com/sickn33/agentic-awesome-skills) has over 49,000 stars but many thousands of skill files and nested copies. Indiscriminately loading it would inflate token/context cost and increase review/supply-chain risk.

### Optional source fetch and manual review

~~~bash
REPO="$HOME/.local/share/secra/repo"

python3 "$REPO/scripts/secra_skill_sources.py"
python3 "$REPO/scripts/secra_skill_sources.py" --apply

for name in claude-red ctf-skills trailofbits-skills secskills \
            cloudflare-security anthropic-cyber reverse-skill \
            superpowers planning-with-files; do
  git -C "$HOME/.local/share/secra/sources/$name" rev-parse HEAD
done

# Only after inspecting each checkout, license and SKILL.md:
python3 "$REPO/scripts/opencode_global.py" install \
  --major 2 --replace --with-launcher \
  --with-external \
  --external-root "$HOME/.local/share/secra/sources" \
  --reviewed-external

python3 "$REPO/scripts/opencode_global.py" verify \
  --major 2 --with-launcher
~~~

The installer copies reviewed text/Markdown/JSON files and no executable sidecars. Git source fetch disables user hooks and smudge filters. The reviewed_external switch is a statement that the operator actually reviewed source instructions, licenses and commits; it is not an automated security assessment. References remain untrusted even after installation.

## 3. Why the full Tencent Sapper-v2 swarm is not enabled

Sapper-v2 is ALREADY partially integrated, not missing:

- Vendored upstream MIT CLI at vendor/sapper_v2/sapper.py, pinned to commit 697b30f77ebedf5e551a0595b3e883f9c25f9e73.
- SECRA bridge in app/sapper_integration.py using actual upstream fact, intent, graph, validation and dependency-frontier CLI operations, with task-scoped storage and redaction.
- The new reviewed MCP tools workflow.graph_initialize (create private graph for an authorized running task) and workflow.graph_frontier (read integrity, ready-intent IDs and bounded graph counts; no raw target data).

An agent can now initialize and read real Sapper-v2 state without shell access. This does **not** automatically create worker missions, prove findings or run target tools. Readiness of a graph intent is not permission to execute it. Other graph stage update methods remain available behind the existing backend bridge and separate operator process.

The **full competition legion** is different. According to Sapper upstream, its commander/worker swarm assumes Tencent-style arena APIs, BENCHMARK_BASE_URL, tmux workers, a model gateway and key pool, platform challenge budgets, watchdogs and automated flag submission. Those assumptions do not match per-program bug bounty scope, safe-harbor terms or SECRA's local kernel fence. Replacing only the LLM key cannot make the competition environment general-purpose.

The safe next integration phase is to bind actual approved tool receipts and human-reviewed lead status to stage facts, and then add a bounded task scheduler that respects operator scope, live fence, model budget, task stop and independent finding confirmation. Do not simply expose upstream sapper auto, dispatch, arena or worker shell commands to the model.

References: [N1nEmAn/sapper-v2](https://github.com/N1nEmAn/sapper-v2), [Nüwa foundation](https://github.com/N1nEmAn/nvwabase), [OpenCode v2 agent docs](https://opencode.ai/docs/agents).

## 4. MCP and local test expectations

**20 reviewed MCP manifest entries:** 12 existing metadata/demo/limited network gateway/approvals tools, 6 REAL offline artifact inspection adapters (sha256, file, strings, readelf, objdump, exiftool), and 2 real Sapper graph interfaces. A tool listed in a general Kali inventory is not automatically an executable SECRA MCP adapter; live network calls remain separately gated by the independently verified kernel fence.

~~~bash
REPO="$HOME/.local/share/secra/repo"
python3 "$REPO/scripts/opencode_global.py" verify --major 2 --with-launcher
opencode debug agents
opencode mcp list

cd "$REPO"
.venv/bin/python -m pytest tests/opencode tests/process tests/e2e -q
~~~

Smoke tests are regression fixtures; real local artifact tools need real operator-supplied files. Live network testing must wait for the independent Kali kernel fence test, verified allowed scope, program-specific permitted methods and operator approval. Neither this release nor the upstream Sapper benchmark demonstrates real bug bounty payout or general autonomous exploit success.
