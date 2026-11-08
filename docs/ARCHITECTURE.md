# SECRA Architecture and roadmap

## Current implemented topology

Browser dashboard -> FastAPI local API -> SQLite -> local worker -> fixed Nmap/curl subprocesses; in parallel, each stage writes a fact-intent record via pinned sapper-v2 CLI. Bundled skills are routed deterministically.

Agent stage monitor:
1. Scope Guardian: validates a single IPv4 target against the authorized IP/CIDR list.
2. Recon Agent: runs Nmap against top 20 TCP ports and normalizes observations from XML.
3. HTTP Analyst: runs curl -I on common HTTP ports found by the scoped scan, retaining status codes only.
4. Knowledge Curator: loads reviewed local SKILL.md files selected by normalized service labels.
5. LLM Advisor: sends vetted static methodology plus positive-allowlisted numeric ports and service labels to 9Router.
6. Verification: records evidence sufficiency, without inventing vulnerability findings.
7. Report Builder: generates a local Markdown report.

The browser polls the backend about once every 1.35 seconds. These are honest stage transitions, NOT fabricated internal reasoning or LLM multi-agent traces.

## Privacy and trust boundary

Real IP -> local tool argv only.
Raw Nmap XML -> local parser -> normalized port/service list.
Allowlisted service values -> fixed-schema JSON with alias ASSET_001 -> 9Router chat completions.
LLM response -> redacted advisory text -> local event ledger; not actionable commands.
Raw HTTP response -> local parsing -> status code only; no raw headers persisted.
Engagement IP/scope/reports -> SQLite plaintext on local disk; encryption at rest is not implemented.

Important: deterministic field allowlisting is the main LLM privacy mechanism. Regex-only masking of arbitrary unstructured logs does not give strong privacy. Neither SECRA nor masking can guarantee what a third-party 9Router provider logs; configure provider allowlists and local models when sensitive.

## Sapper-v2 integration

Original upstream code (MIT) is vendored at vendor/sapper_v2/sapper.py, pinned to commit 697b30f77ebedf5e551a0595b3e883f9c25f9e73. The adapter in app/sapper_integration.py uses the actual fact-intent CLI with a minimal inherited environment, a per-engagement graph directory, and only safe fixed subcommands. Graphs are persisted across browser refreshes and displayed through the authenticated /api/engagements/{id}/graph endpoint.

SECRA does not currently run upstream sapper-v2's CTF commander, general, worker swarm, flag submissions, interactive model CLI, or auto dispatch. The Tencent contest result stated by its maintainers is not a benchmark of SECRA or of this adapted workflow.

## Additional architecture research

- vxcontrol/pentagi (MIT): strongest dashboard + Kali container + observability reference found in research. Investigate as alternative backend before reimplementing the entire runtime.
- usestrix/strix (Apache-2.0): agentic VAPT worker reference.
- N1nEmAn/nvwabase (MIT): fact-intent graph shared memory.
- SnailSploit/Claude-Red (MIT): security knowledge skills for curation.
- trailofbits/skills (CC-BY-SA-4.0): audit and false-positive verification methodology.
- CyberStrikeus/CyberStrike (AGPL-3.0-only): optional browser and MCP design reference, license review required.
- KeygraphHQ/shannon (AGPL-3.0): source-assisted web/API security worker reference.
- OWASP WSTG, ASVS, API Security, MASVS and MASTG: version-pinned knowledge mappings.
- DefectDojo: finding lifecycle, deduplication and remediation.
- Microsoft Presidio: optional local PII/entity detection for free-text data; not a replacement for strict payload allowlisting.
- Langfuse and OpenTelemetry: privacy-aware observability after audit of sensitive telemetry.

## Production roadmap

P1: durable task queue and crash-safe workers, full audit schema, structured event streaming.
P2: per-engagement Kali container with network egress allowlisting, non-root enforcement, no Docker host socket.
P3: authenticated scope models and operator approval for any high-impact test.
P4: multi-user RBAC, encrypted sensitive storage/vault, signed evidence, retention and access audit.
P5: adapter API for Nuclei/ZAP/MobSF/Trivy plus evaluated Strix/PentAGI, with capability policy per action.
P6: model/provider governance, explicit no-fallback mode for sensitive engagements, option for strictly local LLM.
P7: OWASP test-case coverage, finding verification workflow, CVSS/CWE mapping, retest and reporting.
P8: genuine orchestrator graph, durable fact memory, multi-agent coordination and OpenTelemetry metrics.

This is a single-user local MVP. Never expose it on 0.0.0.0 without full security controls, and always use a written Rules of Engagement.
