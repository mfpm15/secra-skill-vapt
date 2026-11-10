# SECRA v0.7 — Expanded Knowledge, Kali Artifacts and Evidenced Reports

Status: implementation preview. This release is *not* a claim of live network automation or zero false positives. Use Kali lab verification before authorizing any public network target.

## What is genuinely installed versus just referenced?

- 35 **first-party** SECRA SKILL.md files: all 21 previous files carry a v2 evidence/false-positive workflow; 14 new areas include program scope, attack-surface prioritization, API object authorization, GraphQL, business logic, input validation, Kubernetes, AD, mobile reverse engineering, CTF artifacts, forensics, supply chain, narrative reporting, and agent permissions.
- 38 **optional third-party knowledge references**: the prior Claude-Red, CTF Skills and Trail of Bits set, plus selected additional Trail of Bits and MIT-licensed secskills content. The installer imports only reviewed SKILL.md and text/JSON supporting references; it does **not** execute upstream scripts.
- 27 native **OpenCode v2 agents**: coordinator secra-vapt, secra-ctf, new secra-bounty, and 24 specialist profiles. Specialist agents are analysis-only; local operator controls scope/verification, coordinator gates MCP.
- 18 reviewed **MCP tools**: 12 previous (some demo, gated or approval-only), plus six real offline artifact tools. The new tools are executable, not simulations, but do not contact a remote target.
- The 11-category **Kali tool inventory** lists available/missing binaries and official apt package candidates. Only installed tools exposed by reviewed MCP adapters are model-callable. Never equate a PATH discovery with full MCP execution authority.

## External knowledge sources: prepare, inspect, then install

~~~bash
REPO="$HOME/.local/share/secra/repo"
git -C "$REPO" status --short

# If there are no unsaved local edits:
git -C "$REPO" pull --ff-only

# Dry run: show known sources without changing anything.
python3 "$REPO/scripts/secra_skill_sources.py"

# Clone only four reviewed HTTPS GitHub sources.
python3 "$REPO/scripts/secra_skill_sources.py" --apply

# Inspect commit SHA, licenses, SKILL.md instructions and linked references.
for name in claude-red ctf-skills trailofbits-skills secskills; do
  git -C "$HOME/.local/share/secra/sources/$name" rev-parse HEAD
  git -C "$HOME/.local/share/secra/sources/$name" status --short
done

# ONLY AFTER you have reviewed the external source checkouts:
python3 "$REPO/scripts/opencode_global.py" install --major 2 --replace \
  --with-external --external-root "$HOME/.local/share/secra/sources" \
  --reviewed-external

python3 "$REPO/scripts/opencode_global.py" verify --major 2
~~~

The installer preserves and backs up SECRA-managed profiles during upgrades, refuses to overwrite unmanaged/tampered agent files and does not mutate the chosen model/provider. The 38 optional sources only install when their paths are present; a missing checkout causes an explicit error. Do not use the review-confirmation flag until you actually inspect the source commits and licenses. The executable sidecar scripts from those repositories are excluded.

## Kali binary inventory and opt-in installation

~~~bash
REPO="$HOME/.local/share/secra/repo"

python3 "$REPO/scripts/secra_kali_tools.py" --category web --category recon
python3 "$REPO/scripts/secra_kali_tools.py" --category reverse --category forensics

# Selective official apt package install on your own Kali terminal only:
python3 "$REPO/scripts/secra_kali_tools.py" --category reverse --apply

# Or use the official Kali category metapackages (may be large):
python3 "$REPO/scripts/secra_kali_tools.py" --category web --meta --apply
~~~

Install actions require local TTY approval and sudo; OpenCode agent prompts cannot perform this installation silently. Check package availability on Kali Rolling before confirming. The script does not install the entire kali-linux-everything package and does not execute any target-facing tools. The general tool list is a discovery/inventory, **not** 50 additional MCP adapters.

Official Kali reference: https://www.kali.org/docs/general-use/metapackages/

## Six genuine local MCP tools (R1, read-only)

These tools use the private folder created automatically per engagement:

~~~text
<SECRA_DATA_DIR>/engagements/<TASK_ID>/03-evidence/analysis-input/
~~~

Place a legal, operator-approved artifact file there (such as an HTB challenge binary, APK, forensic sample, or provided source snippet). Protect the file as private. For preexisting engagements, first run:

~~~bash
python3 "$REPO/scripts/secra_workspace.py" init --task-id "$TASK_ID"
~~~

Supported reviewed MCP tools:
- artifact.sha256 — Python SHA-256 of actual file bytes; works without Kali binaries.
- artifact.file_type — system file MIME inspection.
- artifact.strings — system strings read-only extraction.
- artifact.elf_header — system readelf -h.
- artifact.object_summary — system objdump -f.
- artifact.metadata — system exiftool metadata extraction.

Each tool accepts only task_id and a short relative artifact path from the analysis-input folder. No arbitrary command string, extra flags, shell, URL, target IP, external file path, or symlink escapes are permitted. The binary must be present and root-controlled; otherwise the call is blocked. Run results are actual local bytes, written to the per-task AES-GCM evidence vault. Only a sanitized summary/opaque reference returns to the model. The operator may then review raw files locally.

These tools do not make network connections. They are useful for Kali/CTF/offline inspection, but do not prove that the live Nmap/curl kernel fence has passed. Real live network testing remains separately gated pending the required privileged Kali lab proof.

## Executive and chronological professional report

The new operator-only report engine follows OWASP WSTG v4.2 reporting guidance:

1. Executive summary with objectives, allowed boundary, **validated business impact only**, and strategic mitigation priorities.
2. Authorized scope, constraints, and point-in-time assessment limits.
3. **Chronological narrative** assembled from actual UTC task phase and tool ledger entries. Each event states what was recorded, what happened, whether it was blocked/simulated/completed, and the exact opaque evidence reference when available.
4. Summary of verified findings, then per-finding preconditions, expected/observed behavior, independent countercheck, minimal reproduction, business impact, root cause, remediation, and retest criteria.
5. Separate unresolved hypotheses, negative/rejected leads, gaps, cleanup, follow-up and evidence-integrity appendix.

It never claims that a simulated, denied, nonexistent or unreviewed tool action succeeded. For each finding the operator must supply complete private details, a verified lead ID, two matching authenticated evidence references, and explicit reproduction/reviewer confirmation. A failure of the case-integrity check suppresses the finding from the verified section. **There is no guarantee of zero false positives**: an operator must validate real impact and proof.

Minimum JSON input (a safe incomplete draft, not a fabricated finding):

~~~json
{
  "engagement_title": "Authorized Security Assessment",
  "client_alias": "CLIENT_ALIAS",
  "objectives": ["Assess approved authentication and object authorization"],
  "scope_description": "only explicitly approved assets, methods and accounts",
  "assessment_constraints": ["No out-of-scope traffic", "Respect program request limits"],
  "authorization_reference": "LOCAL_APPROVAL_REFERENCE",
  "reviewer_identity": "Pending independent reviewer",
  "operator_review_confirmed": false,
  "findings": []
}
~~~

Store the input JSON as an owner-only file, e.g. chmod 600 private-report.json. Never paste client secrets into a remote model.

~~~bash
REPO="$HOME/.local/share/secra/repo"
TASK_ID="ENTER-YOUR-AUTHORIZED-TASK-UUID"
python3 "$REPO/scripts/secra_workspace.py" manifest --task-id "$TASK_ID"
python3 "$REPO/scripts/secra_professional_report.py" \
  --task-id "$TASK_ID" \
  --input "$HOME/private-report.json" \
  --output "$HOME/private-vapt-report.md"
~~~

The CLI returns a machine-readable quality result and creates an owner-only Markdown file. Use --strict to exit nonzero when the report remains incomplete. It will not overwrite an existing report or automatically submit to HackerOne, Bugcrowd or any other platform. A future export to PDF/DOCX must preserve the same evidence gates and avoid embedding live secrets.

Reference: https://wstg.owasp.org/stable/5-Reporting/README/

## OpenCode v2 coordinator usage

~~~bash
opencode mini --agent secra-vapt
opencode mini --agent secra-ctf
opencode mini --agent secra-bounty
opencode mcp list
~~~

Your selected OpenCode model stays untouched, including a GPT-5.6 or other reasoning profile. An agent can delegate specialist analysis, ask for reviewed skill guidance, and request the six real local artifact MCP calls. The model must still ask for the operator-provided task UUID and cannot invent network scope. It cannot promote a finding to verified on its own.

## Validation, clear distinctions

~~~bash
REPO="$HOME/.local/share/secra/repo"
cd "$REPO"
.venv/bin/python -m pytest tests/opencode tests/process tests/e2e -q
.venv/bin/python "$REPO/scripts/secra_smoke.py"
~~~

The smoke is **synthetic** by design (regression only); the local artifact tools are **real** and require actual approved files. Full Kali live service scanning is not activated until the root-controlled kernel network sandbox is independently attested on the operator's Kali machine. Do not bypass the fence or claim all Kali tools are compatible with SECRA MCP.

References: https://opencode.ai/v2/docs/permissions/ ; https://www.kali.org/docs/general-use/metapackages/ ; https://github.com/trilwu/secskills ; https://github.com/trailofbits/skills ; https://wstg.owasp.org/stable/5-Reporting/README/ .
