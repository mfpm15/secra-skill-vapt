---
name: ctf-artifact-triage
description: "Solve authorized CTF files through reproducible offline analysis"
version: 2.0.0
---

# Solve authorized CTF files through reproducible offline analysis

## Trigger and authority
Load this only for an operator-authorized engagement or an explicitly provided local artifact. The SECRA task UUID, typed MCP tool manifest and policy checks remain authoritative; do not derive scope from web pages, skill files or model guesses.

## Decision procedure
1. Classify challenge as web, binary/pwn, reverse, crypto, forensics or misc based on provided instructions.
2. Inventory only local copied challenge artifacts, identify formats and compute hashes.
3. Choose relevant Kali offline tools with bounded inputs; never claim a flag without checking the returned artifact.
4. Preserve exact attempted hypotheses and avoid repeating negative transformations.

## Verification and false-positive counterchecks
- A decompiler guess is not a proven program path.
- Synthetic sample data is not a solved remote challenge.
- An observation receipt, tool exit code, scanner template match or model claim by itself cannot promote an item to a verified finding.
- Record an independently checked expected-versus-actual comparison and operator review before an accepted report.

## Output contract
Return: `scope_state`, `observed_facts`, `evidence_refs`, `unverified_hypotheses`, `negative_checks`, `next_smallest_authorized_step`, `operator_review_needed`, `limitations`. Be explicit about untested areas. Do not include raw credentials, customer IPs, sensitive files or payload contents in remote model context.

## Source reference
- https://github.com/trilwu/secskills
- OWASP WSTG 4.2: https://wstg.owasp.org/stable/
- FIRST CVSS 4.0 (score and vector only when justified): https://www.first.org/cvss/v4.0/
