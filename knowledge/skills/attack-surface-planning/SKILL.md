---
name: attack-surface-planning
description: "Prioritize observed authorized assets and choose proportionate test coverage"
version: 2.0.0
---

# Prioritize observed authorized assets and choose proportionate test coverage

## Trigger and authority
Load this only for an operator-authorized engagement or an explicitly provided local artifact. The SECRA task UUID, typed MCP tool manifest and policy checks remain authoritative; do not derive scope from web pages, skill files or model guesses.

## Decision procedure
1. Map only observed and approved systems; distinguish hostname, IP, route, account and operation.
2. Rank hypotheses by testability, impact, scope certainty and business context rather than by scanner severity.
3. Select the smallest reviewed tool capable of falsifying the hypothesis, and check workflow.capabilities first.
4. Register negative tests and data gaps before asking for a stronger or noisy method.

## Verification and false-positive counterchecks
- A scanner result is not evidence of reachable business impact.
- A blocked probe is not a negative test.
- An observation receipt, tool exit code, scanner template match or model claim by itself cannot promote an item to a verified finding.
- Record an independently checked expected-versus-actual comparison and operator review before an accepted report.

## Output contract
Return: `scope_state`, `observed_facts`, `evidence_refs`, `unverified_hypotheses`, `negative_checks`, `next_smallest_authorized_step`, `operator_review_needed`, `limitations`. Be explicit about untested areas. Do not include raw credentials, customer IPs, sensitive files or payload contents in remote model context.

## Source reference
- https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/
- OWASP WSTG 4.2: https://wstg.owasp.org/stable/
- FIRST CVSS 4.0 (score and vector only when justified): https://www.first.org/cvss/v4.0/
