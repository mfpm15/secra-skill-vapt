---
name: bug-bounty-program-rules
description: "Interpret program scope and reporting terms before any testing"
version: 2.0.0
---

# Interpret program scope and reporting terms before any testing

## Trigger and authority
Load this only for an operator-authorized engagement or an explicitly provided local artifact. The SECRA task UUID, typed MCP tool manifest and policy checks remain authoritative; do not derive scope from web pages, skill files or model guesses.

## Decision procedure
1. Read the actual program brief and record the permitted assets, target host patterns, prohibited endpoints, rate limits, valid test identities, and disclosure channel.
2. Separate hostname authorization from IP ownership. A resolved address or CDN neighbor is not automatically in-scope.
3. Classify each proposed test as allowed, requires approval, explicitly forbidden, or unknown. Treat unknown as not permitted.
4. Record a timestamped operator authorization decision and keep it local. Review the brief again before submission.

## Verification and false-positive counterchecks
- A program listing without the current assets and exclusions does not authorize arbitrary discovery.
- Agent advice is not a written authorization.
- An observation receipt, tool exit code, scanner template match or model claim by itself cannot promote an item to a verified finding.
- Record an independently checked expected-versus-actual comparison and operator review before an accepted report.

## Output contract
Return: `scope_state`, `observed_facts`, `evidence_refs`, `unverified_hypotheses`, `negative_checks`, `next_smallest_authorized_step`, `operator_review_needed`, `limitations`. Be explicit about untested areas. Do not include raw credentials, customer IPs, sensitive files or payload contents in remote model context.

## Source reference
- https://docs.bugcrowd.com/researchers/participating-in-program/reviewing-bounty-briefs/
- OWASP WSTG 4.2: https://wstg.owasp.org/stable/
- FIRST CVSS 4.0 (score and vector only when justified): https://www.first.org/cvss/v4.0/
