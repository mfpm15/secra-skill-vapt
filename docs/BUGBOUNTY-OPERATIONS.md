# SECRA Bug Bounty Operations — operator guide

SECRA helps with **authorized** VAPT research and reporting, but does not promise valid findings, bounty rewards, or successful autonomous exploitation. The current backend is a single-IPv4-target MVP with deliberately limited live adapters; wildcard bug-bounty DNS scopes and arbitrary HTTP paths are **NOT** implemented.

## Platform policy references (review each live program, not generic guidance only)

- HackerOne Code of Conduct & Hackbots: https://www.hackerone.com/policies/code-of-conduct
  Human-in-the-loop review; no fabricated AI reports or unsafe scanning.
- Bugcrowd Program Briefs: https://docs.bugcrowd.com/researchers/participating-in-program/reviewing-bounty-briefs/
  Check explicit in-scope targets, out-of-scope assets, automation/rate limits and additional rules.
- Intigriti scope and program rules: https://kb.intigriti.com/en/articles/5379063-selecting-a-target
  Program policies can change; recheck before testing.
- GitHub Bug Bounty report quality: https://bounty.github.com/report-quality
  Reproduction, demonstrated impact, affected component and evidence.
- OWASP WSTG v4.2 reporting: https://wstg.owasp.org/v4.2/5-Reporting/

Operator authorization, approved target, allowed methods, safe-harbor terms, test accounts, throttling, forbidden paths and disclosure rules are specific to the selected program. **Do not assume that an in-scope hostname authorizes testing every resolved IP.** Existing SECRA scope/fence checks remain mandatory.

## 1. Operator-only bug bounty report gate

The local reporting gate requires: an operator-signed lead, two distinct authenticated evidence receipts, intact local case manifest, actual reproduction steps, observed impact, remediation, scope review, accepted program rules, and explicit human PoC confirmation. It does not automatically submit anything.

Create a private JSON document containing these keys:
program, program_url, policy_checked_at_utc, asset, asset_scope_confirmed, automation_allowed, rules_acknowledged, title, weakness, severity, prerequisites, steps (array of two or more steps), observed_result, security_impact, root_cause, remediation, operator_reviewed, program_disclosure_allowed, poc_reproduced_by_operator, rate_limit_complied.

Use values from actual authorized testing. Boolean values are operator attestations; SECRA does not independently prove compliance merely because a box was ticked. Keep the input file 0600 and never share secrets with a remote model.

~~~bash
REPO="$HOME/.local/share/secra/repo"
TASK_ID="ENTER-A-FINISHED-AUTHORIZED-TASK-UUID"
LEAD_ID="ENTER-OPERATOR-SIGNED-LEAD-UUID"
chmod 600 "$HOME/private-program-report.json"

python3 "$REPO/scripts/secra_workspace.py" manifest --task-id "$TASK_ID"
python3 "$REPO/scripts/secra_bounty_report.py" \
  --task-id "$TASK_ID" --lead-id "$LEAD_ID" \
  --input "$HOME/private-program-report.json" \
  --output "$HOME/private-bounty-draft.md"
~~~

Exit 0 indicates that machine-checkable fields are present for *final human review*, not that a bug is independently proven, that a platform accepted it, or that it was submitted. Exit 2 indicates report deficiencies and creates an explicitly incomplete draft. The tool does not contact HackerOne, Bugcrowd or Intigriti.

## 2. Per-task encrypted complete case bundle

Previous workspace-only archives left out the SQLite TaskStore and encrypted evidence vault. New bundles include **only the selected task**: filtered task SQLite and per-task gateway audit records (if present), workspace files, AES-GCM evidence records and their per-task encryption key. All contents are encrypted together using AES-256-GCM and a key derived locally by scrypt from a 16+ character passphrase. No unencrypted ZIP is written to disk.

The task must have a terminal state, a valid manifest, and a passing case-integrity report. The passphrase is prompted by a local TTY (not recorded as a CLI argument).

~~~bash
REPO="$HOME/.local/share/secra/repo"
TASK_ID="ENTER-YOUR-FINISHED-TASK-UUID"

python3 "$REPO/scripts/secra_workspace.py" manifest --task-id "$TASK_ID"
python3 "$REPO/scripts/secra_case_bundle.py" export \
  --task-id "$TASK_ID" --bundle "$HOME/private-case.secra-case"

python3 "$REPO/scripts/secra_case_bundle.py" restore \
  --bundle "$HOME/private-case.secra-case" \
  --destination "$HOME/private-restored-case"
~~~

Restoration always creates a NEW directory and leaves the original system alone. The restored files contain decrypted private data and keys, so keep them locally and restrict access. A lost passphrase cannot be recovered. The implementation currently limits plaintext ZIP size to 96 MiB and at most 2,500 entries; larger cases require a reviewed streaming backup design.

This is a scoped offline recovery bundle, **not** proof of bug-bounty validity or active authorization to access a target.

## 3. Fixed synthetic model benchmark (also works with real 9Router models)

~~~bash
REPO="$HOME/.local/share/secra/repo"

# Offline deterministic fake model; no API key or network:
python3 "$REPO/scripts/secra_model_eval.py" --repeat 3

# Optional: requires user's existing local 9Router gateway and secret:
python3 "$REPO/scripts/secra_model_eval.py" \
  --models "YOUR_AVAILABLE_MODEL_A,YOUR_AVAILABLE_MODEL_B" \
  --repeat 3 --output "$HOME/private-model-evaluation.json"
~~~

The comparison uses three **public synthetic tool-choice** scenarios. It can measure correct next-tool choice and latency; it does **not** measure ability to find vulnerabilities, solve HTB, earn bounties, tokens or costs. No real target IP is included. For actual success comparisons, test identical authorized labs with equal budgets and independent grading.

## 4. Kali live execution prerequisites

~~~bash
REPO="$HOME/.local/share/secra/repo"
python3 "$REPO/scripts/secra_live_preflight.py" \
  --task-id "YOUR-AUTHORIZED-LIVE-TASK-UUID"
~~~

This static preflight never performs scans, uses sudo or proves network isolation. It checks systemd backend selection, root-controlled fence metadata, wrapper ownership and pinned binary digests. It intentionally exits with status 2 to indicate that privileged Kali kernel/BPF isolation is **not** independently attested. Run the existing Kali fence lab suite with authorized, disposable network namespaces before relying on live tooling.

## 5. Real HTTP evidence import (operator-captured HAR, no simulator)

When the live kernel fence is not yet attested, you can still work with **real** traffic captured *manually* from an explicitly authorized application in your local browser or HTTP proxy. Export a HAR file to your Kali machine. Treat HAR as sensitive: it can contain cookies, bearer tokens, request bodies and personal data.

The operator must specify an exact allowlist of program-approved hostnames; wildcard host patterns are rejected. The importer rejects entries from all other hosts, seals the filtered raw HTTP captures into the local AES-GCM evidence vault, and returns only aggregate statuses, header presence and cookie-attribute counts. It does **not** contact those hosts, run scanners, discover subdomains, or assert that headers are valid bounty findings.

~~~bash
REPO="$HOME/.local/share/secra/repo"
TASK_ID="YOUR-AUTHORIZED-TASK-UUID"

# Export HAR from an operator-authorized browser/proxy, then:
chmod 600 "$HOME/private-capture.har"

python3 "$REPO/scripts/secra_har_import.py" \
  --task-id "$TASK_ID" \
  --har "$HOME/private-capture.har" \
  --approved-host "YOUR-EXACT-IN-SCOPE-HOSTNAME" \
  --confirm-program-scope
~~~

The sealed evidence reference can be added to an operator-reviewed hypothesis. A single captured HTTP header, missing CSP, or cookie flag is **not** proof of exploitable impact. A program brief may exclude low-impact header observations or require separate user impact demonstrations.

Privacy boundary: the raw accepted HAR stays encrypted locally; it is not provided to OpenCode's remote model as raw text. Only approved aggregate metadata and opaque evidence references may be shared. The operator must independently confirm not only hostname scope but any excluded paths or methods in the program brief.

## Remaining engineering work

- Actual wildcard DNS scope, rebind resistance and program-level HTTP rate limiting.
- Broader reviewed, non-destructive HTTP/API adapters, only after live fence attestation.
- Independent reviewer identity, reproducibility sign-off and report submission quality.
- Repeatable real-model benchmarks on approved labs with measured tokens, costs and per-task successes.
- No expectation of guaranteed income: payout depends on a unique, valid, in-scope report and program decision.
