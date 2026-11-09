---
name: network-service-discovery
description: "Inventory authorized TCP services with bounded, reproducible scans and evidence-based conclusions."
version: 1.0.1
category: network
---
# Network Service Discovery

## Mission
Create a reproducible service inventory within an explicitly approved scope, without assuming an open port is a vulnerability.

## Assessment methodology
1. Validate an approved IP/CIDR range and rate/time budget before running Nmap or another enumerator.
2. Collect bounded port/protocol observations with execution time and tool settings.
3. Differentiate an observed open port from an inferred service label or confirmed server version.
4. Compare externally reachable services with business-approved exposure and segmentation requirements.
5. Defer credential testing, broad enumeration and exploit checks until separately authorized and sandboxed.

## Evidence and validation
- Record port/protocol, UTC timestamp, observation source and scan constraints.
- Confirm inconsistencies using an approved independent method and document firewall/routing constraints.
- Classify scanner guesses as candidates; obtain reproducible evidence before promoting to a security finding.

## Common interpretation errors
- No response does not prove a service is absent.
- A port number does not identify a specific service or vulnerability by itself.

## Remediation principle
Review exposed services, least-privilege network access, ownership and segmentation.

## Sources and further reference
- https://nmap.org/book/man.html
- https://csrc.nist.gov/pubs/sp/800/115/final

## SECRA safety rule
This skill is guidance, not permission to probe. All tools must run through a scope-checked, bounded local adapter. Never send IP addresses, credentials, or raw customer evidence to an external model.

## v2.0 SECRA operator decision workflow

1. Use `workflow.capabilities` to select only a live-fence-attested reviewed tool; prefer passive or provided observations.
2. Normalize protocol, transport, observed port, banner and collection time with local evidence reference.
3. Cross-check a finding against an application response or service owner expectation; inventory alone is not a vulnerability.

**False-positive gate:** A service banner may be spoofed, stale or a proxy signature.

**Required output:** scope/authorization status; actual facts; `evidence://` references; affected boundary; hypotheses and negative checks; operator decision required; minimal-impact next step; confirmed limitations. Keep raw IPs, secrets, passwords, tokens, personal data and customer logs out of remote LLM context.

**Reporting:** When an observation is operator-verified, connect it to the exact UTC event, source and evidence hash, observed-versus-expected behavior, business impact, countercheck and reproducible remediation. Do not invent a tool run, an exploit, a CVSS score or a success claim. See OWASP WSTG 4.2 (https://wstg.owasp.org/stable/) and NIST SP 800-115 (https://csrc.nist.gov/pubs/sp/800/115/final).
