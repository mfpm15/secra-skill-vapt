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
