# SECRA Pentester Knowledge

12 independent, original SKILL.md files under skills/, indexed through catalog.json.

- A local, deterministic router selects skills by normalized service class.
- Selected skill texts are bundled with the application and versioned in Git.
- Only vetted methodology text (not customer input, HTTP response or scanner log)
  is inserted into the LLM system prompt when an engagement enables 9Router.
- LLM input also includes a positive-allowlisted alias plus port/service pairs.
- The LLM never receives customer IP, credentials, source code or raw evidence.
- The agent cannot use the methodology to issue arbitrary shell commands.
- Findings are not automatically verified or exploited.

OWASP WSTG 4.2 is the stable release; use version-aware IDs and references
when building full test case coverage. OWASP MASTG/MASVS, ASVS, API Security
and FIRST CVSS are cited as external standards, not copied verbatim.
Trail of Bits Skills and Claude-Red are researched but not copied into this
catalog; third-party text requires explicit licensing and provenance review.

Future work: signed curated skill manifests, coverage tracking by WSTG v42
identifier, skill review dates, full evidence schema, per-customer adapter rules,
expanded tool registry and sandboxed execution.
