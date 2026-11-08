# masking.md — deterministic privacy gateway, Phase 1 implementation and remaining hardening

This is the first mandatory enforcement layer before any model request. It runs locally, outside prompts, is not delegated to an LLM, and treats every upstream provider as untrusted. Do not activate raw-log-to-LLM processing before the acceptance tests below pass.

## Phase 1 source-of-truth status (implementation at current feature branch)

This document covers the long-term threat model. The Phase-1 subset below has ACTUAL Python code and CI tests; later-stage contracts below are DESIGN ONLY, not implied by this status.

| Requirement | Code | Verified by |
|---|---|---|
| Entity detection: FQDN/private+public IPv4/IPv6/email/JWT/Bearer/Basic/cookie/hash/home path/customer dictionary | app/masking/redact.py | tests/masking/test_corpus.py, test_entities.py, test_additional_cases.py |
| Stable typed placeholders and in-memory preview | app/masking/vault.py:MemoryVault | tests/masking/test_entities.py |
| Encrypted per-engagement local reversible map, outside project | app/masking/vault.py:Vault | tests/masking/test_vault.py |
| Unknown placeholder and free-form command denied | app/masking/rehydrate.py, app/masking/__init__.py:guard_unmask | tests/masking/test_entities.py |
| Public vs private IP policy (foreign/trusted/local) | app/masking/policy.py | tests/masking/test_entities.py, test_additional_cases.py |
| Split JWT across streaming chunks (no partial plaintext emission) | app/masking/redact.py:StreamingRedactor | tests/masking/test_streaming.py |
| Existing model user-message wire boundary (only canonical allowlisted JSON; immutable public system content) | app/main.py:gateway_request, app/masking/__init__.py:guard_mask | tests/masking/test_llm_transport.py |
| Command-line inspector | app/masking/__main__.py | tests/masking/test_cli.py |
| Hand-written golden corpus (9 samples, all labeled [SINTETIS]) | tests/corpus/raw/, tests/corpus/expected/ | tests/masking/test_corpus.py |

**Additional dependency:** cryptography==50.0.2, pinned in requirements.txt. Reason: AES-256-GCM authenticated encryption for vault mapping data; Python standard library does not provide a maintained AEAD implementation. For correct usage see https://cryptography.io/en/latest/hazmat/primitives/aead/.

**Data keys:** one 256-bit randomly generated file key per UUID engagement; stored mode 0600 under ~/.local/state/secra/masking/keys (or explicitly supplied external root). AES-GCM nonce 12 random bytes per write, authenticated engagement AAD; encrypted mapping under encrypted_maps. Mapping plaintext is never written to repository files. This version relies on Unix filesystem permissions and optional host disk encryption; there is no OS KMS/HSM or key escrow integration yet.

**Important scope limitation:** the redaction function is a deterministic best-effort detector for enumerated entity types, NOT a mathematically complete PII recognizer. All foreign model egress is therefore restricted to the existing fixed typed service schema; raw tool stdout, arbitrary HTML, customer reports or other free text are NOT accepted by guard_mask(for_llm=True), even if their regex redaction appears complete. All tiers retain secret redaction; the trusted/local tier permits public IPs, as explicitly required.

**Streaming contract:** StreamingRedactor buffers the entire message (maximum 2 MB) and emits nothing until finish(); it handles arbitrary chunk boundaries without leaking a partial JWT. It does NOT implement low-latency streaming redaction; truncation/overflow fails closed.

**Remaining enhancements from the broader threat model, not claimed implemented in Phase 1:** arbitrary nested URL/JSON/Unicode decoding, ambiguous high-entropy secrets, encrypted vault keys under KMS, map TTL/revocation/rotation, transparent per-engagement map lifecycle through a Kali tool gateway, provider fallback attestations, OS egress restrictions, approval/shell execution integration. Those belong to further privacy hardening and Phases 2–8. Do not treat passing the bounded corpus as a proof against previously unseen sensitive formats.

**CLI inspection:**

    python -m app.masking check tests/corpus/raw/httpx.jsonl
    python -m app.masking check tests/corpus/raw/client-record.txt --customer "Helios Analytics"
    python -m pytest tests/masking -q

The CLI uses a non-persistent MemoryVault and prints the redacted text, number of placeholders and unresolved list only. It never outputs the original lookup map.

---

## 1. Trust boundary and data order

    Kali subprocess -> encrypted raw evidence spool -> deterministic parser
        -> schema selection -> local entity recognizer + canonicalization
        -> placeholder allocator -> strict egress policy -> byte-level final request inspection
        -> 9Router -> untrusted structured output -> typed placeholder resolver
        -> scope + approval + risk validator -> tool gateway

There is NO raw-output-to-provider path and NO model-generated shell command path. A provider that presents itself as "trusted" is still an untrusted processor. The trust tier selects a stricter or looser local DATA RELEASE policy, never permission to send secrets.

## 2. Entity types and ordered detection

| Type | Placeholder example | Local detector | Data release policy |
|---|---|---|---|
| PRIVATE_IP, PUBLIC_IP, IPv6, CIDR | <IP_1> | Python ipaddress, URL authority parser; match private+public by default | Foreign/trusted never receive literal IP |
| HOSTNAME, FQDN, URL authority | <HOST_1> | RFC-aware URL parser, DNS-name patterns, exact known asset inventory | Mask authority and known aliases even when embedded in URL, JSON or headers |
| EMAIL | <EMAIL_2> | Validated email pattern incl case/Unicode normalizing | Mask entire address |
| API key, JWT, Bearer, OTP, Basic auth, password | <TOKEN_3> | Header/field-aware parsers, known prefix patterns, high-entropy token scan | Never send raw; unknown high-entropy strings cause quarantine |
| Cookie and Set-Cookie | <COOKIE_1> | HTTP header parser, cookie jar/attributes parser | Mask whole credential-bearing field; avoid preserving raw cookie values |
| Known customer, company, person, tenant name | <CUSTOMER_1> | Local customer directory, engagement dictionaries, locally curated deterministic match | Unknown names may evade detection: unstructured external egress denied |
| Hex digest, bcrypt/argon2/password hash, fingerprint | <HASH_1> | Contextual hash regex + lengths + local known-value registry | Mask hash value even if hash is not recoverable plaintext |
| File paths, internal URI, repository URL, project code | <PATH_1>, <PROJECT_1> | Local path and customer inventory patterns | Mask when customer-specific; otherwise quarantine ambiguous fields |
| Existing reserved placeholder text | <LITERAL_1> | Reserved-token lexer before masking | Escape or quarantine to prevent fake placeholder collision |

Precise matching priority: existing-literal placeholder escape -> full secret-bearing headers -> URL/URI parse -> names/IDs from local registry -> email -> CIDR/IP -> hostname -> context-dependent hash/path -> high-entropy unknown detection. Overlaps use longest enclosing sensitive span first, not multiple replacements on already replaced output. Perform Unicode NFKC normalization and protocol-appropriate decoding (JSON strings / URL-encoded fields / folded HTTP headers) before matching; retain original offsets locally for exact reconstruction if necessary.

Ambiguous, truncated, encoded or novel sensitive fields cannot be proven safe by regex alone. Default: send only fixed, typed aggregate metadata; quarantine arbitrary free text. Do not claim "zero leakage" without enforcing this stronger schema boundary.

## 3. Placeholder allocation and collision handling

Placeholder grammar (case-sensitive):

    PLACEHOLDER = "<" TYPE "_" POSITIVE_INTEGER ">"
    TYPE = "IP" | "HOST" | "EMAIL" | "TOKEN" | "COOKIE" | "HASH" |
           "CUSTOMER" | "PATH" | "PROJECT" | "LITERAL"
    examples: <HOST_1> <EMAIL_2> <TOKEN_3>

Allocation is deterministic for each engagement and redaction-map version: repeated identical entity of same class receives the same placeholder within that map; first occurrence in normalized input determines index. Indices are not global between engagements. Associate the active mapping with engagement_id, redaction_session_id, policy_version and request_id (never infer identity from placeholder alone).

Collision protocol:
1. Before replacing any sensitive span, find any literal text matching the reserved placeholder grammar.
2. Either encode it as a LITERAL entity in the local map or deny egress entirely for foreign-tier free text; an attacker-controlled "<TOKEN_3>" must not be interpreted as a valid locally generated credential.
3. Reject duplicate placeholder keys with different plaintext values and duplicate plaintext across incompatible types.
4. Reject rehydration from different engagement, session, policy version, approval or expired map.
5. Reject placeholder variants with Unicode lookalikes, case changes, different angle-bracket encodings or unknown IDs.

## 4. Encrypted mapping vault and lifetime

Only the local masking service may persist the bidirectional map:

    VaultRecord {
      engagement_id: UUID
      session_id: UUID
      mapping_version: int
      placeholder: str
      category: EntityType
      ciphertext: bytes
      nonce: bytes
      aad: bytes  # engagement/session/type/placeholder
      created_at: datetime
      expires_at: datetime
      source_evidence_id: str
    }

Persistence: encrypted at rest using a per-engagement data-encryption key, held behind a local OS keyring / vault, never in repository, browser, log line, Sapper fact, LLM prompt or 9Router request. Restricted file permissions, transactional insert, anti-replay nonces, KMS/OS-keyring master key where supported, rotation/revocation, retention and secure backup policy.

Mapping must NOT be stored in plaintext SQLite, sessionStorage, system prompts, 9Router telemetry, model conversations or Sapper node docs. Authorized local administrator rehydration for evidence export is a separate RBAC/audit pathway, not the LLM output pathway.

[ASUMSI] AES-256-GCM with OS-keystore-managed per-engagement encryption keys is the initial vault option. Reason: no KMS/secret-store choice is configured in the baseline.

## 5. Typed function contracts

All functions below are NEW contracts for future app/privacy_gateway.py, not functions currently present in app/security.py.

    class EntityType(StrEnum): IP; HOST; EMAIL; TOKEN; COOKIE; HASH; CUSTOMER; PATH; PROJECT; LITERAL

    @dataclass(frozen=True)
    class PrivacyContext:
        engagement_id: UUID
        session_id: UUID
        request_id: UUID
        provider_tier: Literal["local", "trusted", "foreign"]
        policy_version: str
        asset_alias: str

    @dataclass(frozen=True)
    class RedactionResult:
        sanitized: str
        map_version: int
        placeholder_ids: tuple[str, ...]
        quarantined: bool
        reason_codes: tuple[str, ...]

    def normalize_and_decode(blob: bytes, media_type: str, max_depth: int = 2) -> ParsedFieldSet: ...
    def detect_entities(fields: ParsedFieldSet, ctx: PrivacyContext) -> list[EntitySpan]: ...
    def allocate_placeholders(spans: list[EntitySpan], ctx: PrivacyContext, vault: MapVault) -> dict[EntitySpan, str]: ...
    def redact_tool_output(raw: bytes, media_type: str, ctx: PrivacyContext, vault: MapVault) -> RedactionResult: ...
    def redact_stream_chunk(chunk: bytes, state: RedactionStreamState, ctx: PrivacyContext, vault: MapVault) -> tuple[bytes, RedactionStreamState]: ...
    def authorize_llm_egress(payload: dict, ctx: PrivacyContext, policy: ProviderPrivacyPolicy) -> SanitizedLLMRequest: ...
    def assert_no_raw_sensitive(request_bytes: bytes, ctx: PrivacyContext, vault: MapVault) -> None: ...
    def rehydrate_typed_field(value: str, expected_type: EntityType, ctx: PrivacyContext, vault: MapVault) -> ResolvedField: ...
    def validate_model_action(action: StructuredToolIntent, ctx: PrivacyContext, scope: ScopePolicy) -> AuthorizedToolIntent: ...

Required gateway interfaces:

    class MapVault(Protocol):
        def put(self, ctx: PrivacyContext, entity_type: EntityType, plaintext: bytes) -> str: ...
        def get(self, ctx: PrivacyContext, placeholder: str, expected_type: EntityType) -> bytes: ...
        def revoke_engagement(self, engagement_id: UUID) -> None: ...

    def reject_unresolved(action: StructuredToolIntent, unresolved: tuple[str, ...]) -> Never: ...

## 6. Fail-closed rehydration contract

Rehydration is ONLY permitted on explicitly typed target/action parameter fields of a validated StructuredToolIntent. A model response is NEVER executed directly or concatenated into a shell string. Model-generated command text, URL navigation, alternate host discovery and arbitrary argv fragments are ignored or rejected.

- Known <HOST_1> in a target_id field: look up local map, validate category=HOST, revalidate asset registration and IP/CIDR policy, return resolved internal target ID to tool gateway.
- <TOKEN_3> in a command, header or argument: reject by default. Authentication uses locally selected named vault references controlled by operator, not model-rehydrated credentials.
- Unknown <HOST_999>, <TOKEN_3> absent from active map, partial <HOST_ or malformed encoded token: produce the **non-executable** diagnostic UNRESOLVED_PLACEHOLDER and deny action. Never pass the token or diagnostic to a shell.
- Any expired, wrong-engagement or wrong-tier placeholder: deny and audit event containing only placeholder type and reason code.
- Known entity rehydration is not equivalent to authorization; ScopeGuard and ToolGateway must independently authorize destination and action after rehydration.

## 7. Stream splits, URL embeddings and encoded fields

- Incoming raw tool output uses byte-preserving spool first, then stateful streaming masking with at least an 8 KiB carry buffer for entity boundaries. A detected candidate longer than the carry limit must quarantine the entire message; no partial fragment is emitted to the LLM.
- Multi-line folded Authorization headers, CRLF-split Bearer tokens, Unicode/percent-encoded identifiers and JSON-escaped strings are normalized before matching. Do not "fix" arbitrary raw binary into uncertain text and forward it.
- For https://server.internal.example/api?email=admin@customer.test&key=abc... replace only allowed structured fields as appropriate; foreign tier receives no raw URL at all, just asset alias / route class.
- For text intentionally containing <HOST_1>, first escape as literal or reject, then allocate genuine placeholders. No new placeholder can shadow a previously issued one in the same map.
- On parse failure, unsupported MIME, zip-bomb risk, huge binary or unknown transform: do not send content to any external provider.

## 8. Provider-tier privacy policy (never assume trust)

| Tier | Allowed LLM material | Raw secret | Arbitrary tool stdout |
|---|---|---|---|
| local | Reviewed structured observations; expanded local-only sanitized data if egress is physically blocked | DENY | DENY unless explicit offline-only review workflow |
| trusted | Public static skill text; fixed schema metadata + placeholders; no identifying content | DENY | DENY |
| foreign (default) | Public static methodology; ASSET alias; numeric ports and normalized allowlisted service labels only | DENY | DENY |

Tier "trusted" is an enterprise contractual classification for routing policy, NOT a guarantee that the remote provider is trustworthy. Unknown provider/route = foreign or hard deny. Gateway routing/fallback must never increase allowed detail.

## 9. Leakage and invariant test matrix

Test harness MUST intercept the actual serialized outbound HTTP request (including path, query, headers, prompt, tool messages, retry, stream payload and telemetry), not merely inspect pre-serialization Python objects.

| Test | Fixture | Required result |
|---|---|---|
| Collision | Literal "<HOST_1>" in raw text + genuine HOST_1 | One is escaped/quarantined; no alias shadowing or incorrect reverse-map |
| Unknown | Model outputs "<HOST_999>" | UNRESOLVED_PLACEHOLDER + DENY, zero subprocess calls |
| Cross-tenant | Reuse <IP_1> from engagement A in B | DENY, never map A's IP in B |
| URL nesting | Host, email, token inside scheme/authority/path/query | No raw sensitive bytes in any outbound request |
| Split token | "Authorization: Bea" and "rer abc..." across arbitrary byte chunks | No fragment emitted before full recognition, or message quarantined |
| Folded token | Bearer token with CRLF continuation | Full secret masked or egress denied |
| Encodings | Unicode, JSON escape and URL percent-encoding | Normalized detection, else quarantine |
| Hashes | 32/40/64/128 hex + bcrypt/argon2 | No raw hashes in external request |
| Customer names | Locally registered customer/tenant aliases | None appear in sent payload, URLs or headers |
| Unknown PII | Unregistered personal name in arbitrary free text | Free-text egress denied by schema, not "regex passed" |
| Streaming | 1-byte and randomized chunk sizes (1000 cases) | Redacted result equivalent to batch or fully quarantined |
| Fuzzing | Malformed placeholder/oversized/Unicode controls | DENY, never shell execution |
| Provider fallback | Expected trusted, effective foreign | Request denied or rebuilt under foreign policy before send |
| Kill audit | Cancel while tool output is pending | Raw bytes sealed locally; no post-cancel model request |

Required CI interfaces:

    def test_collision_literal_vs_generated_placeholder() -> None: ...
    def test_url_embedded_entities_never_egress() -> None: ...
    def test_split_bearer_token_all_chunk_boundaries() -> None: ...
    def test_cross_engagement_rehydration_denied() -> None: ...
    def test_unknown_placeholder_fails_closed_without_tool_call() -> None: ...
    def test_unknown_free_text_does_not_reach_remote_gateway() -> None: ...
    def test_request_wire_bytes_contain_no_fixture_secrets() -> None: ...

Exit criteria: no known sensitive fixture or customer identifier crosses the model egress transport; zero untrusted text reaches shell; unknown or ambiguous content is quarantined. This is a bounded, testable property—not a claim that arbitrary regex detectors can identify every possible sensitive datum.

References: https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/ and https://genai.owasp.org/glossary/prompt-injection/.

## Boundary clarification: masking vs. framing

- **Masking** (`app/masking/`) is deterministic local redaction of PII/secrets and the strict, canonical model-egress allowlist. It never turns raw scan results into permitted model prompts.
- **Framing** (`app/framing/`) is deterministic presentation of an *already masking-approved* canonical service-metadata brief. It adds a static, output-oriented wrapper and a checklist contract; it neither changes commands, paths, placeholders or scope nor overrides provider safety decisions.
- Transport checks must reconstruct the exact frame and validate the extracted canonical JSON with the unchanged Phase-1 guard before any HTTP request. The system prompt remains the existing reviewed static context.
- Safety refusals remain terminal. Optional retries are restricted to non-safety output formatting, with a hard cap of two model calls; default is one call.
- Audit stores only **pre-frame masked** canonical metadata and its exact framed version, plus detection codes, under private local storage. It must not store customer raw prompts, secrets, evidence, vault mappings, or unsafe model replies.
