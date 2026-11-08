# gateway.md — Kali tool execution gateway (PROPOSED)

Baseline reference: app/main.py:117-181 contains fixed Nmap/curl subprocess functions, and app/main.py:469-493 has in-memory start/stop. No generic agent-callable tool gateway, encrypted raw-output evidence store, process-group termination, or operating-system network egress enforcement exists at commit 707c25f.

## 1. Gateway placement

    Orchestrator Agent -> StructuredToolIntent (no arbitrary commands)
      -> identity/engagement check -> action risk policy
      -> placeholder resolver (only typed approved target fields)
      -> scope authorization -> asset lease -> approval decision
      -> host/container egress firewall + DNS/redirect guard
      -> fixed Kali adapter argv in sandbox
      -> encrypted raw output spool FIRST -> parser -> masking -> event bus
      -> masked agent summary (NOT raw tool output to LLM)

No agent or browser directly calls subprocess, SSH, shell, Docker socket, network socket, or a free-form system command. Every tool has a pre-reviewed adapter, version, impact class, timeout, output quota, and approved argument schema.

## 2. Declarative tool registry

| Tool/action | Risk class | Allowed behavior | Initial timeout | Approval |
|---|---|---|---|---|
| asset_inventory.read | R0 | Read engagement metadata only | 5s | Authenticated operator |
| nmap.tcp_top20 | R2 | TCP connect, top 20 ports, T2, no scripts, one pinned IP | 65s | Authorized scope and approved scan mode |
| curl.http_head | R2 | HEAD only, no redirects/proxy, bounded URL, specified TCP port | 10s | Authorized scope |
| tls.certificate_read | R2 | Controlled TLS handshake and certificate metadata, no private keys | 12s | Authorized scope |
| zap.passive_import | R1 | Parse local sanitized existing artifacts, NO outbound network | 20s | Operator |
| nuclei.safe_template | R2 or R3 | Only reviewed, allowlisted template IDs; no arbitrary template source | Per-template, capped | R2 by policy; R3 requires per-action human approval |
| http.authenticated_test | R3 | Restricted synthetic test identity and approved scenario | 30s | Fresh signed approval, synthetic credential reference |
| destructive/exfiltration/bruteforce/persistence/pivot | R4 | No adapter implementation | N/A | DENY regardless of model |

R0 = local read only; R1 = passive offline analysis; R2 = bounded active observation; R3 = elevated or state-changing action with explicit human approval; R4 = prohibited.

The above extensions are a design registry: only Nmap/curl are implemented today. Exact tool versions and vendor plugins are deployment-pinned, not blindly installed from internet at run time.

## 3. Typed contracts

    @dataclass(frozen=True)
    class StructuredToolIntent:
        engagement_id: UUID
        agent_id: str
        request_id: UUID
        tool_id: str
        action_id: str
        target_ref: str             # local asset alias, never raw arbitrary command
        parameters: Mapping[str, JsonScalar]
        requested_at: datetime
        reason_code: str

    @dataclass(frozen=True)
    class ToolPolicy:
        action_id: str
        risk: Literal["R0","R1","R2","R3","R4"]
        allowed_parameter_schema: JsonSchema
        binary_path: Path
        binary_sha256: str
        timeout_ms: int
        max_stdout_bytes: int
        max_stderr_bytes: int
        max_parallel_by_asset: int
        network_enabled: bool

    @dataclass(frozen=True)
    class AuthorizedToolIntent:
        intent: StructuredToolIntent
        resolved_asset_id: str
        resolved_addresses: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]
        policy_hash: str
        approval_id: UUID | None
        lease_id: UUID
        sandbox_profile_id: str

    @dataclass(frozen=True)
    class ToolReceipt:
        tool_run_id: UUID
        exit_code: int | None
        signal: int | None
        started_at: datetime
        finished_at: datetime
        duration_ms: int
        evidence_id: UUID
        raw_sha256: str
        bytes_captured: int
        truncated: bool
        privacy_status: Literal["redacted","quarantined","blocked"]
        audit_event_ids: tuple[int, ...]

    def register_tool(spec: ToolPolicy, registry: SignedToolRegistry) -> None: ...
    def validate_tool_intent(intent: StructuredToolIntent, registry: SignedToolRegistry) -> ToolPolicy: ...
    def resolve_scoped_target(intent: StructuredToolIntent, scope: ScopePolicy, vault: MapVault) -> AuthorizedTarget: ...
    def enforce_scope_per_connection(target: AuthorizedTarget, peer_ip: str, scope: ScopePolicy) -> None: ...
    def require_action_approval(intent: StructuredToolIntent, policy: ToolPolicy, approvals: ApprovalStore) -> ApprovalDecision: ...
    def acquire_asset_lease(eid: UUID, asset_id: str, mode: Literal["read","exclusive"], ttl_ms: int) -> AssetLease: ...
    def build_fixed_argv(policy: ToolPolicy, intent: AuthorizedToolIntent) -> tuple[str, ...]: ...
    def run_tool(intent: AuthorizedToolIntent, policy: ToolPolicy, cancel: CancellationToken) -> ToolReceipt: ...
    def terminate_process_group(tool_run_id: UUID, signal: Literal["TERM","KILL"]) -> None: ...
    def seal_raw_output(stream: BinaryIO, evidence: EvidenceVault, run_id: UUID) -> EvidenceReceipt: ...
    def emit_sanitized_tool_event(run_id: UUID, evidence_id: UUID, privacy: PrivacyGateway) -> SanitizedEvent: ...
    def halt_engagement(eid: UUID, cause: str, authority: OperatorIdentity) -> CancellationReceipt: ...

## 4. Hard scope enforcement

Scope input: signed Rules of Engagement asset allowlist + explicit IP/CIDR plus optional permitted domains, port sets, time windows, excluded networks, API rate caps and test identity profile. The scope signature binds a version and the operator identity. The initial checkbox alone is not sufficient for advanced actions.

Three independent checks:
1. Intent validation: resolve local target_ref to known asset; reject unknown literal host, raw external URL, arbitrary target change or unfamiliar placeholder.
2. Connection boundary: enforce destination IP/CIDR and allowed port at network namespace/firewall layer; deny default route outside authorized addresses. Re-check actual peer socket destination after DNS resolution. Deny loopback, metadata IPs and other prohibited infrastructure unless explicitly isolated/approved.
3. Result boundary: unknown host/URL discovered from output is only a candidate; registering or contacting it requires a new scope authorization. LLM may not extend scope.

For domains: resolve A/AAAA via a controlled resolver; cache and pin valid records for an action; validate CNAME chain and every resolved IP, TLS SNI/Host, destination port and final socket peer. DNS rebinding, IPv4-mapped IPv6, redirects, proxy environment variables and alternate URL schemes must not bypass checks. Redirect following defaults OFF.

For IPv4 targets in current MVP: preserve validate_scope() compatibility but move enforcement into the gateway before every network action. A backend Python check WITHOUT an OS-level network fence is not enough against future adapters.

[ASUMSI] Per-engagement rootless Linux container/namespace with nftables egress allowlist is the initial enforcement deployment. Reason: host network/firewall privileges and Kali installation mode are not yet specified.

## 5. Raw output: persist before redaction

All tool stdout, stderr, exit metadata and tool manifest are written to a local append-only encrypted evidence spool BEFORE any parser, sanitizer, UI event or LLM transport sees data. In memory, use bounded binary chunks; never let Popen pipes fill without draining; use nonblocking selectors/async subprocess stream readers. Use O_NOFOLLOW, private directories, exclusive creation and file descriptor permissions (0600). Encrypt each chunk with authenticated encryption; seal with SHA-256 manifest, monotonic byte index, timestamps, and audit hash chain.

Required ordering:

    launch -> read bounded chunk -> encrypt & durable write
      -> ACK sealed chunk -> parse sanitized projection
      -> privacy gateway -> UI / selected LLM

A write or encryption failure means the tool is paused/terminated and the chunk is NOT sent downstream. Artifact ID + content hash may appear in events; raw bytes do not.

Storage partitions:
- raw evidence: encrypted vault, available only to authorized local reviewer.
- sanitized observations: small structured DB records and placeholder IDs, readable by dashboard/agents.
- audit ledger: append-only action metadata, no raw stdout, no customer identifiers.
- Sapper graph: existing fact-intent node schema is unchanged; use only status summaries and local evidence IDs, never raw content.

Retention must be explicit per engagement; no permanent raw artifact by default without operator policy.

## 6. Reliable kill switch and approval

- Cancel must persist a STOP_REQUESTED event transactionally and mark the engagement non-schedulable BEFORE signalling workers.
- Send TERM to the isolated process group or container, wait grace period, then KILL; verify the process group has exited and block any subsequent network packet through the egress rule.
- Cancellation propagates across child processes; a container/netns can be torn down after artifact sealing.
- Every adapter checks CancellationToken before DNS, before connect, after result and before any LLM call.
- Hard timeout independent of model output and user session.
- R3 actions move to WAITING_APPROVAL without obtaining a network lease. A signed approval binds exact action_id, sanitized parameter digest, target_ref, scope_version, actor_id and expiry. Any parameter change invalidates the approval.
- Deny and expiry are durable transitions, not an implicit yes. No untrusted model or operator UI field can edit the Sapper resolver to approve actions.
- All executions are idempotent on (engagement_id, request_id); repeated delivery cannot trigger duplicate network actions.

## 7. Audit event schema and safety tests

    @dataclass(frozen=True)
    class ToolAuditEvent:
        event_id: int
        engagement_id: UUID
        agent_id: str
        tool_run_id: UUID
        action_id: str
        policy_version: str
        scope_version: int
        approval_id: UUID | None
        outcome_code: str
        evidence_sha256: str | None
        utc_timestamp: datetime

    def test_out_of_scope_literal_host_denied() -> None: ...
    def test_unknown_model_placeholder_never_executed() -> None: ...
    def test_dns_rebind_ipv6_mapped_and_redirect_denied() -> None: ...
    def test_proxy_environment_cannot_escape_allowlist() -> None: ...
    def test_tool_output_sealed_before_redacted_event() -> None: ...
    def test_raw_output_disk_error_prevents_downstream_egress() -> None: ...
    def test_cancel_kills_descendant_processes_and_blocks_new_connect() -> None: ...
    def test_unapproved_R3_cannot_acquire_asset_lease() -> None: ...
    def test_parallel_tool_invocations_share_one_exclusive_asset_lock() -> None: ...
    def test_no_shell_true_or_llm_provided_argv() -> None: ...

Gate: all network paths are checked at connection time, raw bytes are sealed locally before masking, tool subprocesses have bounded timeout and process-group cancellation, and every state transition emits a scrubbed audit record.
