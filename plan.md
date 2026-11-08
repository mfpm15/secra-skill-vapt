# plan.md — SECRA delivery plan: eight implementation phases

Baseline audited: main 707c25f6747c641e33cfd3f2dd0422daf8bf7e76. Graph core, Sapper frontier resolver and node/edge schema are immutable prerequisites. Existing code implements a sequential single-operator dashboard with fixed Nmap/curl actions; the features below are **not yet implemented** merely because this plan exists.

Dependencies: Phase 1 mandatory before any new model context; Phase 2 mandatory before new Kali tool adapters; Phase 3 before parallel multi-provider use; Phase 4/5 before Phase 6 real-time operator workflow. Every phase must pass unit, integration and privacy leakage tests before the next phase can merge.

## Phase 1 — Deterministic masking gateway, first priority

Files to implement: app/privacy_gateway.py, app/privacy_vault.py, app/privacy_policy.py, tests/test_privacy_gateway.py. Keep app/security.py compatibility until callers migrate.

Contracts:
    def redact_tool_output(raw: bytes, media_type: str, ctx: PrivacyContext, vault: MapVault) -> RedactionResult: ...
    def redact_stream_chunk(chunk: bytes, state: RedactionStreamState, ctx: PrivacyContext, vault: MapVault) -> tuple[bytes, RedactionStreamState]: ...
    def rehydrate_typed_field(value: str, expected_type: EntityType, ctx: PrivacyContext, vault: MapVault) -> ResolvedField: ...
    def authorize_llm_egress(payload: dict, ctx: PrivacyContext, policy: ProviderPrivacyPolicy) -> SanitizedLLMRequest: ...

DoD:
- Typed placeholders <HOST_1>, <EMAIL_2>, <TOKEN_3> issued deterministically per engagement; map stored encrypted locally, not transmitted.
- Rehydration rejects unknown, colliding, expired and cross-engagement placeholders; no shell invocation.
- Full bytes of serialized outgoing requests intercepted and tested for IPs, customer names, email, hash, cookie and tokens.
- URL-embedded entity, reserved-placeholder collision, JSON encoding and split-Bearer streaming test corpus pass.
- Arbitrary tool stdout cannot reach a remote model; insufficiently classifiable input is quarantined.
- Failures are observable using only non-sensitive error codes.

Go/no-go tests:
    def test_collision_literal_vs_generated_placeholder() -> None: ...
    def test_split_token_across_every_stream_boundary() -> None: ...
    def test_foreign_egress_contains_no_private_data() -> None: ...

## Phase 2 — Kali Tool Gateway + enforced scope, second priority

Files: app/tool_gateway.py, app/tool_registry.py, app/evidence_vault.py, app/scope_guard.py, tests/test_tool_gateway.py.

Contracts:
    def validate_tool_intent(intent: StructuredToolIntent, registry: SignedToolRegistry) -> ToolPolicy: ...
    def enforce_scope_per_connection(target: AuthorizedTarget, peer_ip: str, scope: ScopePolicy) -> None: ...
    def run_tool(intent: AuthorizedToolIntent, policy: ToolPolicy, cancel: CancellationToken) -> ToolReceipt: ...
    def terminate_process_group(tool_run_id: UUID, signal: Literal["TERM","KILL"]) -> None: ...

DoD:
- Introduce reviewed R0-R4 tool classes; initial R2 adapters cover bounded Nmap and curl only; fixed argv, no model-generated shell commands.
- Every network call checks approved asset/IP/CIDR/port; DNS rebinding, redirects, proxy and IPv6 alternatives cannot escape the sandbox egress allowlist.
- Tool runner writes encrypted, hash-sealed raw stdout/stderr to local evidence storage **before** any masking/agent/UI/LLM event.
- Hard timeout, process-group/container kill, cancellation and audit receipt work even with slow or chatty outputs.
- Failed raw artifact write blocks downstream egress.
- One action_id/request_id maps to one attempt; duplicate delivery cannot cause duplicate network execution.

Go/no-go tests:
    def test_out_of_scope_peer_denied_by_network_fence() -> None: ...
    def test_raw_artifact_sealed_before_redaction() -> None: ...
    def test_cancel_kills_descendants_and_blocks_future_connect() -> None: ...

## Phase 3 — 9Router provider-tier model routing and budgets

Files: app/model_router.py, app/usage_ledger.py, tests/test_model_router.py. Do not modify graph or resolver.

Contracts:
    def resolve_provider_tier(route: ProviderRoute, registry: ProviderRegistry) -> ProviderPrivacyPolicy: ...
    def select_model(task: AgentTask, budget: EngagementBudget, approved_routes: list[ProviderRoute]) -> ProviderRoute: ...
    def reserve_llm_budget(eid: UUID, request_id: UUID, estimated_input: int, estimated_output: int, route: ProviderRoute) -> BudgetReservation: ...
    def verify_effective_route(receipt: RouteReceipt, reservation: BudgetReservation, policy: ProviderPrivacyPolicy) -> None: ...

DoD:
- Discover exact model IDs from local 9Router /v1/models; set explicit provider account, tier and allowed route ID, not guessed brand trust.
- Foreign default; no raw names, IPs, keys, hashes, headers or evidence to ANY remote model.
- Disable cross-provider fallback; ambiguous effective provider fails closed. Cheapest/strongest class is configurable and empirically benchmarked, not hard-coded.
- Per-engagement token and cost reservations/settlement are atomic; max requests, hard stop and alerts work with parallel requests.
- 9Router outage does not change the route or leak previously quarantined content.

Go/no-go tests:
    def test_provider_fallback_tier_downgrade_blocked() -> None: ...
    def test_budget_exhaustion_denies_before_network_io() -> None: ...
    def test_no_raw_context_on_any_9router_transport_path() -> None: ...

## Phase 4 — Parallel agent runtime, durable event bus and asset locks

Files: app/runtime_scheduler.py, app/runtime_store.py, app/event_bus.py, app/leases.py, database migrations; tests/test_runtime.py.

Contracts:
    def schedule_ready_tasks(eid: UUID, graph_snapshot: GraphReadView, limits: ConcurrencyPolicy) -> list[AgentTask]: ...
    def transition_agent(agent_id: str, task_id: UUID, from_state: AgentState, to_state: AgentState, expected_version: int) -> AgentRun: ...
    def acquire_lease(asset_key: str, mode: str, owner: str, ttl_seconds: int) -> AssetLease | LeaseDenied: ...
    def publish_outbox(cursor: int, bus: EventBus, max_batch: int = 100) -> PublishResult: ...

DoD:
- At least three independent agents truly overlap in execution; each has stable ID, tool receipt, bounded workload and visible heartbeat.
- One active network lease per canonical asset/IP; simultaneous alias collision prevented; stale fencing token denied.
- Durable, sanitized event/outbox records survive crashes; Sapper facts/edges are not used as locks.
- Untrusted model output cannot expand dependencies, scopes or capabilities.
- Graph, resolver and schema blob hashes remain identical to commit 707c25f.

Go/no-go tests:
    def test_real_concurrency_and_exclusive_asset_lock() -> None: ...
    def test_outbox_replay_after_worker_crash() -> None: ...
    def test_protected_sapper_files_hash_unchanged() -> None: ...

## Phase 5 — Approval hooks, pausing, kill and recovery

Files: app/approvals.py, app/recovery.py, app/operator_policy.py; tests/test_approvals_recovery.py.

Contracts:
    def require_action_approval(intent: StructuredToolIntent, policy: ToolPolicy, approvals: ApprovalStore) -> ApprovalDecision: ...
    def apply_approval_decision(approval_id: UUID, actor: OperatorIdentity, decision: Literal["approve","deny"]) -> ApprovalReceipt: ...
    def bootstrap_recovery(db: RuntimeDatabase, containers: SandboxRegistry) -> RecoverySummary: ...
    def cancel_engagement(eid: UUID, actor: OperatorIdentity, reason_code: str) -> CancellationReceipt: ...

DoD:
- R3 tasks remain paused without an authenticated, unexpired approval matching exact action digest, scope and actor.
- Deny/expire/revoke are durable; parameter changes invalidate old approvals; no implicit acceptance.
- Stop kills child processes and revokes network privileges; resume revalidates scope, provider tier, leases and budget.
- After forced crash, tasks reconcile to safe states; never silently replay live scans or close unverified Sapper intents.
- Audit trail shows action, actor, decision, version and timestamps without raw secrets.

Go/no-go tests:
    def test_unapproved_R3_has_zero_network_activity() -> None: ...
    def test_kill_resume_scope_and_approval_revalidated() -> None: ...
    def test_crash_recovery_preserves_unfinished_graph_intent() -> None: ...

## Phase 6 — Operator UI, SSE and real-time visualizations

Files: app/ui/* or a new versioned frontend package, app/api/stream.py, tests/test_ui_events.py; keep read-only Sapper graph API compatible.

Contracts:
    async def stream_engagement_events(eid: UUID, last_event_id: int | None, session: OperatorSession) -> EventSourceResponse: ...
    async def get_sanitized_snapshot(eid: UUID, session: OperatorSession) -> SanitizedEngagementSnapshot: ...
    async def decide_approval(approval_id: UUID, body: ApprovalDecisionInput, session: OperatorSession) -> ApprovalReceipt: ...
    function subscribeEvents(eid: string, lastEventId: number, onEvent: (e: SanitizedEvent) => void): EventSubscription;

DoD:
- Operator inputs IP/scope once; routine monitoring displays aliases/placeholders, not raw customer values.
- SSE Last-Event-ID reconnect/replay works, event deduplication is idempotent and backpressure bounded.
- Agent swimlanes display **genuine parallel executions**, current tool, timestamps, progress, status and approvals.
- Stop, pause, resume, approve and deny are backed by real authenticated endpoints and verified transition receipts.
- Graph view remains read-only from existing public_graph/resolve_frontier contracts; no graph node/edge changes.
- Browser, SSE and export channels contain no fixture secrets, raw hashes or real IPs.

Go/no-go tests:
    def test_sse_reconnect_replays_sanitized_events() -> None: ...
    def test_operator_sees_aliases_only() -> None: ...
    def test_stop_and_approve_buttons_change_backend_state() -> None: ...

## Phase 7 — Pentester knowledge routing, findings and reporting

Files: expanded knowledge/catalog.json, app/findings.py, app/coverage.py, app/reporting.py; tests/test_findings.py.

Contracts:
    def select_skills(services: list[dict], limit: int = 6) -> list[dict]: ...  # preserve existing interface
    def map_verification_requirements(assessment_kind: str, standard_version: str) -> CoveragePlan: ...
    def review_candidate_finding(candidate: CandidateFinding, evidence: EvidenceIndex, reviewer: ReviewerContext) -> FindingVerdict: ...
    def generate_report(eid: UUID, findings: list[ConfirmedFinding], privacy: ReportRedactionPolicy) -> ReportArtifact: ...

DoD:
- Keep existing 12 skills and add version-pinned WSTG/ASVS/MASTG/API coverage as independently reviewed packs.
- Source/standard attribution and license review recorded; no unreviewed third-party skill copied.
- Agent recommendations remain hypotheses; independent evidence review required before confirming a vulnerability.
- Reports distinguish observations, candidates, confirmed findings and retest; no hallucinated PoC or missing CVSS reasoning.
- Client deliverables respect privileged local evidence export rules; remote model sees only sanitized summaries.

Go/no-go tests:
    def test_open_port_does_not_become_confirmed_finding() -> None: ...
    def test_sensitive_report_not_sent_to_remote_llm() -> None: ...
    def test_findings_have_reproducible_evidence_and_review() -> None: ...

## Phase 8 — Release hardening, multi-user safety and controlled deployment

Files: migrations, deployment manifests, runbooks, CI threat-model fixtures, SBOM and dependency pinning.

Contracts:
    def evaluate_release_gate(artifact: BuildArtifact, policy: ReleasePolicy, results: TestSuiteResults) -> ReleaseDecision: ...
    def validate_network_isolation(engagement_id: UUID, firewall: NetworkPolicy) -> IsolationVerdict: ...
    def verify_audit_chain(events: Sequence[ToolAuditEvent]) -> AuditVerdict: ...
    def rotate_vault_key(eid: UUID, actor: OperatorIdentity) -> RotationReceipt: ...

DoD:
- Full secret/PII leak corpus passes at actual 9Router wire boundary, including retries, errors, streaming and telemetry.
- Threat-model and penetration test of SECRA itself completed on authorized staging, including malicious tool output/prompt injection.
- Provider fallback leak tests, stale lease / concurrent-agent tests, child-process kill and crash-resume tests pass in CI.
- Non-root sandbox with denied default egress, TLS session/RBAC/CSRF, encrypted artifacts, auditable approval ledger and retention controls validated.
- CI pins dependencies and checks protected Sapper graph/resolver/schema hash invariants.
- Operator documentation covers backup, key rotation, emergency stop, privacy quarantine and rollback.

Go/no-go tests:
    def test_end_to_end_no_known_raw_secret_egress() -> None: ...
    def test_fuzzed_untrusted_tool_output_never_becomes_command() -> None: ...
    def test_production_deployment_denies_unsanctioned_egress() -> None: ...

## Cross-phase non-regression rule

Protected baseline:
- vendor/sapper_v2/sapper.py
- app/sapper_integration.py (graph-core API contracts and resolve_frontier)
- graph node/edge schema

Every phase must check source and API compatibility against the pinned baseline, and must not change the protected files without a separate, explicitly reviewed scope change. Runtime tables and new gateway modules are additive.

Suggested validation command for current baseline (this plan does NOT imply future tests exist yet):

    python -m compileall -q app vendor/sapper_v2
    python -m pytest -q

Current CI checks compilation and existing unit tests; the phase-specific tests above are requirements to implement, not claims of completed work.

[ASUMSI] Default concurrency, cost and token numbers in router.md/runtime.md are pilot configuration values. Reason: engagement workloads, machine performance and 9Router pricing have not been provided.
