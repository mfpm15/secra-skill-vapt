# runtime.md — parallel agent event runtime and crash recovery (PROPOSED)

Baseline: app/main.py:41-42 keeps worker state in a process dictionary; app/main.py:227-348 runs seven sequential stage labels; app/main.py:469-493 starts/stops a thread. app/main.py:61-78 has SQLite events, but not a durable task queue, leases, retry ledger, process registry or event outbox. The existing Sapper fact–intent graph and frontier resolver must stay byte-identical to commit 707c25f.

## 1. Separation from immutable Sapper graph

Sapper graph = assessment reasoning/provenance of facts and intents. It remains an existing component, not a job queue, mutex or approval store.

NEW tables, independently versioned (never alter Sapper schema):
- runtime_agents: engagement_id, agent_id, state, attempt, version, heartbeat_at, task_kind, scope_version.
- runtime_tasks: task_id, engagement_id, graph_intent_ref (optional), input_snapshot_hash, status, risk, idempotency_key.
- runtime_events: monotonic id, engagement_id, agent_id, event_type, sanitized JSON payload, created_at, schema_version.
- runtime_outbox: event_id, published_at, delivery_attempts (commit in same transaction as event).
- runtime_asset_leases: asset_id, engagement_id, owner_agent_id, lease_id, mode, fencing_token, expires_at.
- runtime_approvals: approval_id, action_digest, scope_version, operator_id, decision, expires_at.
- runtime_tools: tool_run_id, task_id, sandbox_id, process_group_id, lease_id, cancel_requested_at, exit_status.
- runtime_budget: engagement_id, reserved_token_count, incurred_usd, request_count, remaining_caps.

No raw secrets or IP strings in these operational tables: use local asset aliases and encrypted references. Existing SQLite target data remains legacy data requiring separate migration and encryption.

## 2. Agent state machine

    CREATED -> QUEUED -> RUNNING -> COMPLETED
                         |          |
                         |          +-> WAITING_APPROVAL -> RUNNING
                         |          |        |
                         |          |        +-> CANCELLED / EXPIRED
                         |          +-> PAUSING -> PAUSED -> QUEUED
                         |          +-> CANCELLING -> CANCELLED
                         |          +-> FAILED -> QUEUED (only reconciled retry)
                         +-> CANCELLED

    RUNNING -> INTERRUPTED (worker lease lost) -> RECOVERING
    RECOVERING -> QUEUED (idempotent read-only task) OR PAUSED (manual review)

All transitions require an expected_version compare-and-swap; terminal states cannot become RUNNING without a new explicit attempt and audited operator action. Approval WAITING_APPROVAL must not hold a network-running process.

State transition contract:

    class AgentState(StrEnum):
        CREATED; QUEUED; RUNNING; WAITING_APPROVAL; PAUSING
        PAUSED; RECOVERING; INTERRUPTED; CANCELLING
        CANCELLED; FAILED; COMPLETED; EXPIRED

    @dataclass(frozen=True)
    class AgentTask:
        task_id: UUID
        engagement_id: UUID
        agent_id: str
        action_id: str
        dependencies: tuple[str, ...]
        graph_intent_ref: str | None
        asset_alias: str
        risk: str
        scope_version: int
        attempt: int
        idempotency_key: str

    @dataclass(frozen=True)
    class RuntimeEvent:
        event_id: int
        engagement_id: UUID
        agent_id: str | None
        event_type: str
        payload: dict     # sanitized structured fields only
        schema_version: int
        timestamp_utc: datetime

    def schedule_ready_tasks(engagement_id: UUID, graph_snapshot: GraphReadView, limits: ConcurrencyPolicy) -> list[AgentTask]: ...
    def transition_agent(agent_id: str, task_id: UUID, from_state: AgentState, to_state: AgentState, expected_version: int) -> AgentRun: ...
    def append_runtime_event(event: RuntimeEvent, db: RuntimeDatabase) -> int: ...
    def publish_outbox(cursor: int, bus: EventBus, max_batch: int = 100) -> PublishResult: ...
    def heartbeat_worker(task_id: UUID, worker_id: str, fencing_token: int) -> None: ...
    def reconcile_lost_worker(task_id: UUID, now: datetime) -> RecoveryDecision: ...
    def pause_agent(task_id: UUID, actor: OperatorIdentity) -> TransitionReceipt: ...
    def resume_agent(task_id: UUID, actor: OperatorIdentity, expected_version: int) -> TransitionReceipt: ...
    def cancel_engagement(eid: UUID, actor: OperatorIdentity, reason_code: str) -> CancellationReceipt: ...
    def apply_approval_decision(approval_id: UUID, actor: OperatorIdentity, decision: Literal["approve","deny"]) -> ApprovalReceipt: ...

## 3. Parallel agent scheduler

Agents may work concurrently only when their ready work graph does not violate scope, dependency, tool risk or resource lock policy:

    ready = resolve_frontier(eid, data_dir)["ready_ids"]  # read-only existing resolver
    tasks = schedule_ready_tasks(eid, sanitized_graph_view, concurrency_policy)

The scheduler maps verified Sapper intent IDs to external runtime task IDs; it does not modify resolver semantics or Sapper node/edge schema. Since the baseline graph currently chains seven stages sequentially, phase 4 must create independent task intents or external task DAG nodes to permit actual concurrent work, without rewriting existing graph-core.

Operator-configurable starting limits (NOT current settings):
- max_parallel_agents_per_engagement = 3
- max_parallel_active_scans_per_asset = 1
- max_parallel_passive_tasks_per_asset = 4
- max_running_tool_processes = 6 globally
- max_llm_requests_per_engagement = 2 in flight (also subject to budget)

[ASUMSI] SQLite WAL with one local orchestrator owns task/lease transactions for first delivery; reason: baseline already uses SQLite and no Redis/Postgres server has been provisioned. Multi-node scheduling requires PostgreSQL or another storage mechanism with authoritative distributed fencing.

## 4. Resource lease and fencing

Asset keys: canonical, internally held asset_id (never user-provided URL text). If scopes overlap, use a canonical destination connection-set key as well as an asset key so two different aliases of the same IP cannot bypass the exclusive lease. A read lock allows independent offline tasks; an active network action demands an exclusive lease.

    @dataclass(frozen=True)
    class AssetLease:
        lease_id: UUID
        asset_key: str
        mode: Literal["read","exclusive"]
        owner_agent_id: str
        fencing_token: int
        expires_at: datetime

    def acquire_lease(asset_key: str, mode: str, owner: str, ttl_seconds: int) -> AssetLease | LeaseDenied: ...
    def renew_lease(lease: AssetLease, expected_fencing_token: int) -> AssetLease: ...
    def release_lease(lease: AssetLease) -> None: ...
    def validate_fencing_token(asset_key: str, token: int) -> None: ...

Use transactional row-lock/CAS; if two workers request the same exclusive asset simultaneously, exactly one receives the active lease. Heartbeat extends only the current valid fencing token. Upon expiry, deny stale-worker writes; verify and tear down old process/network namespace before issuing a new exclusive lease. A timed-out lease does not by itself prove the original scanner stopped.

## 5. Durable bus, event log and streaming

Write a privacy-approved event and matching outbox row in the same SQLite transaction; publish outbox to a bounded in-process pub/sub for local delivery or Redis/NATS after a storage migration. Delivery can be at-least-once; consumers deduplicate by event_id, no false "exactly once" guarantees.

Event record is sanitized BEFORE entering runtime_events and BEFORE SSE. Raw tool data belongs only in the evidence vault. Event subjects include agent.state, tool.started, tool.completed, tool.timeout, tool.cancelled, approval.requested, approval.decided, privacy.blocked, budget.threshold, and report.ready.

    class EventBus(Protocol):
        async def publish(self, event: RuntimeEvent) -> None: ...
        async def subscribe(self, engagement_id: UUID, after_id: int) -> AsyncIterator[RuntimeEvent]: ...

    async def stream_events_sse(
        engagement_id: UUID,
        user: OperatorIdentity,
        last_event_id: int | None = None
    ) -> AsyncIterator[ServerSentEvent]: ...

EventSource reconnects with Last-Event-ID; server reads missing events from durable storage, then streams live events, ordered by event_id. Gap/out-of-retention must return explicit cursor_reset and require snapshot reload, not silently omit events. Send heartbeat comment every 15s and enforce a bounded queue; a slow browser cannot exhaust RAM.

FastAPI supports Server-Sent Events (event-stream) in newer releases; compatibility must be pinned and tested against actual installed framework. Reference: https://fastapi.tiangolo.com/tutorial/server-sent-events/.

## 6. Crash/resume contract

At worker startup:
1. Identify RUNNING tasks with stale heartbeat.
2. Mark INTERRUPTED and persist a recovery event.
3. Kill/reconcile orphan process groups/containers and revoke expired network access.
4. Verify evidence spool integrity and last sealed chunk.
5. Recheck current authorized scope version, approval token, provider tier and engagement budget.
6. Resume only idempotent offline tasks; do NOT blindly replay a live scan or state-changing action.
7. Recreate queued tasks with fresh attempt and fencing token; preserve old attempts for audit.
8. Do not auto-close existing Sapper intents as completed when a worker dies. The graph records only actually verified facts.

    def bootstrap_recovery(db: RuntimeDatabase, containers: SandboxRegistry) -> RecoverySummary: ...
    def reconcile_evidence(run_id: UUID, vault: EvidenceVault) -> EvidenceRecoveryResult: ...
    def checkpoint_task(task_id: UUID, state: dict, expected_version: int) -> CheckpointReceipt: ...
    def resume_safe_task(checkpoint: Checkpoint, approval: ApprovalDecision) -> NewTaskAttempt: ...

## 7. Acceptance tests

    def test_three_independent_agents_run_concurrently_without_graph_mutation() -> None: ...
    def test_two_active_agents_on_same_ip_cannot_both_hold_exclusive_lease() -> None: ...
    def test_same_ip_with_two_aliases_collides_on_lease_key() -> None: ...
    def test_stale_heartbeat_fencing_rejects_late_output() -> None: ...
    def test_event_outbox_replays_after_restart_without_duplication_in_UI() -> None: ...
    def test_sse_reconnect_last_event_id_replays_ordered_events() -> None: ...
    def test_sse_never_contains_raw_IP_token_or_customer_name() -> None: ...
    def test_approval_deny_and_expiry_prevent_resumption() -> None: ...
    def test_cancel_prevents_future_actions_and_terminates_running_process_tree() -> None: ...
    def test_crash_does_not_mark_unfinished_sapper_intent_done() -> None: ...

Gate: demonstrable real task overlap for independent agents, exclusive asset locking for active scans, durable event replay, explicit operator approval and cancellation, and strict separation from the unchanged Sapper graph-core.
