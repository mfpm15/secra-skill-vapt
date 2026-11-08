# ui.md — SECRA monitoring and control UI (PHASE 6 DESIGN)

Current app/static/index.html already renders engagement creation (lines 68-75), seven stage cards (79-82), log console (92-93), skill panel (105-110), and a Sapper graph viewer (113-115). It polls app/main.py endpoints every ~1.35 seconds (app/static/index.html:139-141,190-191). The button at line 80 sends cancel at 185; there is NO operator approval control, SSE/WebSocket or parallel-agent inspector yet.

## 1. Required pages and view contracts

| Route / component | Operator action | Read model | Strict privacy projection |
|---|---|---|---|
| /overview — EngagementList | Create / open / filter jobs; budget and health overview | EngagementSnapshot[] | Only ASSET_001, engagement alias, timestamps and status; no literal IP |
| /engagements/:id — AssessmentWorkspace | See active agents, coverage, risk class and step state | AgentRunSnapshot[] | Masked target refs and sanitized statuses |
| /engagements/:id/graph — SapperGraphPanel | Explore fact -> intent -> fact history | Existing filtered /graph API | Never render raw Sapper docs; do not edit graph schema |
| /engagements/:id/logs — EventStream | Filter chronological agent/tool events, export scrubbed logs | SanitizedEvent[] | Placeholders, reason codes, evidence ID; no secrets or raw stdout |
| /engagements/:id/approvals — ApprovalQueue | Approve/deny/pause risk-R3 action after reviewing exact sanitized parameters | ApprovalRequest[] | Target aliases; identity-protected approval decision |
| /engagements/:id/evidence — EvidenceIndex | See hashes, timestamps, redaction/quarantine state, reviewer-only export request | EvidenceMetadata[] | Only masked metadata until separate privileged local workflow |
| /engagements/:id/models — ModelAndBudget | Select 9Router model from approved route registry; set policy caps | ApprovedModelProfile[] | No provider key, customer data or raw prompt |
| /skills — KnowledgeLibrary | Search bundled SKILL.md and standards | Local catalog | Public curated skill text only |
| /settings — SecurityPolicy | Show egress status, trusted provider tiers, retention, audit health | Read-only policy view for most operators | No raw secrets/config credential values |

Navigation elements should present ACTUAL real worker IDs, not invented autonomous agent icons. A backend stage is labeled "stage" until genuine parallel agent tasks are running.

## 2. Create engagement and target display

Input phase: operator enters actual IP/CIDR into a local-only form which is posted over a secure local connection. Immediately after submission, clear raw form state; subsequent UI receives a stable local asset alias. If operator must inspect actual IP, use a privileged local audit screen with explicit reveal action, separate from normal monitoring and logs.

The browser must never receive rehydration maps, private token values, raw evidence bodies, or raw tool command arguments. Do not put sensitive IDs in browser URL/query, analytics, crash reports, HTML data-attributes or persisted client storage. Replace current sessionStorage bearer-token scheme with local same-site HttpOnly Secure session cookies (over TLS), CSRF checks on mutating actions and short-lived role-scoped sessions.

[ASUMSI] Initial deployment is a local authenticated operator with a TLS reverse proxy when accessed remotely. Reason: no identity provider or remote console deployment has been defined.

## 3. Streaming / connection contract

Prefer SSE for events, since dashboard monitoring is one-way. POST REST endpoints carry stop/approve/deny actions; SSE should not transmit controls. Browser EventSource uses a cookie session (custom X-Secra-Token header cannot be sent through native EventSource). No access token in query params.

Wire format:

    event: tool.completed
    id: 1842
    data: {"engagement_id":"...","agent_id":"agent-web-2","asset_alias":"<HOST_1>","status":"COMPLETED","evidence_id":"...","duration_ms":830}
    
    : heartbeat

SSE endpoint must honor Last-Event-ID on reconnect; if events are pruned, send a cursor-reset event requiring a fresh snapshot. Every SSE event already passes the privacy gateway and a schema filter; HTML escaping in the UI is a secondary defense.

Python API contracts (NEW; do not claim implemented):

    @router.get("/api/engagements/{eid}/stream")
    async def stream_engagement_events(eid: UUID, last_event_id: int | None, session: OperatorSession) -> EventSourceResponse: ...

    @router.get("/api/engagements/{eid}/snapshot")
    async def get_sanitized_snapshot(eid: UUID, session: OperatorSession) -> SanitizedEngagementSnapshot: ...

    @router.get("/api/engagements/{eid}/approvals")
    async def list_pending_approvals(eid: UUID, session: OperatorSession) -> list[ApprovalRequestView]: ...

    @router.post("/api/approvals/{approval_id}/decision")
    async def decide_approval(approval_id: UUID, body: ApprovalDecisionInput, session: OperatorSession) -> ApprovalReceipt: ...

    @router.post("/api/engagements/{eid}/stop")
    async def stop_engagement(eid: UUID, session: OperatorSession) -> CancellationReceipt: ...

    @router.post("/api/agents/{agent_id}/pause")
    async def pause_agent_run(agent_id: str, session: OperatorSession) -> TransitionReceipt: ...

    @router.post("/api/agents/{agent_id}/resume")
    async def resume_agent_run(agent_id: str, session: OperatorSession) -> TransitionReceipt: ...

    @router.get("/api/engagements/{eid}/evidence")
    async def list_masked_evidence(eid: UUID, session: OperatorSession) -> list[EvidenceMetadataView]: ...

Frontend contracts (NEW):

    type AgentPanelProps = {
      engagementId: string;
      agents: AgentRunSnapshot[];
      activeToolRunIds: string[];
      onStop: (eid: string) => Promise<void>;
      onPause: (agentId: string) => Promise<void>;
    };

    function subscribeEvents(eid: string, lastEventId: number, onEvent: (event: SanitizedEvent) => void): EventSubscription;
    function renderAgentTimeline(agentRuns: AgentRunSnapshot[]): HTMLElement;
    function renderMaskedEventLog(events: SanitizedEvent[]): HTMLElement;
    function renderApprovalQueue(requests: ApprovalRequestView[]): HTMLElement;
    function submitApproval(decision: "approve" | "deny", requestId: string, expectedVersion: number): Promise<ApprovalReceipt>;
    function renderSapperGraph(snapshot: SanitizedGraphView): HTMLElement;

## 4. Approval panel correctness

Every approval card displays: action class, named tool adapter, sanitized typed arguments, asset alias, risk level, scope version, operator identity, requested_at, expiration and purpose. Approval requests are immutable; editing parameters creates a new request and invalidates the previous signature.

- APPROVE: only for an exact R3 request and current scope/policy; must be logged and checked again by the tool gateway.
- DENY: durable rejection; no future retry without new explicitly reviewed request.
- EXPIRED: clearly visible and never auto-approved.
- STOP: global emergency action, present throughout the active workspace, moves all running agents into cancellation pipeline and disconnects network egress after group termination.
- PAUSE: prevents new requests, safely finishes or terminates the current bounded action according to its policy; state becomes PAUSED only when confirmed by backend.
- RESUME: revalidates scope, lease, approval and budget; no implicit restart of high-impact action.

Buttons represent requested actions until the backend returns a valid transition receipt; UI must not optimistically show "Stopped" before process termination is confirmed.

## 5. Observability and UX details

- Header: engagement alias, access policy version, MODE=DEMO/LIVE, allowed provider tier, active/cancelled status.
- 7-stage pipeline remains available as a high-level summary, with actual parallel agent rows beneath.
- Agent row: active worker ID, task, work-graph intent ref (optional), status, last heartbeat, tool action, elapsed time, approval state and error reason.
- Timeline: per-agent swimlanes across the same time axis, overlapping only for truly concurrent tasks; distinguish idle vs queued vs waiting approval.
- Logs: event_id, UTC timestamp, agent alias, action class, event type, run_id, redacted summary, evidence hash pointer; tail follow/pause/filter/copy sanitized log.
- Graph: existing Sapper read-only /graph and /frontier endpoints, visually separate from runtime task leases. Never mutate graph-node/edge structure.
- Model usage: selected route, configured/effective tier, token and cost reservations, warning thresholds, fallback denied events.
- Privacy badge: actual redaction-policy version, egress status and quarantined event count. No badge claiming privacy guaranteed by regex.
- Accessibility: keyboard operation, descriptive status, visible error state, no color-only meaning, screen-reader logs with bounded announcements.

## 6. Browser security and output controls

- Content-Security-Policy limiting script/connect origins; no external analytics or third-party scripts.
- HTML values inserted only as textContent or trusted escaped fragments; never append arbitrary model HTML.
- CSRF protection on state changes; HttpOnly cookie session; no auth token in EventSource URL.
- Isolate report download from privileged raw evidence export, log every privileged reveal.
- UI search/filter works on sanitized copies only. Do not store raw values in Service Worker/cache/localStorage.
- Log retention bound: server cursor + streamed batches; client holds capped recent events; backpressure and disconnect handled.
- On privacy quarantine, show blocked/quarantined reason, never a truncated raw excerpt.

## 7. Acceptance tests

    def test_operator_snapshot_never_contains_target_ip_or_secret() -> None: ...
    def test_eventsource_replay_after_disconnect_without_gaps() -> None: ...
    def test_sse_auth_without_query_string_token() -> None: ...
    def test_approval_requires_role_and_current_action_digest() -> None: ...
    def test_stop_button_waits_for_backend_confirmation() -> None: ...
    def test_expired_approval_cannot_resume_agent() -> None: ...
    def test_parallel_timeline_matches_actual_task_timestamps() -> None: ...
    def test_ui_graph_uses_existing_readonly_sapper_contract() -> None: ...
    def test_dom_has_no_model_html_injection_or_raw_ip_value() -> None: ...

Phase-6 gate: SSE stream survives reconnect with correct cursor; stop/approve work through authenticated APIs; operator sees placeholders rather than raw target/evidence data; graph-core and frontier remain unchanged.
