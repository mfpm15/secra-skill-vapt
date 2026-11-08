# router.md — 9Router model routing and privacy policy (PROPOSED)

Baseline: app/main.py:38-39,183-223,409-425 discovers model IDs and calls /v1/chat/completions, but has no tier registry, effective-upstream verification, budget ledger or fallback restrictions. New router sits *after* the deterministic privacy gateway in masking.md; no direct call from an agent to 9Router is allowed.

## 1. 9Router protocol and upstream ambiguity

Verified protocol: locally hosted 9Router commonly exposes http://127.0.0.1:20128/v1; public docs describe OpenAI-compatible GET /v1/models and POST /v1/chat/completions. Model names use provider prefixes such as cc/ or glm/, but model ID is not proof of the ultimate provider. 9Router supports automatic provider/model fallback and may switch providers on quota or errors. **Default fallback behavior is not acceptable for restricted engagements unless a trusted routing policy can guarantee the final tier.**

References:
- https://docs.9router.com/
- https://9router.github.io/en/features/smart-routing/
- https://github.com/decolua/9router/blob/master/gitbook/content/en/integration/other-tools.md

## 2. Tier registry: runtime values, not brand assumptions

| SECRA tier | Provider placement | Permitted context | Effective fallback |
|---|---|---|---|
| local | Verified local inference server with denied internet egress | Static knowledge + locally classified structured observations; never raw credentials | Same isolated local tier only |
| trusted | Remote provider specifically approved under contract + allowed region/retention controls | Public skills + anonymized typed fields; secrets and identifying strings denied | Only explicitly approved same-tier routes; else error |
| foreign | ALL external models by default, including Claude/DeepSeek/GLM/Muse until assessed | Public skills + fixed whitelist metadata/asset aliases, never raw free text | None across provider identity; retry only to same approved route |
| unknown | Unmapped provider, opaque alias, combo model or unverified route | No external request | DENY |

All provider backends are treated as untrusted for secret handling, including the tier named trusted. Tier affects what pre-approved *non-sensitive* data may leave, not confidence in provider obedience.

The app must use an explicit registry keyed by immutable provider account/route identity. A user typing a model name cannot raise its tier. Provider/model IDs are discovered from /models and independently pinned to an allowlist. Do not assume "Muse" is available; discover its exact 9Router model ID if configured.

[ASUMSI] At first release all requests through general 9Router routes default to foreign, with zero automatic cross-provider fallback. Reason: 9Router's effective-upstream proof and enterprise egress constraints have not been integrated into SECRA.

## 3. Declared configuration schemas

    @dataclass(frozen=True)
    class ProviderRoute:
        route_id: str
        model_id: str
        provider_account_id: str
        expected_provider_id: str
        tier: Literal["local", "trusted", "foreign"]
        gateway_base_url: str
        allow_fallback: bool
        approved_fallback_route_ids: tuple[str, ...]
        max_input_tokens: int
        max_output_tokens: int
        timeout_seconds: int
        input_price_per_million: Decimal | None
        output_price_per_million: Decimal | None
        pricing_effective_at: datetime | None

    @dataclass(frozen=True)
    class EngagementBudget:
        engagement_id: UUID
        currency: Literal["USD"]
        max_total_cost: Decimal
        max_requests: int
        max_total_tokens: int
        max_context_tokens: int
        remaining_cost: Decimal
        remaining_tokens: int
        hard_stop: bool

    @dataclass(frozen=True)
    class RoutedRequest:
        engagement_id: UUID
        agent_id: str
        request_id: UUID
        route: ProviderRoute
        sanitized: SanitizedLLMRequest
        max_completion_tokens: int
        idempotency_key: str

    @dataclass(frozen=True)
    class RouteReceipt:
        request_id: UUID
        configured_route_id: str
        effective_provider_id: str | None
        model_id: str
        input_tokens: int
        output_tokens: int
        price_usd: Decimal | None
        policy_version: str
        fallback_performed: bool
        audit_event_id: int

New function contracts (not currently implemented):

    def discover_models(gateway: RouterTransport) -> list[ModelDescriptor]: ...
    def resolve_provider_tier(route: ProviderRoute, registry: ProviderRegistry) -> ProviderPrivacyPolicy: ...
    def select_model(task: AgentTask, budget: EngagementBudget, approved_routes: list[ProviderRoute]) -> ProviderRoute: ...
    def enforce_route_lock(route: ProviderRoute, gateway_config: GatewayConfig) -> None: ...
    def estimate_tokens(request: SanitizedLLMRequest, tokenizer: TokenCounter) -> int: ...
    def reserve_llm_budget(eid: UUID, request_id: UUID, estimated_input: int, estimated_output: int, route: ProviderRoute) -> BudgetReservation: ...
    def prepare_model_request(req: RoutedRequest, privacy: PrivacyGateway) -> WireRequest: ...
    def send_model_request(req: WireRequest, transport: RouterTransport) -> RouteReceipt: ...
    def verify_effective_route(receipt: RouteReceipt, reservation: BudgetReservation, policy: ProviderPrivacyPolicy) -> None: ...
    def settle_llm_budget(receipt: RouteReceipt, reservation: BudgetReservation) -> None: ...
    def on_route_failure(req: RoutedRequest, error: RouterError) -> Literal["retry_same", "fail_closed"]: ...

## 4. Cheap versus strong model policy

Roles describe engineering tradeoffs, not unverified provider performance rankings:

| Task | Default class | Token ceiling (starting configuration) | Inputs |
|---|---|---|---|
| Summarize allowed port/service metadata | cheap / small | 2,000 input, 400 output | Static skills + masked schema |
| Build candidate checklist from known standards | cheap / medium | 4,000 input, 800 output | Curated knowledge and allowed metadata only |
| Resolve contradiction between two verified observations | strong reasoning | 6,000 input, 1,200 output | Only a reviewed structured comparison |
| Independent finding review | strong reasoning | 8,000 input, 1,500 output | Local-only when evidence cannot be safely reduced |
| Sensitive evidence inspection | strictly local/offline | Locally configured | No foreign provider allowed |

Actual choices are operator-pinned model IDs from /models. Example class assignment (not verified benchmarks): Claude may be tagged strong, some GLM/DeepSeek deployments may be cheap or strong depending on version, Muse requires discovery and benchmarking. The gateway must not silently substitute a cheaper or foreign provider.

## 5. Budget and hard-stop semantics

Cost estimate:

    estimated_usd =
      (estimated_input_tokens * input_price_per_million
       + reserved_output_tokens * output_price_per_million) / 1_000_000

The following are initial SECRA policy defaults to be configured, **not model prices**:

- max_requests_per_engagement = 150
- max_total_tokens = 500_000
- max_completion_tokens_per_call = min(model_limit, task_limit)
- max_cost_usd_per_engagement = 10.00 (operator editable)
- warn_at = 70% and 90% of the budget
- hard_stop = 100%; never downgrade to a free/foreign provider automatically

Unknown pricing: deny paid remote calls unless operator grants a separate capped request quota with an explicit estimated ceiling. Subscription plans may not expose per-token cost; enforce request/time/token ceilings nonetheless.

A transaction reserves expected cost before sending, settles the bill after response, and reserves again for any retry. Counting only successful responses is insufficient. 9Router's own budget controls are supplemental: a route switch to a free tier may alter provider identity and must still be refused.

## 6. Route/fallback enforcement

- Before send: model and provider account must be in the signed local allowlist; the privacy gateway serializes under the **worst possible route tier**.
- Disable 9Router Auto Fallback/Smart Routing for restricted engagements. Pin a non-combo model and provider account; if a given 9Router installation cannot prove the destination, treat it as unknown and deny remote routing for sensitive material.
- Never rely solely on the model field or provider-returned metadata for confidentiality; these may be stale or unverified.
- Network egress from the 9Router process should be restricted to approved provider destinations where achievable. Requests without verifiable route identity may carry only fixed public, nonsensitive metadata.
- If the effective provider differs from planned: stop continuation, audit route violation, require explicit operator approval and *new* sanitized request with the new tier. The already-sent request cannot be recalled; pre-send enforcement is mandatory.
- Retry max 1 for transient network errors on the same locked route and same policy. HTTP 429/503 cannot silently create fallback to another provider.
- Any model tool_call is treated as untrusted JSON. Validate with the tool gateway, never execute a free-form command.
- Provider can see request size, timestamps, IP of the gateway and public skill text even if data is masked; this is metadata exposure, not zero-knowledge.

## 7. Acceptance tests

    def test_unknown_model_route_is_denied() -> None: ...
    def test_foreign_route_receives_metadata_only() -> None: ...
    def test_fallback_trusted_to_foreign_is_blocked() -> None: ...
    def test_budget_reservation_is_atomic_under_parallel_agents() -> None: ...
    def test_expensive_retry_cannot_exceed_remaining_budget() -> None: ...
    def test_model_alias_cannot_upgrade_tier() -> None: ...
    def test_effective_provider_mismatch_is_audited() -> None: ...
    def test_unpriced_route_requires_explicit_cap() -> None: ...

Gate: no outbound model request may originate outside the privacy gateway; 9Router fallback is disabled/locked or a strict common-denominator payload policy applies. Runtime denies unknown routes and exhausted budgets before network I/O.
