# open.md — remaining engineering decisions

1. **DECISION REQUIRED — graph encryption.** Select OS full-disk encryption versus application-managed encryption, including key rotation and backup/retention procedures.
2. **DECISION REQUIRED — approval hook.** Adopt a signed, per-intent approval record binding operator, scope, action class, duration and audit trail before allowing mutating resolver operations.
3. **DECISION REQUIRED — upstream update policy.** Assign review ownership for pin refreshes, compatible schema migrations, regression validation and rollback.
4. **DECISION REQUIRED — durable worker state.** Introduce a queue/checkpoint strategy that explicitly reconciles incomplete intents after process termination rather than silently claiming completion.
5. **DECISION REQUIRED — model egress boundary.** Fix provider allowlists, local-only mode, outbound transport controls, response retention and telemetry filtering before any new data fields are allowed to reach 9Router.

[ASUMSI] The first integrated release is a single-operator local deployment. Reason: multi-user RBAC and organization-specific deployment constraints have not been supplied.
