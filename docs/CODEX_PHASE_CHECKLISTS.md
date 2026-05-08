# Codex Phase Checklists

This is the Codex execution index for active Wiremind work. Product direction
stays in `docs/PLANNING.md` and the phase docs; this file converts that direction
into agent-ready, TDD-first task lists.

All code tasks are governed by `docs/TDD_RULES.md`. This run is docs-only; the
checkboxes below are for future implementation passes.

## Phase 0 - Contract Tightening

Owner profiles: Agent 3 API Contract and UI Integration, Agent 5 Documentation.

- [ ] Add failing backend/OpenAPI tests proving `docs/openapi.yaml` matches implemented job, stream, stats, flow, threat, config, and capture routes.
- [ ] Decide whether delivery/HITL state belongs in `Job.status` or a separate delivery model.
- [ ] Add a contract for agent/report execution if n8n must trigger LangGraph after parsing.
- [ ] Add report artifact discovery contract for `findings.json`, `report.md`, PDF, and IOC export.
- [ ] Add or explicitly defer `job_id` filtering for `/api/v1/threats`.
- [ ] Regenerate Go and UI client types after contract changes.

Exit criteria:

- [ ] OpenAPI, API tests, UI plan, and delivery docs describe the same contracts.
- [ ] The `analyst_rejected` status mismatch is resolved or documented as future-only.

## Phase 1 - API Security

Owner profile: Agent 1 Go Core Backend.

- [ ] Auth persistence and config: users, password hash verification, API key hashing, expiry, roles/scopes, env overrides.
- [ ] JWT token endpoint and middleware: public health/docs paths, protected `/api/v1/*`, valid/invalid/expired token cases.
- [ ] API keys and RBAC: `X-API-Key`, read/admin roles, 401 versus 403, key CRUD endpoints.
- [ ] Rate limiting and audit logging: per-IP/per-key token buckets, `429` with `Retry-After`, authenticated audit fields.

Required checks:

- [ ] `go test ./internal/api ./internal/store`
- [ ] `go test ./...`

Docs to update:

- [ ] `docs/openapi.yaml`
- [ ] `docs/API_PLAN.md`
- [ ] `docs/PHASE9.md`
- [ ] `docs/RUNBOOK.md`

## Phase 2 - Threat Intel Cache And Retry

Owner profile: Agent 1 Go Core Backend.

- [ ] Redis-backed threat intel cache interface with in-memory fallback.
- [ ] Cache hit, expiry, JSON marshal/unmarshal, Redis unavailable fallback, TTL config tests.
- [ ] Retry and backoff for VirusTotal and AbuseIPDB: 429, 5xx, permanent 4xx, `Retry-After`, max attempts, context cancellation.
- [ ] Cache successful external responses and preserve graceful degradation when keys are absent.

Required checks:

- [ ] `go test ./internal/enrichment ./config`
- [ ] `go test ./...`

Docs to update:

- [ ] `docs/ARCHITECTURE.md`
- [ ] `docs/PHASE8.md`
- [ ] `docs/PHASE9.md`
- [ ] `docs/RUNBOOK.md`

## Phase 3 - Worker Scaling And Reliability

Owner profiles: Agent 1 Go Core Backend, Agent 4 Runtime and Observability.

- [ ] Durable queue semantics: claim, ack, fail, retry/dead-letter, no duplicate completion.
- [ ] Testable worker processor package: success, source-open failure, parse/enrich/write failure, status transitions, counts, graceful shutdown.
- [ ] Worker heartbeat and health aggregation: Redis status, active worker count, degraded state on TTL expiry.
- [ ] Scale documentation for multiple worker replicas.
- [ ] Observability details are tracked in `docs/OBSERVABILITY_ROADMAP.md` phases O1, O2, and O4.

Required checks:

- [ ] `go test ./internal/queue ./internal/store`
- [ ] `go test ./internal/api ./internal/queue`
- [ ] `go test ./...`

Docs to update:

- [ ] `docs/ARCHITECTURE.md`
- [ ] `docs/PHASE8.md`
- [ ] `docs/PHASE9.md`
- [ ] `docs/RUNBOOK.md`

## Phase 4 - Resource Limits And Pruning

Owner profiles: Agent 1 Go Core Backend, Agent 4 Runtime and Observability.

- [ ] Runtime limits: `max_input_bytes`, `job_timeout_seconds`, `allowed_input_roots`, output/temp directory limits.
- [ ] API validation prevents oversized or disallowed jobs before enqueue.
- [ ] Automated pruning for old jobs/findings, Redis history, dry-run counts, retention and row limits.
- [ ] Docker resource limits and runbook guidance.

Required checks:

- [ ] `go test ./config ./internal/api`
- [ ] `go test ./internal/store ./internal/queue`
- [ ] `go test ./...`

Docs to update:

- [ ] `docs/openapi.yaml`
- [ ] `docs/ARCHITECTURE.md`
- [ ] `docs/PHASE9.md`
- [ ] `docs/RUNBOOK.md`

## Phase 5 - Extended Input Sources

Owner profile: Agent 1 Go Core Backend.

- [ ] Expand input contract without adding empty stubs.
- [ ] Decide whether Zeek, Suricata, and VPC logs need a normalized-event ingestion path separate from `PacketSource`.
- [ ] SSH remote source with fake command tests and process cancellation.
- [ ] S3 source with fake client tests, range reads, and cancellation.
- [ ] Zeek, Suricata, and VPC fixture mapping into existing flow/event shapes.
- [ ] Kafka stream source only after durable worker queues are complete.

Required checks:

- [ ] `go test ./internal/input ./internal/parser`
- [ ] `go test ./internal/enrichment`
- [ ] `go test ./...`

Docs to update:

- [ ] `README.md`
- [ ] `docs/ARCHITECTURE.md`
- [ ] `docs/PHASE1.md`
- [ ] `docs/PHASE9.md`
- [ ] `docs/RUNBOOK.md`

## Phase 6 - UI And Delivery Contract

Owner profiles: Agent 3 API Contract and UI Integration, Agent 4 Runtime and Observability.

- [ ] U3 jobs list, submit drawer, job detail, SSE hook, failed-state display, and View Results link.
- [ ] U4 dashboard stats, recent jobs, top threats, protocol distribution, empty/active/failed fixtures.
- [ ] U5 graph transform, node coloring, side panel, malicious/beacon/job filters, large graph cap.
- [ ] U6 IOC CRUD, pipeline editor, capture start/stop, validation and confirmation flows.
- [ ] Docker UI smoke automation for load, `/api` proxy, deep links, no CORS failures, deterministic data.
- [ ] Delivery contract for report artifacts, agent/report run trigger, and HITL state.

Required checks:

- [ ] `go test ./internal/api ./internal/store` for backend contract changes.
- [ ] UI tests/build in the sibling `wiremind-ui` repo for UI implementation tasks.
- [ ] Docker smoke from `docs/UI_INTEGRATION_TESTING.md` when compose changes.

Docs to update:

- [ ] `docs/openapi.yaml`
- [ ] `docs/UI_PLAN_WS.md`
- [ ] `docs/UI_INTEGRATION_TESTING.md`
- [ ] `docs/PHASE9.md`
- [ ] `docs/RUNBOOK.md`

## Phase 7 - n8n Delivery Automation

Owner profiles: Agent 4 Runtime and Observability, Agent 3 API Contract and UI Integration.

- [ ] Persistent n8n service, credentials/volumes, and documented startup.
- [ ] Webhook trigger submits `POST /api/v1/jobs`.
- [ ] Poll or stream job completion.
- [ ] Trigger agent/report generation through explicit API or documented command path.
- [ ] Slack HITL message with Approve/Reject and report link.
- [ ] API state records approval/rejection instead of keeping decision only in n8n.
- [ ] Email, Jira, S3 archive, and Confluence delivery paths.
- [ ] Dry-run or mocked-credential workflow tests before real integrations.
- [ ] Delivery observability details are tracked in `docs/OBSERVABILITY_ROADMAP.md` phase O7.

Required checks:

- [ ] Workflow dry-run or smoke tests defined in the task.
- [ ] `go test ./internal/api ./internal/store` for any contract support.

Docs to update:

- [ ] `docs/PHASE9.md`
- [ ] `docs/RUNBOOK.md`
- [ ] `docs/API_PLAN.md`

## Phase 8 - Python AI Advancement

Owner profile: Agent 2 Python AI Agents.

- [ ] Normalized Pydantic finding/verdict contract.
- [ ] Deterministic ReAct loops with max-iteration guards and trace persistence.
- [ ] Tool registry, typed arguments, denied/unknown tools, and unsupported deep-dive tools.
- [ ] RAG evaluation harness with local deterministic metrics.
- [ ] LLM cost controls and budget-exhausted metadata; detailed work is split in Phase 8B and `docs/AI_COSTING.md`.
- [ ] Analyst feedback, false positive suppression, and confidence calibration.
- [ ] Multi-LLM fallback, self-critique, and ATT&CK Navigator export.
- [ ] AI observability details are tracked in `docs/OBSERVABILITY_ROADMAP.md` phase O5.

Required checks:

- [ ] `cd python && python -m pytest tests/ -v`

Docs to update:

- [ ] `docs/PHASE3.md`
- [ ] `docs/AI_ROADMAP.md`
- [ ] `docs/ARCHITECTURE.md`
- [ ] `docs/PHASE9.md`
- [ ] `docs/RUNBOOK.md`

## Phase 8A - Observability Hardening

Owner profiles: Agent 4 Runtime and Observability, Agent 1 Go Core Backend, Agent 2 Python AI Agents, Agent 3 API Contract and UI Integration.

- [ ] O0 Contract and baseline: reconcile `/health`, `/metrics`, jobs, SSE, OpenAPI, runbook, and phase docs.
- [ ] O1 Runtime health: Postgres, Redis, queue depth, active/stale workers, disk, degraded reasons.
- [ ] O2 Metrics/dashboards/alerts/SLOs: job, parser, queue, dependency, SSE, auth, delivery, dashboards, alert rules, SLOs.
- [ ] O3 Logs/Sentry/correlation: request IDs, trace IDs, job IDs, JSON/container logs, Loki shipping, Sentry redaction.
- [ ] O4 Distributed tracing: API, Redis, worker, parser, enrichment, Postgres, Python agents, delivery.
- [ ] O5 AI observability: finding envelope, agent trace recorder, tool-call telemetry, evals, RAG metrics, cost, fallback, calibration.
- [ ] O6 Profiling/resource visibility: pprof gate, Pyroscope plan, CPU/memory, LLM token budget panels.
- [ ] O7 Delivery/workflow observability: workflow run IDs, delivery attempts, HITL state, artifact paths, delivery metrics.
- [ ] O8 Smoke/operations: exact health/metrics/logs/tracing/dashboard/failure-drill commands.

Required checks:

- [ ] Follow the per-phase checks in `docs/OBSERVABILITY_ROADMAP.md`.
- [ ] `go test ./internal/api ./internal/queue ./config` for Go runtime observability changes.
- [ ] `cd python && python -m pytest tests/ -v` for Python AI observability changes.
- [ ] `docker compose config` and documented smoke checks for compose/dashboard/provisioning changes.

Docs to update:

- [ ] `docs/OBSERVABILITY_ROADMAP.md`
- [ ] `docs/RUNBOOK.md`
- [ ] `docs/PHASE8.md`
- [ ] `docs/PHASE9.md`
- [ ] `docs/ARCHITECTURE.md`
- [ ] `docs/openapi.yaml` when observability response contracts change.

## Phase 8B - AI Cost Governance

Owner profiles: Agent 2 Python AI Agents, Agent 4 Runtime and Observability, Agent 5 Documentation and Planning.

Canonical plan: `docs/AI_COSTING.md`.

- [ ] Cost contract and policy: define run/job/agent/provider/model/purpose fields, pricing version, budget scopes, redaction rules, and fail-closed behavior.
- [ ] Provider-neutral pricing catalog with model, currency, input/output token rates, optional cache token rates, provider fixed call cost, unit size, and effective date.
- [ ] Budget config: max tokens per call, per agent, and per run; max estimated cost per call/run/job; default fail-closed behavior for unknown pricing.
- [ ] Preflight token and cost estimation before model calls, including top-N evidence compaction and deterministic downgrade paths.
- [ ] Pre-call budget guard that blocks model calls when remaining budget is insufficient and proves no fake provider call occurs.
- [ ] Actual usage accounting from fake provider responses: prompt tokens, completion tokens, cached tokens, stop reason, retry count, fallback reason, estimate reconciliation, and run totals.
- [ ] Structured `budget_exhausted` metadata preserved in agent traces, findings, reports, logs, and future API/UI contracts.
- [ ] Cost telemetry: provider, model, purpose, prompt tokens, completion tokens, estimated cost, actual cost, budget remaining, skipped-call reason, fallback reason, and pricing version.
- [ ] Provider fallback policy that considers availability, budget ceiling, model capability, explicit fallback reason, and estimated cost delta.
- [ ] Report, runbook, dashboard, and delivery guidance for budget exhaustion, skipped AI work, and provider fallback.
- [ ] Cost optimization backlog: prompt compaction, repeated-context caching, deterministic-first routing, optional critique budgeting, local LLM routing, and cost-per-confirmed-finding metrics.

Required checks:

- [ ] `cd python && python -m pytest tests/test_cost_controls.py tests/test_orchestrator.py -v`
- [ ] `cd python && python -m pytest tests/test_reporting.py -v` when reports include cost metadata.
- [ ] `cd python && python -m pytest tests/ -v`
- [ ] Metrics/dashboard smoke checks from `docs/OBSERVABILITY_ROADMAP.md` when telemetry is added.

Docs to update:

- [ ] `docs/AI_COSTING.md`
- [ ] `docs/PHASE3.md`
- [ ] `docs/PHASE8.md`
- [ ] `docs/PHASE9.md`
- [ ] `docs/AI_ROADMAP.md`
- [ ] `docs/OBSERVABILITY_ROADMAP.md`
- [ ] `docs/RUNBOOK.md`
- [ ] `docs/ARCHITECTURE.md`
- [ ] `docs/openapi.yaml` only when cost state is exposed through API/UI contracts.

## Phase 9 - Documentation Consistency

Owner profile: Agent 5 Documentation and Planning.

- [ ] Keep `README.md`, `docs/PLANNING.md`, `docs/PHASE8.md`, and `docs/PHASE9.md` phase statuses aligned.
- [ ] Keep API endpoint examples aligned with `/api/v1` and `docs/openapi.yaml`.
- [ ] Keep `docs/UI_PLAN_WS.md` as the active UI plan link.
- [ ] Treat `docs/COMMIT_HISTORY.md` as narrative history, not current status.
- [ ] Avoid marking UI U4/U5 complete until implemented in `wiremind-ui`.

Required checks:

- [ ] `rg -n "UI_PLAN.md|/flows\\b|Four specialist|lead counts|brainstorm.txt" README.md docs/*.md`
- [ ] `git diff --check`
