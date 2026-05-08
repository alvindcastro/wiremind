# Observability Roadmap

This is the canonical observability track for Wiremind. It turns the Phase 8
observability baseline into future TDD-first hardening tasks across the Go API,
worker, queue, Python agents, delivery automation, dashboards, and operations.

All future code tasks in this file must follow [TDD_RULES.md](TDD_RULES.md).
This document is planning only; it does not imply code has been implemented.

## Current Baseline

- [x] `/metrics` exists for basic API request count and duration.
- [x] `/health` exists.
- [x] Structured logging is planned/partially wired across Go and Python.
- [x] Sentry is initialized for Go/Python error reporting.
- [x] Docker Compose includes Prometheus, Grafana, Jaeger, Loki, and Promtail.
- [x] SSE exists for job status streaming.

Known gaps to close before calling observability production-grade:

- [ ] `/health` contract must match docs: Postgres, Redis, queue depth, active workers, stale workers, disk, status, and degraded reasons.
- [ ] SSE route and job progress events need explicit metrics, typed progress semantics, and immediate first event behavior.
- [ ] Redis queue needs ack/retry/dead-letter telemetry before worker scaling can be trusted.
- [ ] Worker failures need durable failed-state reporting and structured transition logs.
- [ ] Promtail/log paths need to match actual container logging behavior.
- [ ] Grafana dashboards, datasource provisioning, and Prometheus alert rules need source-controlled definitions.
- [ ] OpenTelemetry spans need verifiable API -> queue -> worker -> parser -> enrichment -> persistence -> agent flow.
- [ ] Python AI agents need trace, tool-call, eval, token/cost, fallback, confidence, and Sentry context telemetry; cost policy details live in [AI_COSTING.md](AI_COSTING.md).
- [ ] n8n delivery needs workflow run IDs, delivery attempts, HITL state, and artifact observability.

## O0 - Contract And Baseline

Goal: make the documented observability contract match runtime behavior before adding more telemetry.

- [ ] Verify `docs/openapi.yaml`, API handlers, runbook examples, and phase docs agree on `/health`, `/metrics`, `/api/v1/jobs`, and `/api/v1/jobs/{id}/stream`.
- [ ] Decide whether SSE emits raw `Job` snapshots or typed progress events: `queued`, `claimed`, `parsing`, `enriching`, `writing`, `persisted`, `completed`, `failed`.
- [ ] Define `/health` component schema: `postgres`, `redis`, `queue_depth`, `active_workers`, `stale_workers`, `disk`, and aggregate `status`.
- [ ] Define cardinality rules: no `job_id` Prometheus labels; use logs, traces, and SSE for per-job IDs.
- [ ] Define observability ownership: metrics names, dashboard ownership, runbook checks, alert response.

TDD gate:

- [ ] Add failing API/OpenAPI contract tests before changing handler behavior.
- [ ] Use focused checks: `go test ./internal/api ./internal/store`.
- [ ] Update `docs/openapi.yaml`, `docs/API_PLAN.md`, `docs/PHASE8.md`, and `docs/RUNBOOK.md` after tests pass.

Future prompt:

```text
Use the Standard TDD Preamble. Reconcile Wiremind observability contracts before adding new behavior. First add failing API/OpenAPI tests proving /health, /metrics, /api/v1/jobs, and /api/v1/jobs/{id}/stream match docs and response schemas. Define whether SSE emits raw Job snapshots or typed progress events, and ensure Prometheus metrics avoid job_id labels. Then make the smallest spec/docs/runtime changes needed. Run go test ./internal/api ./internal/store and update docs/openapi.yaml, docs/API_PLAN.md, docs/PHASE8.md, docs/RUNBOOK.md, and docs/OBSERVABILITY_ROADMAP.md.
```

## O1 - Runtime Health And Readiness

Goal: expose actionable liveness/readiness state for the API, database, Redis, workers, queue, and disk.

- [ ] Split liveness/readiness semantics or add structured health fields under one `/health` response.
- [ ] Add Postgres ping latency and error details.
- [ ] Add Redis ping latency and error details.
- [ ] Add queue depth, in-flight count, retry count, dead-letter count, and oldest queued job age.
- [ ] Add worker heartbeat count, stale worker detection, and worker metadata.
- [ ] Add disk free-space check for input/output/temp locations.
- [ ] Preserve public access for `/health`, `/metrics`, `/docs`, and `/openapi.yaml` after auth lands.

TDD gate:

- [ ] Failing tests for DB down, Redis down, zero workers, stale worker TTL, low disk, and degraded aggregation.
- [ ] Use focused checks: `go test ./internal/api ./internal/queue ./config`.

Future prompt:

```text
Use the Standard TDD Preamble. Implement Go/runtime health aggregation. First add failing internal/api and internal/queue tests proving /health reports postgres, redis, queue_depth, in_flight_jobs, active_worker_count, stale_worker_count, disk_free_bytes, component errors, and aggregate status up|degraded|down. Then implement minimal health providers and worker heartbeat registration. Run go test ./internal/api ./internal/queue ./config and go test ./... . Update docs/openapi.yaml, docs/RUNBOOK.md, docs/ARCHITECTURE.md, docs/PHASE8.md, docs/PHASE9.md, and docs/OBSERVABILITY_ROADMAP.md.
```

## O2 - Metrics, Dashboards, Alerts, And SLOs

Goal: give operators measurable service, job, parser, queue, dependency, and delivery signals.

- [ ] Add job lifecycle counters: submitted, claimed, started, completed, failed, retried, dead-lettered.
- [ ] Add parser/enrichment metrics: packets, bytes, flows, protocol event counts, parse duration, enrich duration.
- [ ] Add queue metrics: pending depth, in-flight count, retry count, dead-letter count, worker count, oldest job age.
- [ ] Add dependency metrics: DB latency, Redis latency, threat-intel latency, threat-intel error count, cache hit/miss.
- [ ] Add SSE metrics: active streams, stream duration, emitted events, disconnects, errors.
- [ ] Add auth/rate metrics after auth exists: token requests, auth failures, RBAC denials, allowed/limited requests.
- [ ] Add delivery metrics: attempts, failures, latency, pending HITL, approvals, rejections.
- [ ] Add Grafana provisioning for Prometheus and Loki datasources.
- [ ] Add starter dashboards for API, jobs/workers, parser/enrichment, dependencies, AI agents, delivery, and logs.
- [ ] Add Prometheus alert rules for API down, DB/Redis degraded, no active workers, queue backlog age, dead-letter growth, SSE failures, auth failure spikes, rate-limit spikes, delivery failures, and high p95 latency.
- [ ] Define initial SLOs: API availability, job completion success, queue latency, parse throughput, agent/report latency, and delivery completion.

TDD gate:

- [ ] Use `prometheus/testutil` for counter/gauge/histogram assertions before implementation.
- [ ] Validate dashboard/provisioning/alert files with smoke or config checks before compose rollout.

Future prompts:

```text
Use the Standard TDD Preamble. Expand Prometheus metrics for Go runtime observability. First add failing prometheus/testutil coverage for job submitted/claimed/started/completed/failed/retried/dead-lettered counters, parse/enrich duration histograms, packet/flow/protocol counters, queue depth gauges, worker count gauges, dependency latency metrics, cache hit/miss metrics, and SSE stream metrics. Then implement scoped collectors without duplicate global registration failures in tests. Run go test ./internal/api ./internal/queue ./internal/worker ./internal/enrichment ./config and go test ./... . Update deploy/prometheus.yml, docs/RUNBOOK.md, and docs/OBSERVABILITY_ROADMAP.md.
```

```text
Use the Standard TDD Preamble. Add Grafana provisioning, Prometheus alert rules, and SLO documentation. First add config/render or smoke tests proving datasource, dashboard, and alert files are valid. Then add dashboards for API, jobs/workers, parser/enrichment, dependencies, AI agents, delivery, and logs. Define SLOs for API availability, job success, queue latency, parse throughput, agent/report latency, and delivery completion. Run docker compose config plus Prometheus/Grafana smoke checks. Update docs/RUNBOOK.md, docs/PHASE8.md, docs/PHASE9.md, and docs/OBSERVABILITY_ROADMAP.md.
```

## O3 - Logs, Correlation, Audit, And Error Reporting

Goal: make logs and error events useful for incident response without leaking sensitive packet content.

- [ ] Standardize container Go logs as JSON or document the actual stdout format.
- [ ] Standardize Python logs through `structlog` with compatible fields.
- [ ] Add request IDs and propagate them through job submission, queue payloads, workers, and agent runs where practical.
- [ ] Include `request_id`, `trace_id`, `job_id`, `worker_id`, `run_id`, route, status, latency, stage, packet/flow counts, and error class.
- [ ] Redact full PCAP paths, payload content, secrets, API keys, and raw evidence where needed.
- [ ] Fix Promtail config/compose so Loki receives actual container stdout or actual app log files.
- [ ] Add auth audit logs after auth exists: subject, auth type, role, method, endpoint, status, latency, correlation ID.
- [ ] Add Sentry panic/recovery middleware for API panics.
- [ ] Capture worker job failures with job context and stable fingerprints.
- [ ] Attach AI agent context to Sentry events: `run_id`, `job_id`, `agent`, `trace_id`, provider, budget state, tool name, redacted evidence count.

TDD gate:

- [ ] Log-capture tests prove required fields on success and failure paths.
- [ ] Sentry tests use fake transport; no real Sentry calls in unit tests.

Future prompts:

```text
Use the Standard TDD Preamble. Fix structured logging and Loki/Promtail wiring. First add failing log-capture tests proving API requests and worker jobs emit logs with request_id, trace_id, job_id, worker_id, method, route, status, latency, stage, packet_count, flow_count, and error_class. Then implement request ID middleware and worker log context. Fix compose/promtail so Loki receives real logs. Run targeted Go tests, docker compose config, and a Loki labels smoke check. Update docs/RUNBOOK.md, docs/PHASE8.md, and docs/OBSERVABILITY_ROADMAP.md.
```

```text
Use the Standard TDD Preamble. Add API/worker Sentry observability. First add failing tests with a fake Sentry transport proving API panics are captured with request_id and route, worker job failures are captured with job_id/stage/error_class, and sensitive paths or secrets are redacted. Then implement recovery/capture middleware and worker failure capture. Run go test ./internal/api ./internal/worker ./config and update docs/RUNBOOK.md and docs/OBSERVABILITY_ROADMAP.md.
```

## O4 - Distributed Tracing

Goal: trace a single investigation across API, Redis, worker, parser, enrichment, Postgres, Python agents, report generation, and delivery.

- [ ] Add OpenTelemetry config: service name, endpoint, sampling, enabled flag.
- [ ] Trace `POST /api/v1/jobs`.
- [ ] Propagate trace/job context through queue payload or metadata.
- [ ] Trace Redis publish/claim/ack/fail.
- [ ] Trace worker consume, parser, enrichment, output write, and Postgres persist.
- [ ] Trace threat-intel lookups and mark external-provider errors.
- [ ] Trace SSE subscription lifecycle.
- [ ] Trace Python orchestrator, specialist agents, tool calls, RAG lookup, report generation, and provider fallback.
- [ ] Trace n8n delivery handoff with workflow run ID when available.
- [ ] Keep Jaeger compose ports and runbook smoke checks aligned.

TDD gate:

- [ ] Use an in-memory OpenTelemetry exporter to assert span names, attributes, parent/child linkage, and error status before OTLP rollout.

Future prompts:

```text
Use the Standard TDD Preamble. Add OpenTelemetry tracing for the Go API and worker. First add tests with an in-memory exporter proving spans exist for submit_job, redis_publish, worker_consume, parse, enrich, postgres_persist, output_write, and job_complete, with job_id and error status attributes. Then wire configurable OTLP export to Jaeger. Run go test ./internal/api ./internal/queue ./internal/worker ./config and a Jaeger/OTLP compose smoke. Update docs/ARCHITECTURE.md, docs/RUNBOOK.md, and docs/OBSERVABILITY_ROADMAP.md.
```

```text
Use the Standard TDD Preamble. Add Python agent tracing without live LLM calls. First add failing pytest coverage with an in-memory exporter proving spans for orchestrator_run, specialist_agent, tool_call, rag_lookup, report_generation, provider_fallback, and agent_error with run_id, job_id, agent, finding_count, and error attributes. Then implement minimal trace hooks. Run cd python && python -m pytest tests/ -v and update docs/PHASE3.md, docs/ARCHITECTURE.md, and docs/OBSERVABILITY_ROADMAP.md.
```

## O5 - AI Observability And Quality

Goal: make AI findings explainable, measurable, and cost-visible before more LLM autonomy is added.

AI cost governance is detailed in [AI_COSTING.md](AI_COSTING.md). O5 owns the
observable signals; Phase 8B in [CODEX_PHASE_CHECKLISTS.md](CODEX_PHASE_CHECKLISTS.md)
owns the execution checklist.

- [ ] Clean Python tests so specialist and E2E fixtures use nested Go API wrappers.
- [ ] Add normalized finding/verdict envelope with `trace_id`, `run_id`, `agent`, `finding_id`, severity, raw confidence, optional calibrated confidence, evidence refs, MITRE refs, tool trace summary, and critique status.
- [ ] Add deterministic agent trace recorder events: `reason`, `tool_call`, `observation`, `decision`, `finding_emitted`, `error`, `budget_exhausted`.
- [ ] Add tool-call observability: allow/deny decisions, argument validation failures, latency, result size, API error class, and nested-shape warnings.
- [ ] Add local finding-quality evals: precision/recall by finding type, severity correctness, evidence completeness, MITRE mapping correctness, duplicate finding rate, false-positive suppression impact.
- [ ] Add RAG evals: recall@k, MRR, empty-store behavior, stale/irrelevant context rate.
- [ ] Add cost/token telemetry: selected provider, model, purpose, prompt tokens, completion tokens, cached tokens, estimated cost, actual cost, pricing version, budget remaining, skipped-call metadata.
- [ ] Add budget state events: `budget_available`, `reserved`, `reconciled`, `budget_exhausted`, `unknown_pricing`, and `incomplete_usage`.
- [ ] Add cost metrics without high-cardinality labels: planned calls, executed calls, skipped calls, token usage, estimated spend, actual spend, and fallback spend delta by provider/model tier/agent class.
- [ ] Add provider fallback visibility: fallback reason, retry count, terminal provider, quality/cost change.
- [ ] Add confidence calibration metrics: calibration method/version, labelled history count, Brier score, expected calibration error.
- [ ] Add AI Sentry context: run, job, agent, trace, provider, budget state, tool name, redacted evidence counts.

TDD gate:

- [ ] Add failing pytest coverage before each behavior.
- [ ] Use fake clients/providers; no live LLM, Sentry, ChromaDB cloud, or network calls.
- [ ] Run `cd python && python -m pytest tests/ -v` before handoff unless blocked.

Future prompts:

```text
Use the Standard TDD Preamble. Add AI observability contract coverage. First update or add failing pytest coverage proving every finding carries trace_id, run_id, finding_id, raw_confidence, optional calibrated_confidence, evidence refs, MITRE refs, tool_trace summary, and critique status while preserving nested Go API fixtures. Then implement the minimal Pydantic contract and adapt specialists, correlation, and reporting. Run targeted Python tests, then python -m pytest tests/ -v. Update docs/ARCHITECTURE.md, docs/PHASE3.md, and docs/OBSERVABILITY_ROADMAP.md only after tests pass.
```

```text
Use the Standard TDD Preamble. Add a deterministic Python agent trace recorder. First add failing tests proving reason, tool_call, observation, decision, finding_emitted, error, and budget_exhausted events are recorded with monotonic sequence numbers and redacted payload summaries. Use fake specialists/tools. Then wire the recorder through orchestrator and specialist runs without live LLM calls. Update docs/PHASE8.md, docs/RUNBOOK.md, and docs/OBSERVABILITY_ROADMAP.md.
```

```text
Use the Standard TDD Preamble. Add AI cost telemetry without live provider calls. First add failing pytest coverage proving provider, model, purpose, prompt tokens, completion tokens, cached tokens, estimated cost, actual cost, pricing_version, budget_limit, budget_remaining, skipped_call_reason, and fallback_reason are recorded without raw prompt text, raw packet payloads, secrets, or full PCAP paths. Add metrics tests only with fake collectors or prometheus/testutil, and keep Prometheus labels low-cardinality. Then implement the smallest telemetry plumbing through the Python agent runtime and trace recorder. Run cd python && python -m pytest tests/test_cost_controls.py tests/test_orchestrator.py -v and cd python && python -m pytest tests/ -v. Update docs/AI_COSTING.md, docs/OBSERVABILITY_ROADMAP.md, docs/RUNBOOK.md, and docs/ARCHITECTURE.md only after tests pass.
```

```text
Use the Standard TDD Preamble. Add local AI quality, RAG, cost, provider, and confidence observability. First add failing pytest cases for MITRE/playbook evals, recall@k, MRR, token/cost accounting, provider fallback reason, raw-vs-calibrated confidence preservation, Brier score, and expected calibration error. Use fake providers only. Then implement deterministic helpers and metadata. Update docs/AI_ROADMAP.md, docs/PHASE3.md, docs/PHASE9.md, and docs/OBSERVABILITY_ROADMAP.md.
```

## O6 - Profiling And Resource Visibility

Goal: make CPU, memory, parse cost, worker cost, and Python agent cost visible without exposing unsafe profiling in production.

- [ ] Add configurable Go pprof endpoint, disabled by default or localhost/admin-gated.
- [ ] Add pprof route tests proving disabled-by-default behavior and access gates.
- [ ] Add Pyroscope service/config only after pprof basics are testable.
- [ ] Profile `forensics serve`, `forensics worker`, and Python agents separately.
- [ ] Add container CPU/memory dashboard panels.
- [ ] Add LLM token budget and spend panels after cost telemetry exists.
- [ ] Document safe profiling in Docker and production-like runs.

TDD gate:

- [ ] Config tests for profiling enabled/disabled behavior.
- [ ] Route tests for pprof gate.
- [ ] Compose smoke for Pyroscope only after service is added.

Future prompt:

```text
Use the Standard TDD Preamble. Add profiling gates and resource visibility. First add failing config and httptest coverage proving pprof is disabled by default, only enabled by explicit config, and protected by localhost or admin access. Then add pprof wiring and defer Pyroscope service addition until pprof tests pass. Add dashboard/runbook notes for CPU, memory, parse duration, worker duration, and LLM token spend. Run go test ./internal/api ./config and docker compose config. Update docs/RUNBOOK.md, docs/PHASE8.md, docs/PHASE9.md, and docs/OBSERVABILITY_ROADMAP.md.
```

## O7 - Delivery And Workflow Observability

Goal: make n8n, HITL, and report delivery measurable and diagnosable.

- [ ] Define delivery state separately from parse job state, or explicitly extend `Job.status`.
- [ ] Resolve the planned `analyst_rejected` mismatch before implementation.
- [ ] Track delivery attempts for Slack, email, Jira, S3, and Confluence.
- [ ] Store delivery status, retry count, last error, artifact paths, and workflow run ID.
- [ ] Add n8n workflow run IDs to logs and audit records.
- [ ] Add metrics for delivery attempts, failures, latency, pending HITL, approvals, and rejections.
- [ ] Provide dry-run workflow tests before real credentials.
- [ ] Add runbook failure drills for missing artifacts, rejected HITL, failed job, and connector failure.

TDD gate:

- [ ] API/store tests for delivery state and HITL recording.
- [ ] Mocked workflow smoke for approve, reject, failed job, missing artifact, and retry paths.

Future prompt:

```text
Use the Standard TDD Preamble. Design the minimal delivery/HITL observability contract n8n needs. Start with failing API/store tests for delivery attempts, artifact discovery, approval/rejection state, workflow run IDs, retry counts, last error, and delivery metrics. Resolve the analyst_rejected status mismatch in docs and OpenAPI. Then implement the smallest contract support. Run go test ./internal/api ./internal/store and update docs/openapi.yaml, docs/PHASE9.md, docs/API_PLAN.md, docs/RUNBOOK.md, and docs/OBSERVABILITY_ROADMAP.md.
```

## O8 - Smoke, Operations, And Failure Drills

Goal: give operators exact checks for every observability layer.

- [ ] Add runbook smoke commands for health, metrics, Prometheus targets, Grafana datasource, Jaeger traces, Loki labels/log queries, Sentry test capture, and Pyroscope when added.
- [ ] Add failure drills: DB down, Redis down, no workers, queue backlog, dead-letter growth, SSE disconnects, auth failure spike, rate-limit spike, delivery failure, provider budget exhaustion.
- [ ] Add expected dashboard panels and alert names.
- [ ] Keep commands compatible with local Docker Compose.
- [ ] Document known local test blockers, including missing `pcap.h` when libpcap headers are absent.

TDD/smoke gate:

- [ ] Docs-only additions are allowed without code tests.
- [ ] Scripts or smoke automation must fail first against a missing condition before implementation.

Future prompt:

```text
This is a docs and smoke-focused observability task. Do not change production code unless a failing smoke check requires it. Define Prometheus alert rules and runbook diagnosis commands for API error rate, queue backlog age, no active workers, dead-letter growth, SSE failures, auth failure spikes, rate-limit spikes, provider budget exhaustion, and delivery failures. Add Grafana panel expectations and exact curl/docker commands. Run docker compose config and document any blocked smoke checks.
```
