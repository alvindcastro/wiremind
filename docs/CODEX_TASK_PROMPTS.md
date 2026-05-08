# Codex Task Prompts

Use these prompts to start future Codex agents on bounded tasks. Every prompt
that touches code includes the strict TDD rule from `docs/TDD_RULES.md`.

## Standard TDD Preamble

```text
Read AGENTS.md, docs/TDD_RULES.md, and the relevant phase docs before editing.
This is a strict TDD task: do not change production code until you have added or
updated a failing test and run the narrow target to prove the failure. Then make
the smallest implementation change, rerun focused tests, run broader tests when
needed, and update docs only after behavior is tested. Do not make unrelated
refactors.
```

## Read-Only Brainstorm Prompt

```text
Run a read-only brainstorm for wiremind. Do not edit files. Inspect README.md,
AGENTS.md, docs/CODEX_AGENTS.md, docs/TDD_RULES.md, docs/CODEX_PHASE_CHECKLISTS.md,
and the relevant phase docs. Return a concise list of risks, task ordering,
failing-test ideas, likely files, commands, and docs to update.
```

## Docs-Only Planning Prompt

```text
This is a docs-only task. Do not change Go, Python, Docker, OpenAPI, or scripts.
Update the requested Markdown so it contains phase checklists, tickable tasks,
task prompts, and TDD gates. Keep links relative and verify with rg for stale
references. Run git diff --check and report any warnings.
```

## Go Backend Prompts

### API Security 1.1 - Auth Persistence And Config

```text
Use the Standard TDD Preamble. Read docs/PHASE9.md, internal/store/postgres.go,
internal/models, and config/config.go. First add failing tests for User and APIKey
persistence, password hash verification, API key hash lookup, expiry, role/scope
fields, and auth config env overrides. Then implement models, migrations, store
methods, and config defaults. Run go test ./internal/store ./config and go test
./... . Update docs/ARCHITECTURE.md, docs/PHASE9.md, and docs/RUNBOOK.md.
```

### API Security 1.2 - JWT Token Endpoint

```text
Use the Standard TDD Preamble. First add failing httptest coverage in internal/api
proving /api/v1/* rejects missing, invalid, and expired Bearer tokens while
/health, /metrics, /openapi.yaml, and /docs stay public. Add POST
/api/v1/auth/token tests for valid and invalid credentials. Then implement the
middleware and handler. Run go test ./internal/api ./internal/store and go test
./... . Update docs/openapi.yaml, docs/API_PLAN.md, and docs/PHASE9.md.
```

### API Security 1.3 - API Keys And RBAC

```text
Use the Standard TDD Preamble. First write failing API tests proving X-API-Key
works for machine clients, read-role keys can only use GET, admin role can use
config/capture mutation endpoints, and 401 versus 403 responses are correct.
Then implement API key auth, role checks, and key CRUD endpoints under
/api/v1/config/apikeys. Run go test ./internal/api ./internal/store. Update
docs/openapi.yaml, docs/RUNBOOK.md, and docs/PHASE9.md.
```

### API Security 1.4 - Rate Limiting And Audit Logging

```text
Use the Standard TDD Preamble. First add failing tests for per-IP and per-key
token buckets: anonymous 60/min, API key 300/min, 429 with Retry-After, and no
limiter on health/docs. Add a log-capture test for authenticated audit fields:
user/key id, method, endpoint, status, and latency. Then implement middleware.
Run go test ./internal/api. Update docs/openapi.yaml, docs/RUNBOOK.md, and
docs/PHASE9.md.
```

### Threat Intel 2.1 - Redis Cache

```text
Use the Standard TDD Preamble. Read internal/enrichment/threatintel.go and current
cache tests. First add failing tests for cache hit without HTTP call, expired
cache miss, JSON marshal/unmarshal, Redis unavailable fallback behavior, and TTL
from cache_ttl_minutes. Use a fake cache interface in unit tests. Then implement
ThreatIntelCache with in-memory and Redis implementations. Run go test
./internal/enrichment ./config and go test ./... . Update docs/ARCHITECTURE.md,
docs/PHASE8.md, and docs/PHASE9.md.
```

### Threat Intel 2.2 - Retry And Quota Behavior

```text
Use the Standard TDD Preamble. First add httptest coverage for VirusTotal and
AbuseIPDB: retry on 429 and 5xx, honor Retry-After, do not retry permanent 4xx,
max 3 attempts, context cancellation, and cached result after eventual success.
Then implement provider retry helpers. Run go test ./internal/enrichment. Update
docs/RUNBOOK.md troubleshooting and docs/PHASE9.md.
```

### Worker 3.1 - Durable Queue Semantics

```text
Use the Standard TDD Preamble. Read internal/queue/redis.go and
cmd/forensics/main.go. First add failing tests showing current at-most-once
behavior is insufficient: claimed jobs must be acked, failed jobs retried or
dead-lettered, and duplicate completion must not occur. Prefer Redis Streams
consumer groups unless a simpler reliable pattern is proven by tests. Then
implement publish/claim/ack/fail APIs. Run go test ./internal/queue and go test
./... . Update docs/ARCHITECTURE.md, docs/RUNBOOK.md, and docs/PHASE9.md.
```

### Worker 3.2 - Testable Worker Processor

```text
Use the Standard TDD Preamble. First add failing tests around a worker processor
package for success, source-open failure, parse/enrich/write failure, job status
transitions, packet/flow counts, and graceful shutdown with in-flight work.
Extract worker logic only as needed to make it testable. Run go test
./internal/worker ./internal/store ./internal/queue and go test ./... . Update
docs/RUNBOOK.md worker logs and troubleshooting.
```

### Worker 3.3 - Health And Scale Reporting

```text
Use the Standard TDD Preamble. First add failing API tests that /health reports
Redis status, active worker count, and degraded status when workers disappear.
Add queue heartbeat tests with TTL expiry. Then implement worker heartbeat
registration and health aggregation. Run go test ./internal/api ./internal/queue.
Update docs/openapi.yaml, docs/PHASE8.md, docs/PHASE9.md, and docs/RUNBOOK.md.
```

### Runtime 4.1 - Resource Limits

```text
Use the Standard TDD Preamble. First add failing config and API tests for
max_input_bytes, job_timeout_seconds, allowed_input_roots, and output/temp
directory limits. Prove oversized or disallowed POST /api/v1/jobs requests fail
before enqueue. Then implement config, env overrides, and API validation. Run go
test ./config ./internal/api. Update docs/openapi.yaml, docs/RUNBOOK.md, and
docs/PHASE9.md.
```

### Runtime 4.2 - Automated Pruning

```text
Use the Standard TDD Preamble. First add failing store and pruning tests for
deleting old jobs/findings, preserving recent rows, respecting retention_days and
max_findings_rows, and dry-run counts. Add Redis history trim tests via the queue
abstraction. Then implement a small internal/prune service callable from
serve/worker or a CLI subcommand. Run go test ./internal/prune ./internal/store
./internal/queue. Update docs/RUNBOOK.md, docs/ARCHITECTURE.md, and docs/PHASE9.md.
```

## Observability Prompts

### Observability O0 - Contract And Baseline

```text
Use the Standard TDD Preamble. Reconcile Wiremind observability contracts before adding new behavior. First add failing API/OpenAPI tests proving /health, /metrics, /api/v1/jobs, and /api/v1/jobs/{id}/stream match docs and response schemas. Define whether SSE emits raw Job snapshots or typed progress events, and ensure Prometheus metrics avoid job_id labels. Then make the smallest spec/docs/runtime changes needed. Run go test ./internal/api ./internal/store and update docs/openapi.yaml, docs/API_PLAN.md, docs/PHASE8.md, docs/RUNBOOK.md, and docs/OBSERVABILITY_ROADMAP.md.
```

### Observability O1 - Health Aggregation

```text
Use the Standard TDD Preamble. Implement Go/runtime health aggregation. First add failing internal/api and internal/queue tests proving /health reports postgres, redis, queue_depth, in_flight_jobs, active_worker_count, stale_worker_count, disk_free_bytes, component errors, and aggregate status up|degraded|down. Then implement minimal health providers and worker heartbeat registration. Run go test ./internal/api ./internal/queue ./config and go test ./... . Update docs/openapi.yaml, docs/RUNBOOK.md, docs/ARCHITECTURE.md, docs/PHASE8.md, docs/PHASE9.md, and docs/OBSERVABILITY_ROADMAP.md.
```

### Observability O2 - Metrics

```text
Use the Standard TDD Preamble. Expand Prometheus metrics for Go runtime observability. First add failing prometheus/testutil coverage for job submitted/claimed/started/completed/failed/retried/dead-lettered counters, parse/enrich duration histograms, packet/flow/protocol counters, queue depth gauges, worker count gauges, dependency latency metrics, cache hit/miss metrics, and SSE stream metrics. Then implement scoped collectors without duplicate global registration failures in tests. Run go test ./internal/api ./internal/queue ./internal/worker ./internal/enrichment ./config and go test ./... . Update deploy/prometheus.yml, docs/RUNBOOK.md, and docs/OBSERVABILITY_ROADMAP.md.
```

### Observability O2 - Dashboards Alerts SLOs

```text
Use the Standard TDD Preamble. Add Grafana provisioning, Prometheus alert rules, and SLO documentation. First add config/render or smoke tests proving datasource, dashboard, and alert files are valid. Then add dashboards for API, jobs/workers, parser/enrichment, dependencies, AI agents, delivery, and logs. Define SLOs for API availability, job success, queue latency, parse throughput, agent/report latency, and delivery completion. Run docker compose config plus Prometheus/Grafana smoke checks. Update docs/RUNBOOK.md, docs/PHASE8.md, docs/PHASE9.md, and docs/OBSERVABILITY_ROADMAP.md.
```

### Observability O3 - Logs And Loki

```text
Use the Standard TDD Preamble. Fix structured logging and Loki/Promtail wiring. First add failing log-capture tests proving API requests and worker jobs emit logs with request_id, trace_id, job_id, worker_id, method, route, status, latency, stage, packet_count, flow_count, and error_class. Then implement request ID middleware and worker log context. Fix compose/promtail so Loki receives real logs. Run targeted Go tests, docker compose config, and a Loki labels smoke check. Update docs/RUNBOOK.md, docs/PHASE8.md, and docs/OBSERVABILITY_ROADMAP.md.
```

### Observability O3 - Sentry

```text
Use the Standard TDD Preamble. Add API/worker Sentry observability. First add failing tests with a fake Sentry transport proving API panics are captured with request_id and route, worker job failures are captured with job_id/stage/error_class, and sensitive paths or secrets are redacted. Then implement recovery/capture middleware and worker failure capture. Run go test ./internal/api ./internal/worker ./config and update docs/RUNBOOK.md and docs/OBSERVABILITY_ROADMAP.md.
```

### Observability O4 - Go Tracing

```text
Use the Standard TDD Preamble. Add OpenTelemetry tracing for the Go API and worker. First add tests with an in-memory exporter proving spans exist for submit_job, redis_publish, worker_consume, parse, enrich, postgres_persist, output_write, and job_complete, with job_id and error status attributes. Then wire configurable OTLP export to Jaeger. Run go test ./internal/api ./internal/queue ./internal/worker ./config and a Jaeger/OTLP compose smoke. Update docs/ARCHITECTURE.md, docs/RUNBOOK.md, and docs/OBSERVABILITY_ROADMAP.md.
```

### Observability O4 - Python Tracing

```text
Use the Standard TDD Preamble. Add Python agent tracing without live LLM calls. First add failing pytest coverage with an in-memory exporter proving spans for orchestrator_run, specialist_agent, tool_call, rag_lookup, report_generation, provider_fallback, and agent_error with run_id, job_id, agent, finding_count, and error attributes. Then implement minimal trace hooks. Run cd python && python -m pytest tests/ -v and update docs/PHASE3.md, docs/ARCHITECTURE.md, and docs/OBSERVABILITY_ROADMAP.md.
```

### Observability O5 - AI Observability Contract

```text
Use the Standard TDD Preamble. Add AI observability contract coverage. First update or add failing pytest coverage proving every finding carries trace_id, run_id, finding_id, raw_confidence, optional calibrated_confidence, evidence refs, MITRE refs, tool_trace summary, and critique status while preserving nested Go API fixtures. Then implement the minimal Pydantic contract and adapt specialists, correlation, and reporting. Run targeted Python tests, then python -m pytest tests/ -v. Update docs/ARCHITECTURE.md, docs/PHASE3.md, and docs/OBSERVABILITY_ROADMAP.md only after tests pass.
```

### Observability O5 - Agent Trace Recorder

```text
Use the Standard TDD Preamble. Add a deterministic Python agent trace recorder. First add failing tests proving reason, tool_call, observation, decision, finding_emitted, error, and budget_exhausted events are recorded with monotonic sequence numbers and redacted payload summaries. Use fake specialists/tools. Then wire the recorder through orchestrator and specialist runs without live LLM calls. Update docs/PHASE8.md, docs/RUNBOOK.md, and docs/OBSERVABILITY_ROADMAP.md.
```

### Observability O5 - AI Cost Telemetry

```text
Use the Standard TDD Preamble. Add AI cost telemetry without live provider calls. First add failing pytest coverage proving provider, model, purpose, prompt tokens, completion tokens, cached tokens, estimated cost, actual cost, pricing_version, budget_limit, budget_remaining, skipped_call_reason, and fallback_reason are recorded without raw prompt text, raw packet payloads, secrets, or full PCAP paths. Add metrics tests only with fake collectors or prometheus/testutil, and keep Prometheus labels low-cardinality. Then implement the smallest telemetry plumbing through the Python agent runtime and trace recorder. Run cd python && python -m pytest tests/test_cost_controls.py tests/test_orchestrator.py -v and cd python && python -m pytest tests/ -v. Update docs/AI_COSTING.md, docs/OBSERVABILITY_ROADMAP.md, docs/RUNBOOK.md, and docs/ARCHITECTURE.md only after tests pass.
```

### Observability O5 - AI Quality Cost Fallback Calibration

```text
Use the Standard TDD Preamble. Add local AI quality, RAG, cost, provider, and confidence observability. First add failing pytest cases for MITRE/playbook evals, recall@k, MRR, token/cost accounting, provider fallback reason, raw-vs-calibrated confidence preservation, Brier score, and expected calibration error. Use fake providers only. Then implement deterministic helpers and metadata. Update docs/AI_ROADMAP.md, docs/PHASE3.md, docs/PHASE9.md, and docs/OBSERVABILITY_ROADMAP.md.
```

### Observability O6 - Profiling

```text
Use the Standard TDD Preamble. Add profiling gates and resource visibility. First add failing config and httptest coverage proving pprof is disabled by default, only enabled by explicit config, and protected by localhost or admin access. Then add pprof wiring and defer Pyroscope service addition until pprof tests pass. Add dashboard/runbook notes for CPU, memory, parse duration, worker duration, and LLM token spend. Run go test ./internal/api ./config and docker compose config. Update docs/RUNBOOK.md, docs/PHASE8.md, docs/PHASE9.md, and docs/OBSERVABILITY_ROADMAP.md.
```

### Observability O7 - Delivery Observability

```text
Use the Standard TDD Preamble. Design the minimal delivery/HITL observability contract n8n needs. Start with failing API/store tests for delivery attempts, artifact discovery, approval/rejection state, workflow run IDs, retry counts, last error, and delivery metrics. Resolve the analyst_rejected status mismatch in docs and OpenAPI. Then implement the smallest contract support. Run go test ./internal/api ./internal/store and update docs/openapi.yaml, docs/PHASE9.md, docs/API_PLAN.md, docs/RUNBOOK.md, and docs/OBSERVABILITY_ROADMAP.md.
```

### Observability O8 - Smoke And Failure Drills

```text
This is a docs and smoke-focused observability task. Do not change production code unless a failing smoke check requires it. Define Prometheus alert rules and runbook diagnosis commands for API error rate, queue backlog age, no active workers, dead-letter growth, SSE failures, auth failure spikes, rate-limit spikes, provider budget exhaustion, and delivery failures. Add Grafana panel expectations and exact curl/docker commands. Run docker compose config and document any blocked smoke checks.
```

### Inputs 5.1 - Input Contract Expansion

```text
Use the Standard TDD Preamble. Read internal/input/source.go, docs/PLANNING.md,
and Phase 10 in docs/PHASE9.md. First add failing tests for new SourceType values
and metadata without adding empty stubs. Decide whether log inputs need a separate
normalized-event ingestion path instead of forcing them into PacketSource. Run go
test ./internal/input ./internal/parser. Update docs/ARCHITECTURE.md,
docs/PHASE1.md, and docs/PHASE9.md.
```

### Inputs 5.2 - SSH And S3 Sources

```text
Use the Standard TDD Preamble. First add tests using fake command and fake S3
clients: SSH streams tcpdump -w - bytes into packets and Close cancels the
process; S3 reads range-backed PCAP data without full download and handles context
cancellation. No real network calls in unit tests. Then implement internal/input/ssh.go
and internal/input/s3.go. Run go test ./internal/input ./internal/parser. Update
README supported inputs, docs/RUNBOOK.md, and docs/PHASE9.md.
```

### Inputs 5.3 - Zeek, Suricata, And VPC Logs

```text
Use the Standard TDD Preamble. First add fixture-driven tests mapping Zeek
conn.log/dns.log/http.log/ssl.log, Suricata EVE JSON, and AWS VPC Flow Log rows
into existing models.Flow and enriched event shapes. Do not flatten API wrappers.
Then implement the minimal normalized-log ingestion path. Run go test
./internal/input ./internal/parser ./internal/enrichment. Update
docs/ARCHITECTURE.md, docs/PHASE9.md, and docs/RUNBOOK.md.
```

### Inputs 5.4 - Kafka Stream Source

```text
Use the Standard TDD Preamble. After durable worker queues are complete, first add
tests with a fake Kafka reader for consumer group assignment, cancellation,
malformed message handling, and no duplicate job/event processing. Then implement
internal/input/kafka.go behind config flags. Run go test ./internal/input
./internal/queue ./... . Update README.md, docs/PHASE9.md, and docs/RUNBOOK.md.
```

## Python AI Agent Prompts

### AI 1 - Normalized Verdict Contract

```text
Use the Standard TDD Preamble. Read AGENTS.md and docs/ARCHITECTURE.md. Add a
normalized Python finding/verdict contract for Wiremind AI agents. First write
failing pytest coverage for severity, confidence, evidence, MITRE IDs, timestamps,
tool trace, and critique status. Then update specialists, correlation, and
reporting to use it. Run python -m pytest tests/test_specialists.py
tests/test_correlation.py tests/test_reporting.py -v. Update docs/PHASE3.md and
docs/ARCHITECTURE.md only after tests pass.
```

### AI 2 - Deterministic ReAct Loops

```text
Use the Standard TDD Preamble. Implement deterministic ReAct loops for the Python
specialist agents. Start by adding failing tests proving each agent records
reason/tool/observe/conclude steps, enforces max iterations, and handles malformed
tool output. Use fake reasoners or LLMs only in tests. Then implement the smallest
Python changes needed and run the targeted pytest suite plus tests/test_e2e.py.
```

### AI 3 - Tool-Calling Layer

```text
Use the Standard TDD Preamble. Build the Python tool-calling layer strictly
against the current OpenAPI REST contract. First add failing tests for typed tool
args, registry behavior, denied tools, API errors, and successful calls to
flows/search, dns, tls, http, threats, and stats. Do not add Go endpoints. Mark
packet/entropy deep-dive as unsupported unless docs/openapi.yaml is changed in a
separate API task.
```

### AI 4 - RAG Evaluation Harness

```text
Use the Standard TDD Preamble. Add a local RAG/evaluation harness for MITRE and
playbook retrieval. First create failing pytest cases with fixed expected
techniques and empty-store fallback. Avoid cloud services in unit tests. Implement
deterministic scoring and evaluation helpers and document how to run the eval set
in docs/AI_ROADMAP.md.
```

### AI Cost 5.1 - Pricing Catalog And Budget Config

```text
Use the Standard TDD Preamble. First add failing pytest coverage for a provider-neutral pricing catalog and budget config. Tests must cover known model lookup, unknown model failure, currency and effective-date fields, pricing_version, input/output token rates, optional cached-token rates, provider fixed call cost, max tokens per call, max tokens per agent, max tokens per run, max estimated cost per call/run/job, and env/config overrides. Do not hard-code current vendor pricing in tests or production code; use deterministic fixture rates. Then implement the smallest config and pricing helpers. Run cd python && python -m pytest tests/test_cost_controls.py -v and cd python && python -m pytest tests/ -v. Update docs/AI_COSTING.md, docs/AI_ROADMAP.md, docs/PHASE9.md, and docs/RUNBOOK.md only after tests pass.
```

### AI Cost 5.2 - Preflight Estimation And Budget Guard

```text
Use the Standard TDD Preamble. First add failing pytest coverage proving prompt/token estimation is deterministic, estimated cost is calculated from the configured pricing fixture, and model calls are blocked before execution when remaining budget is insufficient. Tests must prove no fake provider call occurs after denial and that budget_exhausted metadata includes run_id, job_id, agent, provider, model, purpose, pricing_version, budget_limit, estimated_cost, budget_remaining, and skipped_call_reason. Use fake providers only; no live LLM calls. Then implement the smallest accountant and pre-call guard in the Python agent runtime. Run cd python && python -m pytest tests/test_cost_controls.py tests/test_orchestrator.py -v, then cd python && python -m pytest tests/ -v. Update docs/AI_COSTING.md, docs/PHASE3.md, docs/ARCHITECTURE.md, docs/PHASE9.md, and docs/RUNBOOK.md.
```

### AI Cost 5.3 - Actual Usage Accounting

```text
Use the Standard TDD Preamble. First add failing pytest coverage proving token usage is read from fake provider responses, reserved estimated spend is reconciled with actual cost, cached tokens are priced separately when configured, unknown usage fields fail closed or produce explicit incomplete-usage metadata, and cumulative totals are aggregated by run, job, agent, provider, model, and purpose. Use fake provider responses only. Then implement the smallest usage accounting and run summary metadata. Run cd python && python -m pytest tests/test_cost_controls.py tests/test_orchestrator.py -v and cd python && python -m pytest tests/ -v. Update docs/AI_COSTING.md, docs/PHASE3.md, docs/ARCHITECTURE.md, and docs/OBSERVABILITY_ROADMAP.md.
```

### AI Cost 5.4 - Cost Telemetry And Reports

```text
Use the Standard TDD Preamble. First add failing pytest coverage proving each agent run records provider, model, prompt tokens, completion tokens, estimated cost, actual cost, cumulative run cost, budget remaining, pricing_version, and budget_exhausted events without leaking raw prompt text or raw evidence. Add report tests proving machine-readable report output includes a concise cost summary and skipped-call metadata while human Markdown stays readable. Use fake providers and fake runs only. Then implement telemetry plumbing through orchestrator, specialists, correlation, and reporting. Run cd python && python -m pytest tests/test_cost_controls.py tests/test_reporting.py tests/test_orchestrator.py -v and cd python && python -m pytest tests/ -v. Update docs/AI_COSTING.md, docs/OBSERVABILITY_ROADMAP.md, docs/PHASE3.md, docs/RUNBOOK.md, and docs/ARCHITECTURE.md.
```

### AI Cost 5.5 - Provider Fallback Cost Policy

```text
Use the Standard TDD Preamble. First add failing pytest coverage for provider fallback decisions using fake providers: primary unavailable, primary over budget, cheaper fallback selected, fallback denied when capability is insufficient, optional critique skipped before fallback burns budget, and terminal failure when all providers exceed budget. Tests must assert fallback_reason, selected_provider, selected_model, estimated_cost_delta, budget_remaining, and quality/capability guard metadata. Then implement provider routing behind the existing Python agent abstractions. Run cd python && python -m pytest tests/test_cost_controls.py tests/test_orchestrator.py -v and cd python && python -m pytest tests/ -v. Update docs/AI_COSTING.md, docs/AI_ROADMAP.md, docs/PHASE9.md, and docs/OBSERVABILITY_ROADMAP.md.
```

### AI 6 - Feedback And Calibration

```text
Use the Standard TDD Preamble. Implement analyst feedback and confidence
calibration. First write failing tests for positive/negative feedback storage,
false-positive suppression, Platt scaling bounds, and raw-vs-calibrated confidence
preservation. Keep the ChromaDB keyword fallback compatible. Update reporting and
correlation to display calibrated confidence with raw evidence retained.
```

### AI 7 - Multi-LLM, Self-Critique, ATT&CK Export

```text
Use the Standard TDD Preamble. Add multi-LLM fallback, red-team self-critique, and
ATT&CK Navigator export. First write failing tests for provider fallback, critique
outcomes, budget interaction, and valid ATT&CK layer.json output. Implement behind
provider abstractions with fake providers in tests. Run the new targeted tests and
python -m pytest tests/ -v before docs updates.
```

## UI, Contract, And Delivery Prompts

### Contract - U3 Job Flow

```text
Use the Standard TDD Preamble. You are Agent 3 for wiremind API Contract and UI
Integration. Do not edit UI code yet. Add backend/OpenAPI coverage for the U3 job
flow: GET /jobs, POST /jobs, GET /jobs/{id}, and GET /jobs/{id}/stream. First
write failing tests that assert the OpenAPI schema and implemented response shapes
agree, including Job.status, packet_count, flow_count, error, created_at, and
updated_at. Then make the smallest backend/spec changes needed. Run go test
./internal/api ./internal/store and update docs/UI_PLAN_WS.md only if behavior
changes.
```

### UI - U3 Job Management In `wiremind-ui`

```text
Use the Standard TDD Preamble. You are working in the sibling wiremind-ui repo.
Implement U3 job management failing-test-first. Generate API types from
../wiremind/docs/openapi.yaml. Add tests for job listing, submit drawer
validation, successful POST redirect to /jobs/:id, SSE status updates, failed job
display, and View Results linking to /flows?job_id=. Only then implement React
code. Run npm test, npm run build, and npm run generate:api if the contract changed.
```

### Docker UI Smoke Automation

```text
Use the Standard TDD Preamble. You are Agent 3/4 for wiremind Docker UI smoke
automation. Create a smoke script that fails against the documented U7
expectations before fixing anything. It must build/start minimum Compose services,
verify UI load at localhost:3001, verify nginx /api proxy, verify deep-link
fallback, submit a job or use seeded data, and check /flows renders through the UI
path. Keep docs/UI_INTEGRATION_TESTING.md and docs/RUNBOOK.md synchronized.
```

### Delivery Contract For n8n

```text
Use the Standard TDD Preamble. You are Agent 3 for contract design and Agent 4 for
runtime automation. Implement the minimal delivery contract needed by n8n. Start
with failing tests for report artifact discovery, agent/report run trigger or
status, and HITL decision recording. Resolve the mismatch where docs mention
analyst_rejected but Job.status does not. Update docs/openapi.yaml, generated Go
types, API handlers, and docs/PHASE9.md. Run go test ./internal/api ./internal/store.
```

### n8n Workflow Automation

```text
Use the Standard TDD Preamble. You are Agent 4 for n8n delivery automation. Work
failing-test-first where code or scripts are involved. Build a local n8n workflow
export for webhook -> POST /api/v1/jobs -> wait for completion -> trigger report
generation -> Slack HITL -> email/Jira/S3/Confluence delivery. Use mocked
connector credentials or dry-run nodes first, with tests or smoke checks proving
approve, reject, failed job, and missing artifact paths. Update docs/RUNBOOK.md
and docs/PHASE9.md with exact commands and environment variables.
```

## Documentation Consistency Prompt

```text
This is a docs-only task. Do not edit code. Scan README.md and docs/*.md for
stale phase statuses, missing files, outdated endpoint examples, and copied-domain
language. Fix links and status drift while preserving docs/COMMIT_HISTORY.md as
narrative history. Verify with rg for UI_PLAN.md, Four specialist, lead counts,
brainstorm.txt, and old non-/api/v1 endpoint examples. Run git diff --check.
```
