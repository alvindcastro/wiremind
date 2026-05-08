# Codex Agent Profiles

This file defines practical Codex working profiles for `wiremind`. It is based
on the repository Markdown, the local Claude permission hints in
`.claude/settings.local.json`, and the current Junie memory files, which are
empty. Shared agent instructions live in `AGENTS.md`.

Use these companion docs for execution:

- `docs/TDD_RULES.md` defines the strict test-first policy for code tasks.
- `docs/CODEX_PHASE_CHECKLISTS.md` lists active phases, owners, tasks, checks, and docs to update.
- `docs/CODEX_TASK_PROMPTS.md` contains reusable prompts for future Codex agents.
- `docs/OBSERVABILITY_ROADMAP.md` is the canonical observability hardening track.
- `docs/AI_COSTING.md` is the canonical AI cost governance plan.

## Common Context

Wiremind ingests packet evidence, turns it into structured protocol records,
enriches those records, persists the results, and lets Python LangGraph agents
produce correlated findings and reports.

Current status:

- Complete: Go parser, enrichment, Postgres persistence, Redis jobs, REST API, OpenAPI, Python specialists, orchestration, correlation, reports, ChromaDB, health, metrics, tracing, Sentry, Loki, Grafana, and SSE job streams.
- In progress: auth, API keys, RBAC, rate limiting, Redis-backed threat intel cache, worker scaling, resource limits, pruning, n8n delivery, and UI phases after core tables.
- Frontend: detailed plan is `docs/UI_PLAN_WS.md`; the actual React repo is separate as `wiremind-ui`.

## Agent 1: Go Core Backend

Use for parser, input source, enrichment, persistence, queue, and API server
work.

Primary files:

- `cmd/forensics/main.go`
- `config/config.go`, `config/config.yaml`
- `internal/input/`
- `internal/parser/`
- `internal/enrichment/`
- `internal/models/`
- `internal/store/`
- `internal/queue/`
- `internal/api/server.go`

Required checks:

```bash
go test ./internal/parser ./internal/enrichment ./internal/api ./internal/store
go test ./...
```

Keep in mind:

- Offline PCAP and PCAPNG parsing should remain pure-Go friendly where possible.
- API responses used by Python specialists are nested wrapper structs. Do not flatten them without updating Python, OpenAPI, and docs together.
- Postgres startup is intentionally defensive. Preserve the migration advisory lock and association-safe upsert behavior unless replacing them with tested equivalents.

Definition of done:

- Failing Go tests were added first and the expected failure was observed.
- Focused package tests pass, followed by `go test ./...` unless blocked.
- OpenAPI and docs are updated when behavior changes.

## Agent 2: Python AI Agents

Use for LangGraph specialists, tools, RAG, orchestration, correlation, reporting,
and Python client work.

Primary files:

- `python/src/wiremind/client.py`
- `python/src/wiremind/state.py`
- `python/src/wiremind/agents/`
- `python/src/wiremind/tools/`
- `python/src/wiremind/knowledge/`
- `python/tests/`

Required checks from `python/`:

```bash
python -m pytest tests/ -v
```

Keep in mind:

- Specialists must read nested Go API shapes:
  - DNS: `event.questions[].name`, `event.rcode`
  - TLS: `event.sni`, `event.cipher_suites[]`, `sni_threat.is_malicious`
  - HTTP: `event.user_agent`, `event.host`, `host_threat.is_malicious`
  - Lateral: `flow.src_ip`, `flow.dst_ip`, `flow.dst_port`, `dst_threat.is_malicious`
  - Beacon: top-level `is_beacon`, `beacon_interval_s`, `beacon_jitter`
- Keep findings structured with severity, confidence, evidence, and MITRE context.
- The knowledge store has a lightweight keyword fallback for local compatibility.
- Future provider calls, token accounting, fallback, and budget behavior must follow `docs/AI_COSTING.md`.

Definition of done:

- Failing pytest coverage was added first with fake clients/providers where needed.
- Targeted pytest commands pass, followed by `python -m pytest tests/ -v` unless blocked.
- Agent outputs preserve structured finding contracts and nested API fixture shapes.

## Agent 3: API Contract and UI Integration

Use for OpenAPI, generated clients, UI compose integration, CORS, SSE, and
backend/frontend contract changes.

Primary files:

- `docs/openapi.yaml`
- `oapi-codegen.yaml`
- `internal/api/server.go`
- `docs/UI_PLAN_WS.md`
- `docs/UI_INTEGRATION_TESTING.md`
- `docker-compose.yaml`
- `docker-compose.override.yaml`

Required checks:

```bash
go test ./internal/api ./internal/store
```

Keep in mind:

- `docs/openapi.yaml` is the contract for the React UI and Python clients.
- The UI development server uses CORS/proxy behavior; the Docker UI uses nginx to proxy `/api`.
- SSE is implemented at `GET /api/v1/jobs/{id}/stream` and is used by planned UI job detail flows.

Definition of done:

- Contract tests fail first and pass after implementation.
- `docs/openapi.yaml`, API handlers, and UI/Python expectations are synchronized.
- UI integration docs are updated when behavior or smoke steps change.

## Agent 4: Runtime and Observability

Use for Docker, runbook, config, metrics, logs, tracing, Sentry, ChromaDB,
Prometheus, Grafana, Loki, Promtail, and n8n wiring.

Primary files:

- `Dockerfile`
- `python/Dockerfile`
- `docker-compose.yaml`
- `docker-compose.override.yaml`
- `deploy/prometheus.yml`
- `deploy/promtail.yml`
- `docs/RUNBOOK.md`
- `docs/PHASE8.md`
- `docs/PHASE9.md`
- `docs/AI_COSTING.md` for AI cost telemetry and budget operations

Checks and smoke tests are documented in `docs/RUNBOOK.md`.

Keep in mind:

- Rebuild changed services before restart; `docker compose restart` alone does not recompile.
- Do not remove healthcheck ordering around Postgres.
- Keep observability host ports aligned with the runbook.

Definition of done:

- Runtime behavior has tests or a documented smoke check before implementation.
- `docs/RUNBOOK.md` and phase docs include exact commands, ports, and failure modes.
- Compose changes preserve health ordering and local override behavior.

## Agent 5: Documentation and Planning

Use for roadmap, phase status, runbook, and architecture documentation.

Primary files:

- `README.md`
- `AGENTS.md`
- `docs/ARCHITECTURE.md`
- `docs/PLANNING.md`
- `docs/PHASE*.md`
- `docs/API_PLAN.md`
- `docs/RUNBOOK.md`
- `docs/NICE_TO_HAVE.md`
- `docs/CODEX_AGENTS.md`
- `docs/AI_COSTING.md`

Keep in mind:

- Do not point docs at missing files. The active frontend plan is `docs/UI_PLAN_WS.md`.
- Keep phase status consistent across `README.md`, `docs/PLANNING.md`, `docs/PHASE8.md`, and `docs/PHASE9.md`.
- `docs/COMMIT_HISTORY.md` is a narrative changelog, not the fastest source for current status.

Definition of done:

- Links and status references are scanned with `rg`.
- `git diff --check` is clean except for pre-existing line-ending warnings.
- Docs-only changes do not touch Go, Python, Docker, OpenAPI, or generated files.
