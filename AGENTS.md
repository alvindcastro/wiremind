# Codex Agent Instructions - wiremind

These instructions are for Codex agents working in this repository. They are
source-controlled on purpose; local Claude and Junie state under `.claude/` and
`.junie/` is ignored and should not be treated as shared project truth.

## Read First

Start with these files before making changes:

- `README.md` for the product overview and phase status.
- `docs/ARCHITECTURE.md` for package boundaries, data flow, and the API response shapes used by Python agents.
- `docs/RUNBOOK.md` for Docker, local development, logging, and troubleshooting.
- `docs/CODEX_AGENTS.md` for role-specific Codex agent profiles.
- `docs/TDD_RULES.md` for the strict test-first policy.
- `docs/CODEX_PHASE_CHECKLISTS.md` for active TDD task checklists.
- `docs/CODEX_TASK_PROMPTS.md` for reusable future-agent prompts.
- `docs/OBSERVABILITY_ROADMAP.md` before changing health, metrics, logs, tracing, Sentry, profiling, dashboards, alerts, or AI telemetry.
- `docs/AI_COSTING.md` before changing AI provider pricing, token accounting, budgets, fallback, or cost telemetry.
- `docs/openapi.yaml` before changing API handlers, clients, or UI integration.

## Project Shape

Wiremind is a Go + Python network forensics system.

- Go owns packet sources, parsing, enrichment, persistence, Redis jobs, REST API, metrics, and Docker runtime.
- Python owns the LangGraph AI agents, RAG helper, orchestration, correlation, and report generation.
- PostgreSQL is the audit store. Redis is the job queue. ChromaDB is AI memory.
- The React UI lives in a separate sibling repo, `wiremind-ui`; this backend repo only contains compose integration and UI planning docs.

## Working Rules

- Use Go 1.24 or newer. `go.mod` declares `go 1.24.0`.
- For code tasks, write or update a failing test before changing production code. Docs-only and read-only brainstorming are the normal exceptions.
- Run targeted Go tests for touched packages, and prefer `go test ./...` before handing off backend changes.
- From `python/`, run `python -m pytest tests/ -v` for Python agent changes.
- Treat `docs/openapi.yaml` as the API contract. Keep API handlers, docs, and generated/client-facing expectations in sync.
- Do not commit secrets, PCAPs, MaxMind databases, IOC feed snapshots, logs, `output/`, `.claude/`, or `.junie/`.
- Preserve existing Postgres/GORM bring-up fixes: advisory migration lock, disabled FK constraints during migration, `models.IPAddr`, and `FlowID` propagation in enrichment.
- Preserve the Python specialists' nested API field access. Protocol API records wrap protocol data under `event`; enriched flow details are under `flow`.

## Verification Shortcuts

Use the narrowest useful check first:

```bash
go test ./internal/parser ./internal/enrichment
go test ./internal/api ./internal/store
go test ./...
```

```bash
cd python
python -m pytest tests/ -v
```

For runtime and Docker checks, follow `docs/RUNBOOK.md` instead of inventing new commands.

## Documentation Sync

When behavior changes, update the closest status or runbook document in the same change:

- Parser, enrichment, or API behavior: `docs/ARCHITECTURE.md`, `docs/PHASE1.md`, `docs/PHASE2.md`, `docs/API_PLAN.md`.
- Python agents, orchestration, reports, or RAG: `docs/PHASE3.md`, `docs/AI_ROADMAP.md`, `docs/ARCHITECTURE.md`.
- Runtime, Docker, auth, jobs, or queues: `docs/RUNBOOK.md`, `docs/PHASE8.md`, `docs/PHASE9.md`.
- Observability, including health, metrics, logs, traces, Sentry, dashboards, alerts, profiling, or AI telemetry: `docs/OBSERVABILITY_ROADMAP.md`, `docs/RUNBOOK.md`, `docs/PHASE8.md`.
- AI provider pricing, token budgets, fallback, or cost telemetry: `docs/AI_COSTING.md`, `docs/AI_ROADMAP.md`, `docs/OBSERVABILITY_ROADMAP.md`, `docs/RUNBOOK.md`.
- UI/backend contract or compose integration: `docs/UI_PLAN_WS.md`, `docs/UI_INTEGRATION_TESTING.md`, `docs/PHASE9.md`.
