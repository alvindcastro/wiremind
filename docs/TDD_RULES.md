# TDD Rules For Codex Tasks

This repo uses strict test-driven development for future code work. A Codex task
that changes Go, Python, OpenAPI behavior, Docker runtime, scripts, or UI
integration must start with failing tests. Docs-only and read-only brainstorming
tasks are the only normal exceptions.

## Non-Negotiable Rule

No production code change before a failing test exists.

For each code task:

- [ ] Identify the smallest behavior change.
- [ ] Add or update the narrowest test that should fail for that behavior.
- [ ] Run the narrow test and capture the expected failure in the task notes.
- [ ] Implement the smallest code change that makes the test pass.
- [ ] Run the focused test again.
- [ ] Run broader tests when touching shared models, API contracts, persistence, runtime wiring, or agent orchestration.
- [ ] Update the closest docs only after behavior is implemented and tested.

## Allowed Exceptions

- [ ] Docs-only edits, including planning, prompts, checklists, and runbooks.
- [ ] Read-only analysis, reviews, or brainstorming.
- [ ] Mechanical generated-code refresh after the source contract has already been changed and tested.
- [ ] Emergency local runtime diagnosis that does not change source files.

If a task claims an exception, state the exception explicitly in the handoff.

## Red-Green-Refactor Loop

- **Red:** Write the failing test first and run the narrow command.
- **Green:** Make the smallest implementation change.
- **Refactor:** Clean only the touched area while keeping tests green.
- **Document:** Update status, runbook, OpenAPI, or architecture docs after tests pass.

Do not combine unrelated refactors with feature work. If a refactor is needed to
make the test possible, keep it local and explain why.

## Verification Matrix

| Area | First test target | Broader check |
|---|---|---|
| Parser/input sources | `go test ./internal/input ./internal/parser` | `go test ./...` |
| Enrichment/threat intel | `go test ./internal/enrichment ./config` | `go test ./...` |
| API/OpenAPI/store | `go test ./internal/api ./internal/store` | `go test ./...` |
| Queue/worker/runtime | `go test ./internal/queue ./internal/store` | `go test ./...` |
| Python agents/tools | `cd python && python -m pytest tests/test_specialists.py tests/test_orchestrator.py -v` | `cd python && python -m pytest tests/ -v` |
| Python RAG/reporting | `cd python && python -m pytest tests/test_rag.py tests/test_reporting.py tests/test_correlation.py -v` | `cd python && python -m pytest tests/ -v` |
| Docker/runtime smoke | Follow `docs/RUNBOOK.md` and task-specific smoke docs | Full compose smoke only when needed |
| Documentation only | Link and status scan with `rg` | No code tests required |

## API Contract Gate

Any API behavior change must satisfy all of these:

- [ ] Failing `internal/api` test added first.
- [ ] `docs/openapi.yaml` updated when request or response contract changes.
- [ ] Store/model tests updated when persistence changes.
- [ ] Python client/UI contract impact reviewed.
- [ ] `docs/API_PLAN.md`, `docs/ARCHITECTURE.md`, or `docs/RUNBOOK.md` updated when behavior changes.

The OpenAPI file is the external contract. Do not rely on undocumented handler
behavior.

## Python Agent Gate

Any Python agent behavior change must satisfy all of these:

- [ ] Failing pytest coverage added first.
- [ ] API-shape fixtures preserve nested Go response wrappers.
- [ ] Findings remain structured with severity, confidence, evidence, and MITRE context.
- [ ] Tool calls are tested with fake clients or mocked HTTP; no live network calls in unit tests.
- [ ] Cost, loop, and fallback behavior fails closed instead of silently producing weak findings.

## AI Cost Gate

Any AI provider pricing, token accounting, budget, fallback, or cost telemetry
change must satisfy all of these:

- [ ] Read `docs/AI_COSTING.md` before editing.
- [ ] Add failing pytest coverage with fake providers before runtime changes.
- [ ] Use deterministic fixture pricing; do not hardcode current vendor prices in tests or production code.
- [ ] Prove over-budget calls are denied before any provider call occurs.
- [ ] Prove `budget_exhausted`, unknown pricing, fallback, and actual-usage reconciliation metadata is structured and redacted.
- [ ] Preserve deterministic parser/enrichment/heuristic findings when model work is skipped.
- [ ] Run `cd python && python -m pytest tests/test_cost_controls.py tests/test_orchestrator.py -v`, then broader Python tests unless blocked.

## Runtime Gate

Runtime work must be testable before compose smoke:

- [ ] Config/env behavior has unit tests.
- [ ] Queue and worker state transitions have isolated tests.
- [ ] Docker compose changes include a documented smoke path.
- [ ] Runbook commands and service ports stay synchronized.

## Observability Gate

Observability work must prove signals before relying on dashboards:

- [ ] Health contract changes have failing API/OpenAPI tests first.
- [ ] Metrics changes have `prometheus/testutil` assertions for names, labels, and values.
- [ ] Avoid high-cardinality Prometheus labels such as `job_id`, raw IPs, domains, or file paths.
- [ ] Logs and Sentry tests use captured or fake transports and prove required correlation fields and redaction.
- [ ] Tracing tests use an in-memory exporter before OTLP/Jaeger wiring.
- [ ] Dashboard, alert, and provisioning files have config, render, or smoke validation before compose rollout.
- [ ] AI observability tests use fake clients/providers only; no live LLM, Sentry, ChromaDB cloud, or network calls.
- [ ] Runbook smoke commands are updated for every new observable signal.

## Done Definition

A future code task is done when:

- [ ] Failing test was added and observed.
- [ ] Focused tests pass.
- [ ] Broader tests pass or the blocker is documented.
- [ ] OpenAPI/docs are updated when behavior changed.
- [ ] No unrelated source files were changed.
- [ ] The final handoff lists tests run and remaining risk.
