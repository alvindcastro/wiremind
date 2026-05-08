# AI Costing Plan

This document is a docs-only planning artifact. It does not mean cost tracking
has been implemented. Future code tasks must follow [TDD_RULES.md](TDD_RULES.md):
write the failing test first, prove the failure, then make the smallest code
change.

Wiremind's current Python specialists are mostly deterministic heuristics over
the Go API data. This plan covers the next stage where LangGraph specialists,
supervisors, RAG helpers, critique passes, report generation, and provider
fallbacks may make real model calls.

## Goals

- [ ] Estimate and cap AI spend before each model call.
- [ ] Reconcile estimated spend with provider-reported token usage after each call.
- [ ] Track cost by run, job, agent, provider, model, purpose, and budget scope.
- [ ] Keep deterministic parser, enrichment, IOC, and heuristic findings available when budget is exhausted.
- [ ] Make skipped AI work explicit with structured `budget_exhausted` metadata.
- [ ] Surface spend in reports, logs, traces, metrics, dashboards, and future UI/delivery flows.
- [ ] Avoid hardcoding current vendor prices in production code or tests.

## Non-Goals

- [ ] Do not add live model calls during planning.
- [ ] Do not store raw prompts, raw packet payloads, secrets, or full PCAP paths in cost logs.
- [ ] Do not add high-cardinality Prometheus labels such as `job_id`, raw domains, raw IPs, or file paths.
- [ ] Do not rely on live provider APIs in unit tests.

## Cost Drivers

- [ ] Specialist reasoning calls: DNS, TLS, HTTP, lateral movement, beaconing, and future protocol specialists.
- [ ] Supervisor/router calls that decide which specialist or tool should run next.
- [ ] Tool-using ReAct loops, especially repeated flow/DNS/TLS/HTTP lookups.
- [ ] RAG retrieval and embeddings for MITRE, playbooks, past cases, advisories, and analyst feedback.
- [ ] Report generation, executive summaries, remediation plans, and IOC export narratives.
- [ ] Self-critique or red-team passes over findings.
- [ ] Multi-provider fallback and retry behavior after provider errors or quality failures.
- [ ] Long-context prompts that include too many flows, events, findings, or evidence snippets.
- [ ] External non-LLM services: VirusTotal, AbuseIPDB, Sentry, hosted vector stores, managed tracing, and cloud storage.
- [ ] Runtime infrastructure: Python agent CPU/memory, ChromaDB, Postgres, Redis, n8n, Prometheus, Grafana, Loki, and Jaeger.

## Pricing Model

Provider prices change over time, so code should load pricing from config or a
versioned data file instead of embedding constants.

- [ ] Store prices by `provider`, `model`, `effective_date`, `currency`, and unit.
- [ ] Support input tokens, output tokens, cached input tokens, embedding tokens, image/audio units if future providers need them, and fixed per-call minimums if applicable.
- [ ] Keep unknown provider/model pricing fail-closed for enforcing spend caps, with an explicit development-only override if needed.
- [ ] Record the pricing version used for each estimate so historical run totals can be explained later.

Formula:

```text
estimated_model_cost =
  (estimated_input_tokens / price_unit) * input_token_price
+ (max_output_tokens / price_unit) * output_token_price
+ provider_fixed_call_cost
```

After the call:

```text
actual_model_cost =
  (actual_input_tokens / price_unit) * input_token_price
+ (actual_output_tokens / price_unit) * output_token_price
+ (cached_input_tokens / price_unit) * cached_input_token_price
+ provider_fixed_call_cost
```

Run total:

```text
run_estimated_cost =
  sum(model_call_estimates)
+ sum(embedding_estimates)
+ sum(external_api_estimates)
+ optional_runtime_estimate
```

## Budget Scopes

- [ ] Per call: deny a single model request that is too expensive.
- [ ] Per agent: stop one specialist from consuming the whole run budget.
- [ ] Per run: stop the current LangGraph execution before it exceeds budget.
- [ ] Per job: include report generation and any delivery-triggered agent reruns.
- [ ] Daily or monthly: future operator and tenant budget guard.
- [ ] Provider quota: prevent accidental retries from burning external provider limits.

## Phase C0 - Cost Contract And Policy

Goal: define the cost accounting contract before implementation.

- [ ] Decide the canonical budget fields: `run_id`, `job_id`, `agent`, `provider`, `model`, `purpose`, `pricing_version`, `estimated_cost`, `actual_cost`, `budget_remaining`, `budget_state`.
- [ ] Decide where durable cost records live: Python trace file first, Postgres API contract later if UI/report history needs it.
- [ ] Define config names for provider pricing, default budgets, per-agent overrides, and development-mode behavior.
- [ ] Define redaction rules for prompt summaries and evidence refs.
- [ ] Define report behavior when budget is exhausted: include skipped stages and deterministic findings.
- [ ] Link this plan from `docs/AI_ROADMAP.md`, `docs/OBSERVABILITY_ROADMAP.md`, and `docs/CODEX_PHASE_CHECKLISTS.md`.

TDD gate for later code:

- [ ] Add failing config/model tests before any runtime implementation.
- [ ] Use fake providers and fixed pricing fixtures only.

## Phase C1 - Preflight Estimation And Budget Gates

Goal: estimate cost before each provider call and fail closed when budget is not available.

- [ ] Add a provider-neutral token estimator interface with deterministic tests.
- [ ] Add a budget ledger that reserves estimated spend before calls.
- [ ] Deny over-budget calls before network access.
- [ ] Emit structured `budget_exhausted` events with skipped agent, purpose, estimated cost, and remaining budget.
- [ ] Keep heuristic findings, correlation, and reporting running with explicit degraded metadata.
- [ ] Test unknown provider/model pricing and missing budget config.

TDD gate:

- [ ] First failing tests should prove over-budget calls are skipped and no fake provider call occurs.
- [ ] Run targeted Python tests, then `cd python && python -m pytest tests/ -v`.

## Phase C2 - Actual Usage Accounting

Goal: reconcile estimates with provider usage data after successful calls.

- [ ] Capture provider-reported input tokens, output tokens, cached tokens, model, stop reason, retry count, and fallback reason.
- [ ] Reconcile reserved estimate with actual cost and release unused reservation.
- [ ] Aggregate totals by run, job, agent, provider, model, and purpose.
- [ ] Add budget state to final `ForensicsState` or the future normalized finding/run envelope.
- [ ] Preserve raw confidence and evidence while adding cost metadata.
- [ ] Keep accounting deterministic in tests with fake provider responses.

TDD gate:

- [ ] First failing tests should prove estimate-versus-actual reconciliation and run-level totals.
- [ ] No live provider calls in tests.

## Phase C3 - Cost Observability

Goal: make AI spend visible without leaking sensitive evidence.

- [ ] Add log fields for cost events: `run_id`, `job_id`, `agent`, `provider`, `model`, `purpose`, `budget_state`, `estimated_cost`, `actual_cost`, and `error_class`.
- [ ] Add traces around model calls, skipped calls, RAG lookups, fallback, and report generation.
- [ ] Add Prometheus counters/histograms for calls, skipped calls, estimated spend, actual spend, token usage, and fallback count without high-cardinality labels.
- [ ] Add Sentry context for budget-exhausted and provider-failure events using redacted summaries.
- [ ] Add Grafana panels for run spend, token usage, budget exhaustion, fallback cost, and cost by agent.
- [ ] Add alert and failure-drill guidance for budget exhaustion spikes.

TDD gate:

- [ ] Metrics tests must use `prometheus/testutil`.
- [ ] Trace tests must use an in-memory exporter.
- [ ] Sentry tests must use fake transport.

## Phase C4 - API, UI, Reports, And Delivery

Goal: expose cost state to analysts and automation after runtime accounting exists.

- [ ] Decide whether cost summaries belong in an agent-run endpoint, job details, report artifacts, or all three.
- [ ] Update `docs/openapi.yaml` only after failing API contract tests define the response shape.
- [ ] Add report sections for AI work performed, skipped work, total estimated spend, and provider fallback.
- [ ] Add future UI cards or tables for budget remaining, skipped agents, and cost by stage.
- [ ] Add n8n delivery metadata so Slack/email/Jira can include budget-exhausted warnings.
- [ ] Add runbook commands for diagnosing missing pricing, exhausted budget, and provider fallback.

TDD gate:

- [ ] Add failing API/report tests before changing API handlers or report output.
- [ ] Keep UI changes in the sibling `wiremind-ui` repo and regenerate client types only after OpenAPI changes are tested.

## Phase C5 - Cost Optimization And Quality Tradeoffs

Goal: reduce spend without hiding quality regressions.

- [ ] Add prompt compaction rules that cap flows/events/evidence snippets per agent.
- [ ] Prefer deterministic heuristics and Go enrichment before model calls.
- [ ] Add cheap-model routing for low-risk summarization and stronger-model routing for high-severity reasoning.
- [ ] Add local LLM routing for air-gapped or low-cost deployments where quality is acceptable.
- [ ] Cache stable RAG results and repeated model-independent context.
- [ ] Track quality metrics next to cost: precision, recall, evidence completeness, severity correctness, duplicate finding rate, Brier score, and expected calibration error.
- [ ] Treat self-critique as budgeted optional work unless a task explicitly marks it required.

TDD gate:

- [ ] Add failing eval tests showing quality/cost metadata is preserved across routing decisions.
- [ ] Use fake providers with deterministic outputs.

## Phase C6 - Operations And Governance

Goal: make cost controls operable in local, demo, and production-like runs.

- [ ] Document required and optional environment variables in `docs/RUNBOOK.md` after config exists.
- [ ] Add default local budgets that are safe for demos.
- [ ] Add budget exhaustion failure drills to `docs/OBSERVABILITY_ROADMAP.md` O8.
- [ ] Define operator override rules and audit logging for budget changes.
- [ ] Add periodic cost summary export for future admin UI or delivery workflows.
- [ ] Review pricing fixtures on a scheduled basis without changing historical run totals.

TDD/smoke gate:

- [ ] Config and override behavior needs failing tests first.
- [ ] Docs-only runbook additions are allowed after behavior exists or as planning notes.
