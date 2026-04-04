# Phase 8 — Productionization, Observability & Refinement

## Goal
Transform the `wiremind` forensics engine into a reliable, high-performance, and observable system ready for real-world deployment.

---

## Checklist

### 🏗️ Infrastructure & Scalability
- [x] **Step 1: HTTP API Server** — REST endpoints for tool access.
- [x] **Step 2: PostgreSQL Store** — GORM-backed persistence for findings.
- [x] **Step 3: Redis Job Queue** — Asynchronous PCAP processing.
- [x] **Step 4: Docker Compose** — One-command startup for all services.
- [ ] **Step 5: JWT Authentication** — Secure the Go HTTP API.
- [ ] **Step 6: Worker Scaling** — Horizontal scaling of forensics workers via Redis.
- [x] **Step 18: Standalone ChromaDB** — Persistent vector storage for AI agents. ✓
- [x] **Step 21: Log Aggregation (Loki/Promtail)** — Centralized log management for Go and Python services. ✓
- [ ] **Step 22: Secret Management (Vault)** — Securely manage API keys and database credentials.
- [ ] **Step 19: Workflow Automation (n8n)** — Post-analysis orchestration and alerting.

### 👁️ Observability & Monitoring
- [x] **Step 7: Advanced Health Checks** — `/health` endpoint checking DB, Redis, and Worker status.
- [x] **Step 8: Structured Logging** — Implement `internal/logger` using `log/slog` (Go) and `structlog` (Python).
- [x] **Step 9: Prometheus Metrics** — `/metrics` endpoint for lead counts, run times, and packet rates.
- [x] **Step 10: OpenTelemetry Tracing** — Distributed tracing across Go and Python agents using Jaeger. ✓
- [x] **Step 11: OpenAPI/Swagger Specification** — Defined `docs/openapi.yaml` for all API endpoints. ✓
- [x] **Step 24: SSE Progress Streaming** — Real-time status updates for long-running jobs. ✓
- [x] **Step 12: Sentry Integration** — Automated error reporting for scraper failures, enrichment timeouts, and API errors.
- [x] **Step 20: Grafana Dashboards** — Visualize metrics from Prometheus and logs from Loki. ✓
- [ ] **Step 23: Continuous Profiling (Pyroscope)** — Real-time performance profiling for Go and Python.

### 🛠️ Refinement & AI Integration
- [x] **Step 13: Entity Resolution** — Initial schema and correlation models for host/user tracking.
- [x] **Step 25: Advanced Search & Filtering** — Implemented query parameters for IPs, protocols, and aggregate threat view. ✓
- [ ] **Step 14: Persistent Cache** — Redis-backed cache for GeoIP and Threat Intel lookups.
- [ ] **Step 15: API Rate Limiting** — Intelligent handling of VirusTotal/AbuseIPDB quotas.
- [ ] **Step 16: Resource Limits** — Docker CPU/Memory limits and LLM token spend caps.
- [ ] **Step 17: Automated Pruning** — Purge old PCAPs and findings from Postgres/Redis.

---

## Detail: Observability & Refinement Brainstorm

### Health & Liveness
- **Endpoint**: `GET /health`
- **Checks**:
  - `database`: ping PostgreSQL
  - `queue`: ping Redis
  - `worker`: count of active forensics workers
  - `disk`: available space for temporary PCAP storage

### Distributed Tracing (OpenTelemetry)
Trace the lifecycle of a `job_id`:
1. `POST /api/v1/jobs` (API Server)
2. `LPush forensics_jobs` (Redis)
3. `BRPop` (Worker)
4. `internal/parser.Parse()`
5. `internal/enrichment.Enrich()`
6. `POST /api/v1/agents/run` (Python Orchestrator)
7. `Agent Reasoning Loop` (Claude API)
8. `Report Generation`
9. `n8n Webhook` (Delivery)

### Refined Caching
Current Threat Intel cache is in-memory.
- **Refinement**: Move to Redis with a 24h TTL.
- **Benefit**: Restarts don't burn expensive API quotas.
- **Keyspace**: `threatintel:{ip_or_domain}`

### Progress Streaming (SSE)
Agents and UI need to know how far along a 2GB PCAP parse is.
- **Event types**: `parsing`, `enriching`, `reasoning`, `completed`, `failed`.
- **Payload**: `{"job_id": "...", "percent": 45, "status": "enriching flows"}`

### Entity Resolution
Correlating fragmented observations into unified entities.
- **Entities**: `Host`, `User`, `ExternalTarget`, `Campaign`.
- **Logic**: Use MAC, IP, and Hostname history to track a single machine across DHCP changes.
- **AI Help**: Specialists provide entity labels; Orchestrator merges them in Postgres.

---

## Summary of Completed Steps
1. **HTTP API Server** (Step 8 in PHASE2.md)
2. **PostgreSQL Store** (Step 9 in PHASE2.md)
3. **Redis Job Queue** (Step 10 in PHASE2.md)
4. **Docker Compose Orchestration** (Step 4)
5. **Advanced Health Checks** (Step 7)
6. **Structured Logging (slog/structlog)** (Step 8)
7. **Prometheus Metrics** (Step 9)
8. **Sentry Error Tracking** (Step 12)
9. **Entity Resolution Schema** (Step 13)
10. **Loki/Promtail Log Aggregation** (Step 21)
11. **Grafana Dashboards** (Step 20)
12. **Jaeger Tracing Integration** (Step 10)
13. **Standalone ChromaDB** (Step 18)
14. **Advanced Search & Filtering** (Step 25)
15. **SSE Progress Streaming** (Step 24)
