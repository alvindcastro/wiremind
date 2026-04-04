# API Roadmap for Wiremind

This document outlines the expansion of the Wiremind API to support advanced forensics workflows, AI agent interaction, and production-ready monitoring.

---

## 🏗️ API Architecture Recommendation

### Recommendation: REST (Primary) + gRPC (Internal)

- **REST (Current & Primary)**: 
  - **Why**: Best compatibility with Python-based AI agents (LangGraph, LangChain), standard tooling (cURL, Postman), and easy debugging. 
  - **Use Case**: Agent tool calls, Job management, Configuration, and standard data retrieval.
- **gRPC (Future Internal)**: 
  - **Why**: High performance, low latency, and strict schema enforcement.
  - **Use Case**: Communication between the Go API server and distributed Go Workers for real-time packet streaming or heavy data transfers if REST becomes a bottleneck.
- **GraphQL (Not Recommended)**: 
  - **Why**: Adds complexity that isn't yet justified by the data relationships. Standard REST with query parameters for filtering is sufficient for the current forensics model.

---

## 🚀 API Expansion Backlog

### 🛠️ Phase A: Job & Task Management (Priority 1)
- [x] **Step A1: Job Submission API**
  - `POST /api/v1/jobs` — Submit a new PCAP for analysis (returns `job_id`).
  - Support for local paths, S3 URLs, or multipart/form-data uploads.
- [x] **Step A2: Job Status API**
  - `GET /api/v1/jobs/{id}` — Current status (Pending, Processing, Completed, Failed).
  - Include metadata: start time, duration, packet count, error messages.
- [x] **Step A3: Job List & History**
  - `GET /api/v1/jobs` — Paginated list of all forensics tasks.
- [x] **Step A4: Job Result Scoping**
  - Update existing endpoints (`/api/v1/flows`, etc.) to support a `?job_id={id}` filter.
  - *Note: Basic implementation exists via database-backed retrieval.*

### 🔍 Phase B: Advanced Search & Filtering (Priority 2)
- [x] **Step B1: Flow Search API**
  - `GET /api/v1/flows/search` — Filter by IP, Port, Protocol, or Time Range.
  - Support for CIDR notation and multi-value filters.
- [x] **Step B2: DNS/TLS Query API**
  - `GET /api/v1/dns?query={domain}` — Find all flows associated with a domain.
  - `GET /api/v1/tls?sni={sni}` — Find all TLS handshakes for a specific SNI.
- [x] **Step B3: Malicious Findings API**
  - `GET /api/v1/threats` — Aggregate view of all IOC matches, DGA hits, and high-entropy flows.

### ⚙️ Phase C: Configuration & Control (Priority 3)
- [x] **Step C1: IOC Management API**
  - `POST /api/v1/config/ioc` — Dynamically add IPs, domains, or hashes to the local blocklist.
  - `DELETE /api/v1/config/ioc/{id}` — Remove an entry.
- [x] **Step C2: Pipeline Thresholds**
  - `PATCH /api/v1/config/pipeline` — Adjust entropy thresholds or beaconing jitter sensitivity at runtime.
- [x] **Step C3: Live Capture API**
  - `POST /api/v1/capture/start` — Initiate a live capture on a specific interface.
  - `POST /api/v1/capture/stop` — Gracefully stop the capture and finalize the job.

### 👁️ Phase D: Monitoring & Observability (Priority 4)
- [x] **Step D1: Health Checks**
  - `GET /health` — Status of PostgreSQL, Redis, and Worker availability.
- [x] **Step D2: OpenAPI/Swagger Specification**
  - Spec: `docs/openapi.yaml` — OpenAPI 3.0.3, covers all endpoints and schema components.
  - Served live: `GET /openapi.yaml` returns the raw YAML (embedded in binary via `docs/embed.go`).
  - Swagger UI: `GET /docs` renders an interactive explorer (Swagger UI v5, loaded from CDN).
  - Code generation: `oapi-codegen.yaml` at project root — run `oapi-codegen -config oapi-codegen.yaml docs/openapi.yaml` to generate typed Go structs and server interface into `internal/api/generated.go`.
- [x] **Step D3: Real-time Progress (SSE)**
  - `GET /api/v1/jobs/{id}/stream` — Server-Sent Events for real-time parsing/enrichment progress.
- [x] **Step D4: Prometheus Metrics**
  - `GET /metrics` — Expose standard Go metrics + application-specific counters (packets/sec, total flows).

---

## 📈 Integration Tasks (Tick List)

- [x] Define OpenAPI/Swagger specification for all endpoints (`docs/openapi.yaml`).
- [x] Implement middleware for structured logging (`slog`) and correlation IDs.
- [ ] Implement JWT-based authentication for all non-health endpoints.
- [ ] Add rate-limiting to prevent API abuse (especially for external threat intel lookups).
- [x] Create Python `WiremindClient` wrappers for all new endpoints.
- [x] Add integration tests for the full Job -> Process -> Retrieve lifecycle.
