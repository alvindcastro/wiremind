# Phase 9 — Security, Performance & Extended Delivery

Covers the remaining hardening work across three areas: **security & access control**,
**performance & reliability**, and **delivery automation (n8n)**. Phases 10–13 are
roadmap items for after the core system is production-hardened.

---

## Phase 9A — Security & Access Control

Goal: lock down the API so it is safe to expose beyond localhost.

### Tasks

- [x] **CORS middleware** — configurable `allowed_origins` in `config.yaml` + `CORS_ALLOWED_ORIGINS` env var; handles OPTIONS preflight (`internal/api/server.go`)
- [ ] **JWT authentication** — Bearer token validation on all `/api/v1/*` endpoints
  - Issue tokens via `POST /api/v1/auth/token` (username + password)
  - Store hashed credentials in Postgres (`users` table)
  - Skip auth on `/health`, `/metrics`, `/openapi.yaml`, `/docs`
- [ ] **API key support** — alternative to JWT for machine clients (`X-API-Key` header)
  - Keys stored in Postgres with optional expiry and scope
  - `POST /api/v1/config/apikeys`, `DELETE /api/v1/config/apikeys/{id}`
- [ ] **Rate limiting** — per-IP (or per-key) token-bucket limiter
  - Default: 60 req/min per IP, 300 req/min per API key
  - Return `429 Too Many Requests` with `Retry-After` header
- [ ] **RBAC** — two roles: `read` (GET only) and `admin` (all methods + config + capture)
- [ ] **Audit logging** — structured log line for every authenticated API call: `user`, `method`, `endpoint`, `status`, `latency`
- [ ] **Secret management (Vault)** — replace plaintext DB/API credentials in `config.yaml` with Vault dynamic secrets
  - Agent-based sidecar or `VAULT_ADDR` + `VAULT_TOKEN` env injection
  - Postgres dynamic credentials (short TTL leases)
  - VirusTotal / AbuseIPDB keys stored as Vault KV secrets

---

## Phase 9B — Performance & Reliability

Goal: eliminate fragile in-process state and ensure graceful degradation under load.

### Tasks

- [ ] **Redis-backed threat intel cache** — replace in-memory map with Redis KV
  - Key: `threatintel:{ip_or_domain}`, TTL: 24 h (from `cache_ttl_minutes`)
  - Survives restarts; shared across multiple worker replicas
- [ ] **Retry with exponential backoff** — wrap all VirusTotal / AbuseIPDB HTTP calls
  - Retry on 429, 5xx; respect `Retry-After` header
  - Max 3 attempts, base delay 1 s, jitter ±20 %
- [ ] **Worker horizontal scaling** — document and test running multiple `forensics worker` replicas
  - Redis consumer group semantics to avoid duplicate job processing
  - Health endpoint reports active worker count
- [ ] **Resource limits** — add Docker Compose `deploy.resources` limits for all services
  - Go forensics: 1 CPU / 512 MB, Go worker: 2 CPU / 1 GB
  - LLM token cap: configurable `max_tokens_per_run` in config
- [ ] **Automated data pruning** — background goroutine (or cron job) that:
  - Deletes PCAP files older than `retention_days` (default 30)
  - Purges Postgres rows beyond `max_findings_rows` (default 500 k)
  - Trims Redis job history older than 7 days
- [ ] **Continuous profiling (Pyroscope)** — Go pprof integration via `pyroscope-go` agent
  - Push profiles to self-hosted Pyroscope server (add to Docker Compose)
  - Profile both `forensics serve` (API) and `forensics worker`

---

## Phase 9C — n8n Delivery Automation

Goal: close the loop from analysis completion → analyst notification → archival.

### Tasks

- [ ] **n8n Docker Compose service** — add persistent volume, re-enable service in `docker-compose.yaml`
- [ ] **Webhook trigger** — n8n HTTP trigger node receives `POST /webhook/pcap` with `input_path`; forwards to Go `POST /api/v1/jobs`
- [ ] **Job polling** — n8n polls `GET /api/v1/jobs/{id}` every 10 s until `status == completed`
  - Alternatively: Go calls n8n webhook on job completion (push model)
- [ ] **Slack notification** — on completion, send message to `#forensics-alerts` with:
  - Severity, top finding, affected hosts, link to full report
  - Approve / Reject buttons for HITL checkpoint
- [ ] **HITL gate** — n8n waits for analyst Slack response; on Approve → continue; on Reject → flag job as `analyst_rejected`
- [ ] **Email delivery** — send PDF/Markdown report as attachment to configured recipients
- [ ] **Jira ticket creation** — create issue in configured project with findings summary and IOC list in description
- [ ] **S3 archival** — upload PCAP + `findings.json` + `report.md` to `s3://wiremind-archive/{job_id}/`
- [ ] **Confluence page** — publish full technical report as a Confluence page under the security space

---

## Phase 10 — Extended Input Sources

Goal: cover cloud and enterprise environments beyond local PCAP files.

### Tasks

- [ ] **SSH remote capture** (`internal/input/ssh.go`) — stream from `tcpdump -w -` on remote host
- [ ] **S3 batch source** (`internal/input/s3.go`) — range-read large PCAPs from S3 without full download
- [ ] **VPC Flow Logs adapter** (`internal/input/vpc_flow.go`) — AWS/GCP/Azure metadata-only flows
- [ ] **Zeek log ingestion** (`internal/input/zeek.go`) — parse `conn.log`, `dns.log`, `ssl.log`, `http.log`
- [ ] **Suricata EVE JSON** (`internal/input/suricata.go`) — alerts + flow metadata from existing sensors
- [ ] **AF_PACKET high-perf capture** (`internal/input/afpacket.go`) — Linux kernel bypass for >1 Gbps links
- [ ] **Kafka stream source** (`internal/input/kafka.go`) — consumer group, fan-out across workers
- [ ] **eBPF capture** — future; requires kernel headers and `cilium/ebpf` dependency

---

## Phase 11 — Frontend Dashboard

Goal: browser UI for submitting jobs, viewing findings, and managing IOCs.

> Full detail in [UI_PLAN_WS.md](UI_PLAN_WS.md).
> Separate repo: `wiremind-ui` (React 19 + Vite + TypeScript + Tailwind + shadcn/ui).
> API types generated from `docs/openapi.yaml` via `openapi-typescript`.

### Phase breakdown

| UI Phase | Goal | Status |
|---|---|---|
| U1 | Scaffold + CORS config + routing | ✅ Done |
| U2 | Core data tables (Flows, Threats, DNS, TLS, HTTP, ICMP) | ✅ Done |
| U3 | Job management + SSE live progress | ⬜ Next |
| U4 | Dashboard (stats cards, charts, recent jobs) | ⬜ Not started |
| U5 | Network graph (Cytoscape.js IP relationship explorer) | ⬜ Not started |
| U6 | Config & control (IOC CRUD, pipeline editor, capture start/stop) | ⬜ Not started |

### Key decisions

- **Stack**: React 19 + Vite (SPA, no SSR), TypeScript strict, Tailwind v3, shadcn/ui
- **API client**: `openapi-fetch` + generated types from `docs/openapi.yaml`
- **Tables**: TanStack Table v8 (virtualization, column filters, sort)
- **Routing**: React Router v6
- **Charts**: Recharts; **Graph**: Cytoscape.js
- **Repo**: separate `wiremind-ui` — can open alongside `wiremind` in WebStorm workspace
- **CORS**: ✅ already configured in Go server; add `http://localhost:5173` to `CORS_ALLOWED_ORIGINS`

---

## Phase 12 — Advanced AI & Learning

Goal: improve agent accuracy over time and reduce LLM cost.

### Tasks

- [ ] **LLM cost controls** — `max_tokens_per_run` config; hard cap enforced in Python before each LLM call
- [ ] **Analyst feedback loop** — HITL corrections fed back into ChromaDB as negative examples
- [ ] **False positive suppression** — agent confidence scores adjusted based on historical accuracy per rule
- [ ] **Multi-LLM fallback** — GPT-4o as fallback when Claude API is unavailable; `LLM_PROVIDER` env var
- [ ] **MITRE ATT&CK Navigator export** — generate `layer.json` files importable into ATT&CK Navigator
- [ ] **Confidence calibration** — Platt scaling on agent confidence scores using labelled investigation history
- [ ] **Agent self-critique** — add a "red-team" LLM pass that challenges each finding before reporting

---

## Status Summary

| Phase | Area | Status |
|-------|------|--------|
| 9A | Security & Access Control | 🟡 In Progress (CORS done; JWT/auth pending) |
| 9B | Performance & Reliability | ⬜ Not started |
| 9C | n8n Delivery | ⬜ Not started |
| 10  | Extended Input Sources | ⬜ Not started |
| 11  | Frontend Dashboard | 🟡 In Progress (U1/U2 done; see [UI_PLAN_WS.md](UI_PLAN_WS.md)) |
| 12  | Advanced AI & Learning | ⬜ Not started |
