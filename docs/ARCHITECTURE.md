# Architecture — wiremind

How the codebase is structured and how data flows through it.

> For a higher-level overview and quick start, see [README.md](README.md).
> For running the stack end-to-end, see [RUNBOOK.md](RUNBOOK.md).

---

## What it does

Takes raw network traffic (a `.pcap` file, a live interface, a pipe, etc.) and produces:

1. **Structured events** — per-protocol slices (DNS, TLS, HTTP, ICMP, Flows) parsed from raw packets.
2. **Enriched findings** — GeoIP, IOC matching, Shannon entropy, beacon detection, and optional threat intel (VirusTotal/AbuseIPDB) applied per flow.
3. **Persistent audit trail** — all findings written to PostgreSQL via GORM and queryable through a REST API.
4. **AI-agent insights** — five LangGraph specialist agents (DNS, TLS, HTTP, Lateral Movement, Beaconing) reason over the enriched data and emit structured findings with severity, confidence, and MITRE context.

---

## Data flow (Distributed & Async)

```
[Packet Source] (CLI parse) ──► [Redis Job Queue] ──► [Worker]
                                                        │
[Worker / Parser Loop] ◄────────────────────────────────┘
      │
      ├──► flow tracker      → Flow[]
      ├──► DNS extractor     → DNSEvent[]
      ├──► TLS extractor     → TLSEvent[]
      ├──► HTTP extractor    → HTTPEvent[]
      └──► ICMP extractor    → ICMPEvent[]
                │
                ▼
        [Enrichment Pipeline] (GeoIP, IOC, Entropy, Beacon, ThreatIntel)
                │
                ▼
      [PostgreSQL Store] (GORM) ◄───► [Go REST API Server]
                │                            │
                └────────────────────────────┘
                             │
                             ▼
                    [LangGraph AI Agents] (Python)
                             │
                             ▼
                    [Specialist Agents] (DNS, TLS, HTTP, LM, Beacon)
```

---

## Package map (Go Core)

### `internal/models`
Pure data — structs only, no logic.
Every other package depends on this; nothing here depends on anything else. Includes GORM models and JSON tags for API/DB serialization.

### `internal/input`
Source adapters. Each one implements `PacketSource`.
- `pcap_file.go` / `pcapng.go`: **Pure-Go** `pcapgo` for offline analysis (no `libpcap` required).
- `live.go`: Live capture (requires `libpcap`/`Npcap`).
- `pipe.go`: stdin/named pipes support.

### `internal/parser`
Stateless (mostly) functions that turn packets into typed events.
- `pcap.go`: Main dispatch loop.
- `flow.go`: Bidirectional 5-tuple tracking.
- `dns.go`, `tls.go`, `http.go`, `icmp.go`: Protocol extractors.

### `internal/enrichment`
Multi-source enrichment pipeline.
- `geoip.go`: MaxMind GeoLite2 integration.
- `ioc.go`: Local blocklist matcher (IP, Domain, Hash).
- `entropy.go`: Shannon entropy for payload randomness.
- `beacon.go`: Jitter analysis for C2 detection.
- `threatintel.go`: Async VirusTotal and AbuseIPDB integration with in-memory caching.
- `pipeline.go`: Orchestrator for all enrichers.

### `internal/api`
Go HTTP server (`internal/api/server.go`) providing REST endpoints (`/api/v1/flows`, `/dns`, `/stats`, etc.) to serve enriched results to Python agents.

Also hosts two documentation endpoints:
- `GET /openapi.yaml` — serves the OpenAPI 3.0.3 spec embedded from `docs/openapi.yaml`
- `GET /docs` — Swagger UI (interactive browser, Swagger UI v5 via CDN)

### `docs`
Documentation package. Contains `openapi.yaml` (the OpenAPI 3.0.3 spec, source of truth for all API contracts) and `embed.go` (Go embed directive that bundles the YAML into the compiled binary so `/openapi.yaml` is served without filesystem access).

Code generation: run `oapi-codegen -config oapi-codegen.yaml docs/openapi.yaml` to produce typed Go structs and a `net/http` `StrictServer` interface in `internal/api/generated.go`.

### `internal/store`
PostgreSQL persistence layer using GORM. Handles automatic migrations and transaction-safe storage of all forensics findings.

### `internal/queue`
Redis-based job queue (`internal/queue/redis.go`) for asynchronous processing of PCAP files between the CLI and worker.

### `cmd/forensics`
Cobra CLI:
- `parse`: Run synchronous or asynchronous (`--async`) processing. Use `--serve` to also start the API after parsing.
- `worker`: Background worker listening to Redis for new jobs.
- `serve`: Start the API server standalone — no PCAP required. Used by Docker Compose.

---

## AI Agent Architecture (Python)

Located in `python/src/wiremind/`:

- **`client.py`**: Async Python client for the Go REST API.
- **`state.py`**: `ForensicsState` definition for LangGraph orchestration.
- **`agents/specialists.py`**: Each agent reads from its dedicated API endpoint. The Go API returns enriched wrapper structs — protocol events are nested under an `event` key, and flow details are nested under `flow`. Specialists must read these nested paths:

    | Agent | API endpoint | Key fields read |
    |---|---|---|
    | `DNSAgent` | `/api/v1/dns` | `event.questions[].name`, `event.rcode` |
    | `TLSAgent` | `/api/v1/tls` | `event.sni`, `event.cipher_suites[]`, `sni_threat.is_malicious` |
    | `HTTPAgent` | `/api/v1/http` | `event.user_agent`, `event.host`, `host_threat.is_malicious` |
    | `LateralMovementAgent` | `/api/v1/flows` | `flow.src_ip`, `flow.dst_ip`, `flow.dst_port`, `dst_threat.is_malicious` |
    | `BeaconingAgent` | `/api/v1/flows` | `is_beacon`, `beacon_interval_s`, `beacon_jitter` (all top-level) |

    Detection logic per agent:
    - `DNSAgent`: Long query strings (DGA heuristic), NXDOMAIN responses.
    - `TLSAgent`: Weak/deprecated cipher suites (RC4), IOC-matched SNI hostnames.
    - `HTTPAgent`: CLI user-agents (`curl`, `python-requests`), IOC-matched request hosts.
    - `LateralMovementAgent`: Internal RFC1918→RFC1918 flows on SMB/RPC ports (445/135/139), IOC-matched destination IPs.
    - `BeaconingAgent`: Flows flagged `is_beacon=true` by the Go engine; confidence derived from `beacon_jitter` (lower jitter = more regular = higher confidence).

---

## Tests

| Package | Responsibility | Fixture |
|---|---|---|
| `internal/parser` | Packet-to-Event accuracy | `chargen-tcp.pcap` |
| `internal/enrichment` | IOC, Threat Intel, Stats logic | Mocks (httptest) |
| `internal/store` | GORM/PostgreSQL persistence | SQLite (CGO-free) |
| `internal/api` | REST endpoint validation | httptest.ResponseRecorder |
| `python/tests` | Agent reasoning & API client | pytest + respx |

Run all Go tests: `go test ./...`
Run AI tests: `python -m pytest python/tests/`

---

## Key Design Decisions

1.  **Go for Speed, Python for Brains**: High-speed packet processing and database management in Go. Complex reasoning and LLM orchestration in Python via LangGraph.
2.  **REST-First Integration**: The Go and Python components communicate over a clean, documented REST API, allowing them to scale independently.
3.  **Distributed by Default**: Use of Redis for job queuing allows the system to scale horizontally from a single CLI tool to a distributed cluster of workers.
4.  **Mono-repo Workflow**: Both Go and Python live in one repository to ensure API consistency. Each is managed in its native JetBrains IDE (GoLand/PyCharm).
5.  **Offline-Friendly**: Offline PCAP parsing is pure-Go, removing the requirement for `libpcap` on Windows/Linux for forensic analysis of existing files.
6.  **Schema-on-Write**: Findings are immediately structured and persisted to PostgreSQL, ensuring an immutable audit trail for forensic investigations.

---

## E2E Fixes Applied (initial bring-up)

These non-obvious fixes were required to get the pipeline working end-to-end from scratch:

| Area | File | Problem | Fix |
|---|---|---|---|
| Build | `Dockerfile` | `go.mod` requires Go 1.24 but image used 1.22 | Changed base image to `golang:1.24-alpine` |
| CLI | `cmd/forensics/main.go` | `parse --serve` required a `--file` arg, container exited immediately | Added standalone `serve` cobra command |
| Docker | `docker-compose.yaml` | `forensics`/`worker` raced with Postgres startup | Added `pg_isready` healthcheck; `depends_on: condition: service_healthy` |
| Docker | `docker-compose.yaml` | Jaeger v1 EOL warning | Changed to `jaegertracing/jaeger:latest` (v2) |
| Migration | `internal/store/postgres.go` | Concurrent `AutoMigrate` from two containers caused `duplicate key` on `pg_type` | Added Postgres advisory lock (`pg_advisory_lock`) |
| Migration | `internal/store/postgres.go` | GORM created backwards FK (`flows → enriched_flows`) | Added `DisableForeignKeyConstraintWhenMigrating: true` |
| Persistence | `internal/store/postgres.go` | GORM `Save()` re-inserted associations, hitting unique constraints | Replaced with `clause.OnConflict{DoNothing: true}` + `Omit(clause.Associations)` |
| Persistence | `internal/enrichment/pipeline.go` | `EnrichedFlow.FlowID` never set — all 194 flows had empty ID, only 1 row inserted | Added `FlowID: f.FlowID` when constructing `EnrichedFlow` |
| Types | `internal/models/ip.go` (new) | pgx returns `inet` columns as `string`; `net.IP` has no `sql.Scanner` | Created custom `IPAddr` type with `sql.Scanner` / `driver.Valuer` |
| Types | `internal/models/flow.go`, `events.go` | `gorm:"type:inet"` with `net.IP` caused scan errors | Changed to `gorm:"type:text"` with `IPAddr` |
| Python | `python/pyproject.toml` | `sentry_sdk` import failed — missing from dependencies | Added `sentry-sdk = "^2.0.0"` |
| Python | `python/src/wiremind/agents/specialists.py` | All 5 specialists used flat field names (`log.get("query")`) but API returns nested structs (`event.questions[].name`) | Updated all agents to read correct nested paths; added IOC-based detection rules |
