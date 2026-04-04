# Wiremind — Local Runbook

Step-by-step guide to get a full end-to-end analysis running from cold start.

---

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Docker Desktop | 4.x+ | With Compose v2 (`docker compose`) |
| Go | 1.22+ | Only needed for local (non-Docker) builds |
| Python | 3.12+ | Only needed for local (non-Docker) agent runs |
| `libpcap` | any | Linux: `apt install libpcap-dev` · Mac: `brew install libpcap` · Windows: Npcap |

---

## 1. Clone & enter

```bash
git clone https://github.com/alvindcastro/wiremind
cd wiremind
```

---

## 2. Create your `.env` file

Create a `.env` file in the project root. Docker Compose reads it automatically.

```bash
# .env — copy this block and fill in your keys

# --- Required: Anthropic (for Python AI agents) ---
ANTHROPIC_API_KEY=sk-ant-...

# --- Optional: Threat Intel enrichment ---
# Leave blank to skip VirusTotal/AbuseIPDB lookups
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=

# --- Optional: Sentry error tracking ---
SENTRY_ENABLED=false
SENTRY_DSN=
SENTRY_ENVIRONMENT=development
SENTRY_RELEASE=1.0.0

# --- PostgreSQL (defaults match docker-compose.yaml, no change needed) ---
DB_ENABLED=true
DB_HOST=postgres
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=wiremind_pass
DB_NAME=wiremind

# --- Redis ---
REDIS_ENABLED=true
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0

# --- Go API server ---
TOOL_SERVER_PORT=8765

# --- GeoIP paths inside container (default — no change needed) ---
MAXMIND_DB_PATH=/root/data/GeoLite2-City.mmdb
MAXMIND_ASN_DB_PATH=/root/data/GeoLite2-ASN.mmdb

# --- Python agents ---
WIREMIND_API_URL=http://forensics:8765
```

> **Note:** `ANTHROPIC_API_KEY` is the only key that will break the agents container if missing.
> All other keys are optional — the pipeline degrades gracefully without them.

---

## 3. Download required data files

The enrichment pipeline needs three types of static data. Place them under `./data/`.

```bash
mkdir -p data/ioc
```

### 3a. GeoIP databases (MaxMind — free account required)

1. Sign up at https://www.maxmind.com/en/geolite2/signup
2. Download **GeoLite2-City.mmdb** and **GeoLite2-ASN.mmdb**
3. Place them:

```
data/
  GeoLite2-City.mmdb
  GeoLite2-ASN.mmdb
```

> If you skip this step, GeoIP enrichment is silently disabled. Everything else still works.

### 3b. IOC blocklists (free, no account needed)

```bash
# Feodo Tracker — C2 IP blocklist (Emotet, TrickBot, etc.)
curl -o data/ioc/feodo-tracker-ips.txt \
  https://feodotracker.abuse.ch/downloads/ipblocklist.txt

# URLhaus — malicious URLs/hostnames
curl -o data/ioc/abuse-ch-domains.txt \
  https://urlhaus.abuse.ch/downloads/text/

# IPsum — aggregated threat IP list (127k+ IPs)
curl -o data/ioc/ipsum-ips.txt \
  https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt
```

> These paths match `config/config.yaml` exactly. If files are missing the IOC matcher starts empty (no crash).

### 3c. Sample PCAP for end-to-end testing

Pick one of the following — all are well-known public captures with rich traffic:

| PCAP | Why it's good | Download |
|---|---|---|
| **malware-traffic-analysis** (recommended) | Real C2, DNS tunneling, HTTP beaconing | https://www.malware-traffic-analysis.net/training-exercises.html |
| `2018-01-TRAFFIC.pcap` (CTF-style) | DNS, TLS, HTTP mix, manageable size | https://github.com/pan-unit42/wireshark-tutorial-decrypting-HTTPS-traffic |
| Wireshark sample captures | Clean reference traffic | https://wiki.wireshark.org/SampleCaptures |
| `chargen-tcp.pcap` | Already in repo — used by unit tests | `internal/parser/testdata/chargen-tcp.pcap` |

**Recommended for a first run:**

```bash
# Download a small but threat-rich exercise PCAP from malware-traffic-analysis
# (pick any exercise ZIP, extract the .pcap inside)
# Place it at:
mkdir -p data
cp /path/to/your.pcap data/sample.pcap
```

---

## 4. Start the full stack

```bash
docker compose up --build
```

This starts 11 services. First build takes ~3-5 minutes. Subsequent starts are fast.

| Service | Port | Purpose |
|---|---|---|
| `forensics` | 8765 | Go API server (standalone, no PCAP needed to start) |
| `worker` | — | Background PCAP processor |
| `agents` | — | Python LangGraph AI agents |
| `postgres` | 5432 | Persistent findings storage |
| `redis` | 6379 | Async job queue |
| `prometheus` | 9091 | Metrics scraper |
| `grafana` | 3000 | Dashboards (login: `admin` / `wiremind_pass`) |
| `jaeger` | 16686 | Distributed tracing UI (v2) |
| `chromadb` | 8000 | Vector store for AI agent memory |
| `loki` | 3100 | Log aggregation |
| `n8n` | 5678 | Workflow automation |

**Startup order:** `forensics` and `worker` wait for Postgres to pass its health check (`pg_isready`) before connecting. Expect ~10s on first boot.

**Wait for the API to be ready:**

```bash
curl http://localhost:8765/health
# Expected: {"postgres":"up","status":"up"}
```

---

## 4a. Managing individual services

You rarely need to restart the full stack. Target only what changed:

```bash
# Start only the core services (skip observability)
docker compose up forensics worker postgres redis

# Rebuild and restart a single service
docker compose build forensics && docker compose up -d forensics
docker compose build agents   && docker compose up -d agents

# Restart without rebuilding (picks up new .env values)
docker compose restart forensics
docker compose restart worker

# Bring up a service that was not started yet
docker compose up -d chromadb

# Scale the worker (run 2 worker replicas)
docker compose up -d --scale worker=2
```

**After code changes to the Go service or Python agents**, always `build` first — `restart` alone does not recompile.

---

## 5. Run an end-to-end analysis

### Option A — Parse a PCAP directly inside the container

```bash
# Exec into the forensics container and parse
docker compose exec forensics ./wiremind parse \
  --input file \
  --file /root/data/2024-07-30-traffic-analysis-exercise.pcap \
  --output /root/output
```

Results are written to `./output/` and persisted to Postgres. The API server is already running — query it immediately after.

### Option B — Async via Redis job queue (mirrors production flow)

```bash
# Submit a job through the API
curl -X POST http://localhost:8765/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{"input_path": "/root/data/2024-07-30-traffic-analysis-exercise.pcap", "output_path": "/root/output"}'

# Response: {"job_id":"<uuid>","status":"pending"}

# Watch the job status (poll or stream)
JOB_ID=<uuid>
curl http://localhost:8765/api/v1/jobs/$JOB_ID

# Or stream SSE progress
curl -N http://localhost:8765/api/v1/jobs/$JOB_ID/stream
```

The `worker` container picks up the job and processes it automatically.

---

## 6. Query the results

```bash
# Flows (with filters)
curl "http://localhost:8765/api/v1/flows?limit=20&protocol=TCP"
curl "http://localhost:8765/api/v1/flows?src_ip=192.168.1.1"

# Protocol-specific events
curl http://localhost:8765/api/v1/dns
curl http://localhost:8765/api/v1/tls
curl http://localhost:8765/api/v1/http
curl http://localhost:8765/api/v1/icmp

# Threat findings only
curl http://localhost:8765/api/v1/threats

# Summary stats
curl http://localhost:8765/api/v1/stats

# Prometheus metrics
curl http://localhost:8765/metrics
```

---

## 7. Run the AI agents

The `agents` container runs automatically on `docker compose up` and connects to the Go API. To run manually or re-trigger:

```bash
docker compose exec agents python -m wiremind.main --url http://forensics:8765
```

Or from your local machine (with Python env set up):

```bash
cd python
pip install poetry && poetry install
python -m wiremind.main --url http://localhost:8765
```

The orchestrator dispatches to DNS, TLS, HTTP, Lateral Movement, and Beaconing specialists, then produces a correlated report.

---

## 8. Observability UIs

| UI | URL | Credentials |
|---|---|---|
| **Swagger UI (API docs)** | http://localhost:8765/docs | — |
| **OpenAPI spec (raw YAML)** | http://localhost:8765/openapi.yaml | — |
| Grafana | http://localhost:3000 | `admin` / `wiremind_pass` |
| Jaeger tracing (v2) | http://localhost:16686 | — |
| Prometheus | http://localhost:9091 | — |
| ChromaDB | http://localhost:8000 | — |
| n8n workflows | http://localhost:5678 | — |
| Loki (raw) | http://localhost:3100 | — |

**Check the API docs are live:**

```bash
curl -s http://localhost:8765/openapi.yaml | head -5
# Expected:
# openapi: 3.0.3
# info:
#   title: Wiremind API
```

Open http://localhost:8765/docs in a browser to explore and test all endpoints interactively via Swagger UI.

---

## 9. Local development (no Docker)

### Go only

```bash
# Build
go build -o wiremind ./cmd/forensics/

# Start the API server only (no PCAP needed)
./wiremind serve --config config/config.yaml

# Parse a PCAP and persist results (DB must be running)
./wiremind parse \
  --input file \
  --file data/2024-07-30-traffic-analysis-exercise.pcap \
  --output ./output \
  --config config/config.yaml

# Run Go tests
go test ./...
```

### Regenerate typed Go code from the OpenAPI spec (oapi-codegen)

The spec at `docs/openapi.yaml` is the source of truth. `oapi-codegen` can generate
typed Go structs and a `net/http` server interface from it:

```bash
# Install (one-time)
go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest

# Generate — writes internal/api/generated.go
oapi-codegen -config oapi-codegen.yaml docs/openapi.yaml
```

Config lives in `oapi-codegen.yaml` at the project root. It generates:
- Go structs for every schema component (`types`)
- A `StrictServer` net/http interface matching every route (`server`)
- The spec embedded in the binary (`spec`)

> **Note:** The generated file is not committed. Run the command above whenever
> the spec changes and you want up-to-date typed interfaces.

### Python only

```bash
cd python
poetry install
python -m wiremind.main --url http://localhost:8765

# Run Python tests
python -m pytest tests/ -v
```

---

## 10. Tear down

```bash
# Stop all containers (keep volumes)
docker compose down

# Stop and wipe all data volumes (full reset)
docker compose down -v
```

---

## 11. Log checking

### All services at once
```bash
docker compose logs -f
```

### Single service (follow)
```bash
docker compose logs -f forensics
docker compose logs -f worker
docker compose logs -f agents
docker compose logs -f postgres
```

### Last N lines
```bash
docker compose logs --tail=50 forensics
docker compose logs --tail=100 worker
```

### Show timestamps on every line
```bash
docker compose logs -f --timestamps forensics
# Output: 2024-07-30T12:34:56.789Z | level=INFO msg="api server starting" addr=:8765
```

### Only logs from the last N minutes / since a point in time
```bash
docker compose logs --since 10m forensics       # last 10 minutes
docker compose logs --since 1h worker           # last hour
docker compose logs --since "2024-07-30T12:00" forensics  # since a timestamp
```

### Save logs to a file for offline review
```bash
docker compose logs --no-color forensics > forensics.log
docker compose logs --no-color > all-services.log
```

### Check running container status and health
```bash
docker compose ps          # shows State, Ports, and health status
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

### Resource usage (CPU / memory per container)
```bash
docker stats               # live dashboard, Ctrl+C to exit
docker stats --no-stream   # single snapshot
```

### Open an interactive shell inside a container
```bash
docker compose exec forensics sh   # Go API / worker container (Alpine)
docker compose exec agents bash    # Python agents container
docker compose exec postgres bash  # Postgres

# Useful once inside forensics:
ls /root/data/      # verify PCAP and mmdb files are mounted
ls /root/output/    # check parsed JSON output
ls /root/logs/      # check app log files written to disk
cat /root/config/config.yaml  # inspect the active config
```

### Inspect logs written to the mounted ./logs volume
```bash
# The forensics and worker services write to ./logs/ on the host
ls ./logs/
# View a specific log file
tail -f ./logs/wiremind.log
```

### Key things to look for

**forensics startup — healthy:**
```
level=INFO msg="geoip city db opened"
level=INFO msg="ioc blocklist loaded" ... count=5
level=INFO msg="ioc blocklist loaded" ... count=69849
level=INFO msg="api server starting" addr=:8765
```

**forensics startup — postgres connected:**
```
# No WARN about "failed to connect to postgres"
```
```bash
curl http://localhost:8765/health
# {"postgres":"up","status":"up"}
```

**worker — ready for jobs:**
```
level=INFO msg="worker started, waiting for jobs..."
```

**worker — job picked up and completed:**
```
level=INFO msg="processing job" job_id=<uuid> file=/root/data/...
level=INFO msg="job completed"  job_id=<uuid> packets=12345
```

**agents — analysis running and producing findings:**
```json
{"api_url": "http://forensics:8765", "event": "starting_ai_analysis", "level": "info"}
{"findings_count": 2816, "event": "analysis_complete", "level": "info"}
{"severity": "HIGH", "agent": "DNSAgent", "description": "Long query string detected: _ldap._tcp...", "event": "finding_detected", "level": "info"}
{"severity": "CRITICAL", "agent": "TLSAgent", "description": "SNI matched threat intel: ...", "event": "finding_detected", "level": "info"}
```

> `findings_count: 0` with no errors means the specialist agents are reading wrong field names from the API response — see troubleshooting table.

### Filter logs by level
```bash
# Errors only across all services
docker compose logs | grep "level=ERROR"

# Warnings and above
docker compose logs | grep -E "level=(WARN|ERROR)"

# Specific job
docker compose logs worker | grep "<your-job-id>"
```

### Check Postgres migration ran correctly
```bash
docker compose exec postgres psql -U postgres -d wiremind -c "\dt"
# Should list: enriched_flows, flows, dns_events, tls_events, http_events, icmp_events, jobs, entities, ...
```

### Check Redis has jobs queued
```bash
docker compose exec redis redis-cli LLEN forensics_jobs
# 0 = queue empty, N = jobs pending
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `forensics` exits immediately | No config file found | Ensure `config/config.yaml` exists; it's copied into the image at build time |
| `agents` crashes on startup | Missing `ANTHROPIC_API_KEY` | Add to `.env` and restart: `docker compose up agents` |
| `health` shows `postgres: not_initialized` | Race condition — DB not ready | Fixed via healthcheck; if still occurs run `docker compose restart forensics` |
| Empty results from `/api/v1/flows` | No PCAP parsed yet | Run Step 5 first |
| GeoIP fields empty | `.mmdb` files not in `./data/` | Download and place them per Step 3a |
| IOC matches always 0 | Blocklist files missing | Download them per Step 3b |
| `docker ps` → `Failed to initialize` | Docker credential store broken in WSL | Run: `export DOCKER_CONFIG=/home/$USER/.docker-wsl && mkdir -p $DOCKER_CONFIG && echo '{}' > $DOCKER_CONFIG/config.json` then add the export to `~/.bashrc` |
| Port 9090 already allocated | Another service using Prometheus port | Prometheus is mapped to `9091` on host — use http://localhost:9091 |
| `relation "enriched_flows" does not exist` | Stale DB volume with wrong migration order | Run `docker compose down -v && docker compose up --build` |
| `agents` logs `findings_count: 0` with no error | Specialist agents using wrong JSON field paths | Already fixed in `specialists.py` — rebuild: `docker compose build agents && docker compose up -d agents` |
| `workers` log `duplicate key value violates unique constraint` | Concurrent AutoMigrate race between `forensics` and `worker` | Fixed via Postgres advisory lock in `AutoMigrate`; wipe volume if the old constraint is stuck: `docker compose down -v` |
| `unsupported Scan, storing driver.Value type string into type *net.IP` | pgx returns `inet` columns as strings, `net.IP` has no `sql.Scanner` | Fixed via custom `models.IPAddr` type and `gorm:"type:text"` columns |
| Only 1 row in `enriched_flows` after parsing | `FlowID` field not set in enrichment pipeline | Fixed in `internal/enrichment/pipeline.go` — wipe DB volume to re-parse |
| `forensics` healthy but `worker` crashes with FK constraint error | GORM created a backwards FK between `flows` and `enriched_flows` | Fixed via `DisableForeignKeyConstraintWhenMigrating: true`; wipe volume if schema is stuck |
| `ModuleNotFoundError: No module named 'sentry_sdk'` | Missing dependency in `python/pyproject.toml` | Fixed — rebuild agents image: `docker compose build agents` |