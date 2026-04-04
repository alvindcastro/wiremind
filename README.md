# wiremind

> Feed it packets. Get back answers.

Wiremind is a multi-agent AI network forensics pipeline. Drop in a PCAP — or point it at a live interface — and a team of specialized AI agents automatically investigates it, correlates findings across protocols, and produces a structured threat report.

---

## What it does

```
PCAP / live capture / pipe
         │
         ▼
  ┌─────────────────────────────────────────┐
  │  Go Parser  (gopacket)                  │
  │  ├── TCP/UDP flow tracker               │
  │  ├── DNS · TLS · HTTP · ICMP extractors │
  │  └── Flow health (retransmissions, RST) │
  └──────────────┬──────────────────────────┘
                 │
                 ▼
  ┌─────────────────────────────────────────┐
  │  Enrichment Pipeline  (Go)              │
  │  ├── GeoIP + ASN  (MaxMind GeoLite2)    │
  │  ├── IOC matching  (Feodo, URLhaus, etc)│
  │  ├── Threat intel  (VirusTotal, Abuse)  │
  │  ├── Payload entropy  (Shannon)         │
  │  └── Beacon detection  (jitter analysis)│
  └──────────────┬──────────────────────────┘
                 │  REST API  (:8765)
                 ▼
  ┌─────────────────────────────────────────┐
  │  AI Agent Orchestra  (LangGraph/Python) │
  │  ├── DNSAgent      DGA · NXDOMAIN       │
  │  ├── TLSAgent      weak ciphers · IOC   │
  │  ├── HTTPAgent     CLI agents · IOC     │
  │  ├── LateralAgent  SMB/RPC pivots       │
  │  └── BeaconAgent   C2 heartbeat stats   │
  │            │                            │
  │    correlation + report                 │
  └─────────────────────────────────────────┘
                 │
                 ▼
        Structured findings
        MITRE ATT&CK mapping
        Executive + technical report
```

### Real numbers from a 2024 malware PCAP exercise

| Metric | Value |
|---|---|
| Packets processed | 11,562 |
| Flows reconstructed | 194 |
| DNS events | 169 |
| TLS handshakes | 65 |
| HTTP events | 4 |
| ICMP events | 3 |
| AI findings generated | **2,816** |
| Analysis time (agents) | ~124 ms |

---

## Tech stack

| Layer | Technology | Why |
|---|---|---|
| Packet parsing | Go · gopacket | Speed, gopacket ecosystem, CGO-free for offline files |
| Enrichment | Go goroutines | Parallel GeoIP/IOC/entropy with in-memory caching |
| Persistence | PostgreSQL · GORM | Structured audit trail, queryable via REST |
| Job queue | Redis | Async PCAP processing, horizontal scale |
| Agent framework | LangGraph · Python | Stateful graphs, parallel nodes, HITL support |
| LLM | Anthropic Claude | Best reasoning for security context |
| Observability | Prometheus · Grafana · Jaeger · Loki | Full metrics/tracing/log stack |
| Workflow automation | n8n | Trigger, deliver, archive |
| Vector memory | ChromaDB | Past investigation context for agents |

---

## Project status

| Phase | Status | Description |
|---|---|---|
| **Phase 1** | ✅ | Go input adapters + PCAP parser |
| **Phase 2** | ✅ | Enrichment pipeline, PostgreSQL, REST API |
| **Phase 3** | ✅ | LangGraph AI agents (DNS · TLS · HTTP · Lateral · Beacon) |
| **Phase 4** | ✅ | Orchestrator, correlation, attack chain |
| **Phase 5** | ✅ | Report generation |
| **Phase 6** | 🚧 | n8n delivery (Slack · email · Jira) |
| **Phase 7** | ✅ | ChromaDB vector memory |
| **Phase 8** | 🚧 | Productionization, observability, auth |
| **Phase 11** | 🗓 | [Frontend dashboard](docs/UI_PLAN.md) — React + Vite · TypeScript · shadcn/ui |

---

## Quick start

**Full stack (recommended):**
```bash
git clone https://github.com/alvindcastro/wiremind
cd wiremind

# Copy and fill in your keys
cp .env.example .env          # set ANTHROPIC_API_KEY at minimum

# Download a PCAP (e.g. from malware-traffic-analysis.net)
mkdir -p data
cp /path/to/your.pcap data/sample.pcap

# Bring up all 11 services
docker compose up --build
```

**Submit a PCAP for analysis:**
```bash
# Async via job queue (recommended)
curl -X POST http://localhost:8765/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{"input_path": "/root/data/sample.pcap", "output_path": "/root/output"}'

# Watch progress
curl http://localhost:8765/api/v1/jobs/<job_id>
```

**Query results:**
```bash
curl http://localhost:8765/api/v1/flows       # enriched flows with GeoIP/IOC/beacon data
curl http://localhost:8765/api/v1/dns         # DNS events
curl http://localhost:8765/api/v1/tls         # TLS handshakes
curl http://localhost:8765/api/v1/threats     # flows flagged malicious
curl http://localhost:8765/api/v1/stats       # summary statistics
```

**API docs:**
```bash
open http://localhost:8765/docs          # Swagger UI (interactive)
curl http://localhost:8765/openapi.yaml  # raw OpenAPI 3.0.3 spec
```

**Observability:**

| UI | URL |
|---|---|
| Swagger UI | http://localhost:8765/docs |
| Grafana dashboards | http://localhost:3000 |
| Jaeger tracing | http://localhost:16686 |
| Prometheus | http://localhost:9091 |
| n8n workflows | http://localhost:5678 |
| wiremind-ui (dev) | http://localhost:5173 |
| wiremind-ui (prod) | http://localhost:3001 |

See [RUNBOOK.md](docs/RUNBOOK.md) for the full step-by-step guide including data downloads, environment variables, and troubleshooting.

---

## How the AI agents work

Each specialist agent is a LangGraph node that fetches its data slice from the Go REST API, applies heuristic and IOC-based detection, then emits structured findings. The orchestrator runs all five agents in sequence, collects findings, runs correlation, and generates a final report.

```
DNS agent    →  DGA detection (long subdomain heuristic)
                NXDOMAIN response spikes
                IOC-matched domain threats

TLS agent    →  Weak / deprecated cipher suites (RC4, export-grade)
                SNI hostnames matched against threat intel

HTTP agent   →  CLI user-agents (curl, python-requests)
                Request hosts matched against threat intel

Lateral      →  Internal RFC1918 → RFC1918 flows on SMB/RPC ports
Movement        Destination IPs matched against IOC blocklists

Beaconing    →  Flows flagged is_beacon=true by Go jitter analysis
                Confidence inversely proportional to jitter coefficient
```

The Go enrichment engine does the heavy lifting — entropy calculation, beacon detection, IOC matching — before data ever reaches the Python agents. Agents focus on reasoning and correlation, not raw computation.

---

## Architecture

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full package map, data flow, API field reference for agents, and a table of every fix applied during the initial bring-up.

---

## Supported input sources

| Source | Status | Command |
|---|---|---|
| PCAP file | ✅ | `parse --input file --file capture.pcap` |
| Live interface | ✅ | `parse --input live --interface eth0` |
| PCAPNG | ✅ | `parse --input pcapng --file capture.pcapng` |
| stdin / named pipe | ✅ | `tcpdump -w - \| parse --input pipe` |
| SSH remote | 🗓 | `parse --input ssh --host 10.0.0.5` |
| S3 / blob storage | 🗓 | `parse --input s3 --bucket s3://archive/` |
| Zeek / Suricata logs | 🗓 | `parse --input zeek --path /var/log/zeek/` |
| Kafka stream | 🗓 | `parse --input kafka --broker kafka:9092` |
| VPC Flow Logs | 🗓 | `parse --input vpc-flows --provider aws` |

---

## License

MIT
