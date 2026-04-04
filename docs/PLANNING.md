# PLANNING.md — UC7 Multi-Agent Network Forensics

Full architecture, phase breakdown, and design decisions.

---

## Problem Statement

Given any network packet source — a `.pcap` file, a live interface, a remote host,
a cloud log, or a stream — automatically investigate it using multiple specialized AI
agents and produce a correlated threat timeline, MITRE ATT&CK mapping, and human-readable
forensics report — with a human-in-the-loop checkpoint before finalizing findings.

---

## Architecture Overview

```
[ Input Source ]                   ← PCAP file | live eth0 | SSH remote | pipe |
      ↓                               PCAPNG | AF_PACKET | S3 | Zeek logs | Kafka
[ Go Input Adapter ]               ← swappable, source-specific
      ↓
[ Packet Channel ]                 ← unified gopacket.Packet stream
      ↓
[ Phase 1 ] Go Parser & Flow Health
    Raw packets → structured JSON per protocol + flow health (retransmissions, blocked, slow)
    ↓
[ Phase 2 ] Go Enrichment Pipeline
    JSON → GeoIP, threat intel, IOC matching, entropy, beaconing, RTT anomalies
    ↓
[ Phase 3 ] LangGraph Sub-Agents (parallel)
    DNS Agent | TLS Agent | HTTP Agent | Lateral Movement Agent
    Each calls back into Go API for additional queries
    ↓
[ Phase 4 ] LangGraph Orchestrator
    Correlates findings → attack chain → MITRE ATT&CK map
    Human-in-the-loop checkpoint
    ↓
[ Phase 5 ] Report Generation
    Executive summary + technical deep-dive + timeline
    ↓
[ Phase 6 ] n8n Delivery
    Slack / email / Jira / Confluence
    ↓
[ Phase 7 ] Memory & Learning
    Vector DB stores findings → future investigations informed
    ↓
[ Phase 8 ] Productionization
    HTTP API, job queue, auth, observability, Docker
```

---

## Development Environment & IDEs

The `wiremind` project is a polyglot mono-repo designed for high-performance processing (Go) and advanced AI reasoning (Python). We leverage specialized JetBrains tools for each domain:

### 🛠 Tools of the Trade

| Domain | Recommended IDE | Purpose |
|---|---|---|
| **Go Core** | **GoLand** | Packet parsing, API development, concurrency |
| **AI Agents** | **PyCharm** | LangGraph orchestration, Python clients, RAG |
| **Data & Storage**| **DataGrip** | PostgreSQL (GORM), Redis, ChromaDB |
| **Workflows** | **n8n** | Pipeline orchestration, Slack/Jira delivery |

### 📁 Repository Strategy: Mono-repo

We currently use a **mono-repo** for `wiremind` to ensure:
- **Unified API Contract**: Changes to the Go REST API can be immediately reflected in the Python `WiremindClient`.
- **Simplified Deployment**: Docker Compose handles the entire stack from a single source of truth.
- **Cross-Language Testing**: Integration tests can span both Go and Python components.

If the AI reasoning component grows into a standalone service with a separate lifecycle, it may be split into `wiremind-core` (Go) and `wiremind-ai` (Python) in the future.

---

## Phase 1 — Go Input Adapters & PCAP Parser ✅

**Goal:** Accept packets from any source through a unified interface, parse into
clean structured JSON slices per protocol, and compute flow health metrics.

**Technology:** Go, `gopacket`, `libpcap`, `afpacket`, `ssh`, `s3`

---

### Input Adapter Architecture

Single interface — all sources implement it:

```go
// PacketSource is the single contract all input adapters implement
type PacketSource interface {
    Open() error
    Packets() chan gopacket.Packet
    Close() error
    Meta() SourceMeta
}

type SourceMeta struct {
    InputType   string    // file | live | pcapng | pipe | ssh | afpacket | s3 | zeek | kafka
    Identifier  string    // filename, interface name, host, bucket path, etc.
    StartedAt   time.Time
    BPFFilter   string    // optional Berkeley Packet Filter expression
}
```

Factory — CLI picks the right adapter:

```go
func NewPacketSource(cfg Config) (PacketSource, error) {
    switch cfg.InputType {
    case "file":      return NewPCAPFileSource(cfg)
    case "live":      return NewLiveInterfaceSource(cfg)
    case "pcapng":    return NewPCAPNGSource(cfg)
    case "pipe":      return NewPipeSource(cfg)
    case "ssh":       return NewSSHRemoteSource(cfg)
    case "afpacket":  return NewAFPacketSource(cfg)
    case "s3":        return NewS3Source(cfg)
    case "zeek":      return NewZeekLogSource(cfg)
    case "kafka":     return NewKafkaSource(cfg)
    default:          return nil, fmt.Errorf("unknown input type: %s", cfg.InputType)
    }
}
```

Everything downstream — parsers, enrichment, agents — never knows what the source was.

---

### Input Sources

**Source 1 — PCAP File** ✅ start here
```bash
./forensics parse --input file --file capture.pcap
```
- Offline analysis, reproducible, good for historical forensics

**Source 2 — Live Network Interface**
```bash
./forensics parse --input live --interface eth0
./forensics parse --input live --interface eth0 --bpf "tcp port 443"
```
- Real-time capture via `gopacket` + `libpcap`
- BPF filter support — same syntax as Wireshark
- Requires root / `CAP_NET_RAW` privilege
- Ring buffer — rolling window, keeps last N seconds

**Source 3 — PCAPNG File**
```bash
./forensics parse --input pcapng --file capture.pcapng
```
- Next-gen PCAP — richer metadata, multi-interface, Wireshark default export
- `gopacket` supports natively, near-zero extra effort

**Source 4 — Named Pipe / stdin**
```bash
tcpdump -i eth0 -w - | ./forensics parse --input pipe
tshark -i eth0 -w - | ./forensics parse --input pipe
```
- Real-time streaming from another tool, zero disk usage
- Compose freely with `tcpdump`, `tshark`, `dumpcap`

**Source 5 — SSH Remote Interface**
```bash
./forensics parse --input ssh \
  --host 192.168.1.10 --user admin --interface eth0
```
- Go SSHes into remote host, runs `tcpdump -w -`, streams back
- Investigate remote servers without downloading large PCAP files

**Source 6 — AF_PACKET (Linux high-performance)**
```bash
./forensics parse --input afpacket --interface eth0
```
- Linux kernel bypass — lower overhead than libpcap
- `gopacket` afpacket support, packet fanout across goroutines
- Use on high-throughput links where libpcap drops packets

**Source 7 — Zeek / Suricata Log Files**
```bash
./forensics parse --input zeek --path /var/log/zeek/
./forensics parse --input suricata --path /var/log/suricata/eve.json
```
- Pre-parsed protocol logs from existing sensors
- Zeek: `dns.log`, `http.log`, `ssl.log`, `conn.log`
- Suricata: EVE JSON with alerts + flow metadata
- Normalised into same internal structs as packet sources

**Source 8 — S3 / Blob Storage Batch**
```bash
./forensics parse --input s3 \
  --bucket s3://pcap-archive/ --prefix 2026/03/26/
```
- Process archived PCAPs from cloud storage
- Go streams PCAP directly from S3 without full download
- Parallel processing via goroutine pool

**Source 9 — Cloud VPC Flow Logs**
```bash
./forensics parse --input vpc-flows \
  --provider aws --bucket s3://my-vpc-logs/
```
- AWS VPC Flow Logs, Azure NSG Flow Logs, GCP VPC Flow Logs
- Metadata only (no payloads) — src/dst IP, port, protocol, bytes, action
- Covers cloud-native infra where full PCAP isn't available

**Source 10 — Kafka Stream**
```bash
./forensics parse --input kafka \
  --broker kafka:9092 --topic network-packets
```
- Consume pre-captured packet events from enterprise stream
- Consumer group — scale horizontally
- Enterprise SIEM integration, high-volume SOC pipelines

---

### Build Priority

| Priority | Source | Effort | Value | Status |
|---|---|---|---|---|
| 1 | PCAP file | Low | Foundation | ✅ |
| 2 | Live interface | Low | Real-time use | ✅ |
| 3 | PCAPNG | Very low | Free with gopacket | ✅ |
| 4 | Named pipe | Low | Composability | ✅ |
| 5 | SSH remote | Medium | Remote forensics | [ ] |
| 6 | AF_PACKET | Low | High-throughput | [ ] |
| 7 | Zeek / Suricata | Medium | Enterprise environments | [ ] |
| 8 | S3 batch | Medium | Historical hunting | [ ] |
| 9 | VPC Flow Logs | Medium | Cloud coverage | [ ] |
| 10 | Kafka | High | SOC pipeline integration | [ ] |
| 11 | eBPF Capture | High | Modern observability | [ ] |
| 12 | NetFlow/IPFIX | Medium | Router/Switch logs | [ ] |
| 13 | EDR Logs (Sysmon) | Medium | Endpoint visibility | [ ] |

---

## 🛠 Planned Tasks (Next Steps)

### Phase 1.5 — Expanded Input Sources
- [ ] **Step 14: SSH Remote Source**
  - Implement `SSHRemoteSource` in `internal/input/ssh.go`.
  - Stream packets via `ssh -C user@host "tcpdump -w - interface eth0"`.
- [ ] **Step 15: S3 / Blob Storage Source**
  - Implement `S3Source` in `internal/input/s3.go`.
  - Stream large PCAPs directly from S3 using range-reads.
- [ ] **Step 16: Cloud VPC Flow Log Adapter**
  - Implement `VPCFlowSource` in `internal/input/vpc_flow.go`.
  - Support AWS VPC Flow Logs (S3/CloudWatch), GCP, and Azure.
- [ ] **Step 17: SIEM / Log Integration**
  - Support Zeek/Suricata JSON logs via `ZeekSource`.
  - Map external logs to internal `EnrichedFlow` models.
- [ ] **Step 18: Kafka / Event Stream Source**
  - Consume pre-captured packet events for large-scale distributed forensics.

---

### Parser Outputs
```
output/
├── meta.json          # File stats, protocol summary, top talkers
├── flows.json         # TCP/UDP flow records
├── flow_health.json   # Retransmissions, blocked flows, slow flows, zero window
├── dns.json           # DNS query/response records
├── tls.json           # TLS handshake metadata
├── http.json          # HTTP request/response records
├── icmp.json          # ICMP records
└── raw_stats.json     # Packet counts, byte totals, timing
```

**Key structs:**
```go
type Flow struct {
    ID            string
    SrcIP         string
    DstIP         string
    SrcPort       uint16
    DstPort       uint16
    Protocol      string
    StartTime     time.Time
    EndTime       time.Time
    PacketCount   int
    BytesTotal    int64
    TCPFlags      []string
    Direction     string    // inbound | outbound | internal
    Health        FlowHealth
}

type FlowHealth struct {
    Retransmissions    int
    OutOfOrder         int
    ZeroWindowEvents   int
    RSTCount           int
    DuplicateACKs      int
    AvgInterPacketGapMs float64
    MaxGapMs           float64
    Completion         string  // complete | incomplete | reset | timeout
    BlockedIndicator   bool
    BlockReason        string  // SYN_no_response | ICMP_unreachable | RST_from_dst | zero_window_stall
    SlowIndicator      bool
    SlowReason         string  // high_rtt | zero_window | retransmission_storm
}

type DNSEvent struct {
    Timestamp  time.Time
    SrcIP      string
    DstIP      string
    QueryName  string
    QueryType  string
    Response   []string
    TTL        uint32
    FlowID     string
}

type TLSEvent struct {
    Timestamp       time.Time
    SrcIP           string
    DstIP           string
    SNI             string
    Version         string
    CipherSuite     string
    CertSubject     string
    CertIssuer      string
    CertExpiry      time.Time
    SelfSigned      bool
    FlowID          string
}

type HTTPEvent struct {
    Timestamp   time.Time
    SrcIP       string
    DstIP       string
    Method      string
    Host        string
    Path        string
    UserAgent   string
    StatusCode  int
    BodySize    int64
    ContentType string
    FlowID      string
}
```

### CLI Examples

```bash
# PCAP file
./forensics parse --input file --file capture.pcap --output ./output/

# Live interface
./forensics parse --input live --interface eth0 --output ./output/
./forensics parse --input live --interface eth0 --bpf "not port 22" --output ./output/

# PCAPNG
./forensics parse --input pcapng --file capture.pcapng --output ./output/

# Pipe from tcpdump
tcpdump -i eth0 -w - | ./forensics parse --input pipe --output ./output/

# SSH remote
./forensics parse --input ssh --host 10.0.0.5 --user admin --interface eth0 --output ./output/

# S3 batch
./forensics parse --input s3 --bucket s3://pcap-archive/ --prefix 2026/03/ --output ./output/

# All inputs support optional filters
./forensics parse --input file --file capture.pcap \
  --protocols dns,tls,http \
  --start "2026-03-26T00:00:00Z" \
  --end "2026-03-26T01:00:00Z" \
  --output ./output/
```

### Go Packages

```
# Core packet capture
github.com/google/gopacket
github.com/google/gopacket/pcap
github.com/google/gopacket/layers
github.com/google/gopacket/afpacket      # AF_PACKET source

# Remote + cloud sources
golang.org/x/crypto/ssh                  # SSH remote source
github.com/aws/aws-sdk-go-v2/service/s3  # S3 batch source
github.com/segmentio/kafka-go            # Kafka source

# CLI
github.com/spf13/cobra
```

### Flow Health Detection (`internal/parser/flow_health.go`)

| Signal | How Detected | Threshold |
|---|---|---|
| Retransmission | Same TCP seq number seen twice on same flow | Any |
| Out-of-order | Seq number lower than previously seen on flow | Any |
| Zero window | TCP window size = 0 in ACK | Any |
| RST storm | RST count on single flow | > 3 |
| Duplicate ACK | Same ACK number repeated | > 2 |
| SYN no response | SYN sent, no SYN-ACK within timeout | 3s default |
| ICMP unreachable | ICMP type 3 received after connection attempt | Any |
| Slow flow | Avg inter-packet gap far above baseline | > 10× baseline |
| Retransmission storm | Retransmissions as % of total packets | > 20% |

---

## Phase 2 — Go Enrichment Pipeline ✅

**Goal:** Augment parsed JSON with external intelligence before sending to LangGraph.

**Technology:** Go, parallel goroutines per enrichment type, PostgreSQL, GORM, SQLite (tests)

**Enrichments applied:**

| Enrichment | Source | Applied To |
|---|---|---|
| GeoIP (country, city) | MaxMind GeoLite2 | All external IPs |
| ASN / Org | MaxMind ASN DB | All external IPs |
| Reverse DNS | System resolver | All IPs |
| Port classification | Built-in registry | All dst ports |
| IOC matching | Local IOC file + feeds | IPs, domains, hashes |
| Threat score | VirusTotal API | Suspicious IPs/domains |
| AbuseIPDB score | AbuseIPDB API | External IPs |
| Shodan exposure | Shodan API | External IPs |
| Payload entropy | Go computation | HTTP bodies, DNS subdomains |
| Beaconing score | Go time-series analysis | Repeated connection patterns |
| RTT anomaly score | Go computation vs baseline | All TCP flows |
| Flow completion rate | Go computation | All TCP flows |
| Asymmetric routing | Go — packets in vs out ratio | All flows |
| Internal/external | RFC1918 check | All IPs |
| Business hours | Configurable schedule | All timestamps |

**Output:** Enriched JSON files + PostgreSQL records.

**Performance:**
- Enrich IPs in parallel using goroutine worker pool
- Cache GeoIP, IOC, and Threat Intel lookups in memory
- Rate-limit external API calls (VirusTotal, AbuseIPDB)
- Persist to PostgreSQL via GORM for distributed agent access
- Skip enrichment for RFC1918 IPs where not applicable

---

## Phase 3 — [LangGraph Sub-Agents](PHASE3.md) 🚧

**Goal:** Four specialist agents reason over their protocol slice in parallel.

**Technology:** LangGraph, Python, Anthropic Claude API

**Agent topology:**
```
orchestrator
    ├── dns_agent      (parallel)
    ├── tls_agent      (parallel)
    ├── http_agent     (parallel)
    └── lateral_agent  (parallel)
```

**Each agent:**
1. Receives its enriched JSON slice as context
2. Has access to Go tool server for additional queries
3. Runs a ReAct loop (reason → tool call → reason → conclude)
4. Outputs a structured `AgentVerdict` Pydantic model

**AgentVerdict schema:**
```python
class Finding(BaseModel):
    finding_id: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    title: str
    description: str
    evidence: list[str]          # packet refs, IPs, domains
    mitre_technique: str         # e.g. T1071.004
    mitre_tactic: str            # e.g. Command and Control
    confidence: float            # 0.0 - 1.0
    first_seen: datetime
    last_seen: datetime

class AgentVerdict(BaseModel):
    agent: str
    findings: list[Finding]
    summary: str
    iocs: list[str]              # IPs, domains, hashes confirmed malicious
    false_positive_candidates: list[str]
```

**Go tool server endpoints (called by agents):**

```
GET  /packets?ip=x.x.x.x&limit=100
GET  /flow/:flow_id
GET  /flow/:flow_id/health          # retransmissions, blocked, slow details
GET  /flows/blocked                 # all flows with blocked_indicator=true
GET  /flows/slow                    # all flows with slow_indicator=true
GET  /dns?domain=example.com
GET  /entropy?flow_id=abc
GET  /ioc?indicator=x.x.x.x
GET  /timeline?ip=x.x.x.x&start=...&end=...
GET  /peers?ip=x.x.x.x          # other internal IPs talking to same dst
```

**DNS Agent focuses on:**
- DNS tunneling (high entropy subdomains > 3.5 bits/char)
- DGA domains (high consonant ratio, random-looking)
- Beaconing (same domain queried at regular intervals)
- Unusual record types (TXT, NULL used for C2 data)
- Long TTL anomalies

**TLS Agent focuses on:**
- Self-signed certificates
- Expired certificates
- Suspicious SNI (IP addresses as SNI, mismatched domains)
- Unusual cipher suites (export-grade, null encryption)
- JA3 fingerprint anomalies
- TLS to non-standard ports

**HTTP Agent focuses on:**
- Large outbound POST bodies (data exfiltration)
- Suspicious User-Agent strings (known malware, empty UA)
- Encoded payloads in URL params or body (base64, hex)
- Web shell patterns
- Unusual HTTP methods (CONNECT tunneling)
- C2 check-in patterns (regular GET to same path)
- **Zero window + large POST** — exfiltration being throttled by receiver
- **Retransmission storms on C2 flows** — unstable or lossy C2 channel

**Lateral Movement Agent focuses on:**
- Internal-to-internal traffic on sensitive ports (445, 3389, 5985)
- Port scanning patterns (sequential ports, many IPs)
- SMB/RDP/WMI connection attempts
- Pass-the-hash indicators
- Unusual internal communication paths
- **Blocked flows to internal hosts** — SYN with no response = scanning firewall-blocked ports
- **RST storms on internal traffic** — IPS/host rejecting repeated connection attempts
- **Slow flows on lateral paths** — throttled or congested lateral movement channels

---

## Phase 4 — Orchestrator & Correlation 🚧

**Goal:** Merge agent findings into a coherent attack narrative.

**Technology:** LangGraph orchestrator node, Claude

**What the orchestrator does:**
1. Collects all four `AgentVerdict` objects
2. Cross-correlates: same IP appearing in multiple agent findings = higher confidence
3. Reconstructs attack chain: initial access → persistence → C2 → exfiltration
4. Maps to MITRE ATT&CK tactics in sequence
5. Assigns overall severity and confidence
6. **Human-in-the-loop:** pauses graph, sends summary to analyst via n8n
7. Analyst approves, modifies, or rejects findings
8. Graph resumes with analyst feedback incorporated

**Output:**
```python
class CorrelatedFindings(BaseModel):
    investigation_id: str
    overall_severity: str
    overall_confidence: float
    attack_chain: list[AttackStep]   # ordered timeline
    mitre_attack_map: dict           # tactic → techniques
    confirmed_iocs: list[str]
    affected_hosts: list[str]
    timeline_start: datetime
    timeline_end: datetime
    analyst_notes: str               # added at HITL checkpoint
    all_findings: list[Finding]
```

---

## Phase 5 — Report Generation 🚧

**Goal:** Transform structured findings into human-readable deliverables.

**Technology:** LangGraph report agent, Go PDF/Markdown generator

**Report types:**

**Executive Summary (1 page)**
- What happened in plain language
- Business impact assessment
- Recommended immediate actions
- Overall risk rating

**Technical Report**
- Full IOC list with evidence
- Per-finding detail with packet references
- MITRE ATT&CK matrix (highlighted techniques)
- Chronological event timeline
- Affected host inventory
- Remediation steps per finding

**Machine-readable output**
- `findings.json` — full structured findings for downstream systems
- `iocs.txt` — plain IOC list for firewall/EDR import
- `mitre_map.json` — ATT&CK navigator layer file

**Output formats:** Markdown, PDF, JSON

---

## Phase 6 — n8n Integration & Delivery 🚧

**Goal:** Automate pipeline triggering and report distribution.

**Technology:** n8n, webhooks

**n8n workflow steps:**
1. **Trigger** — file drop to watched folder, or HTTP webhook, or schedule
2. **Invoke Go parser** — HTTP node calls `./forensics parse` via Go API
3. **Poll for completion** — wait for enrichment to finish
4. **Trigger LangGraph** — HTTP node starts agent run
5. **HITL gate** — send Slack message to analyst with summary, wait for approval
6. **Resume on approval** — analyst clicks approve in Slack → n8n resumes
7. **Deliver report** — send to Slack channel, email, Confluence page, Jira ticket
8. **Archive** — store PCAP + findings in S3/storage with audit metadata

---

## Phase 7 — Memory & Learning 🚧

**Goal:** System improves with each investigation.

**Technology:** ChromaDB or pgvector, LangGraph memory

**What gets stored:**
- Past investigation summaries (vector embeddings)
- Confirmed IOCs → local blocklist
- False positive patterns → injected as agent context
- Normal baseline behavior per network segment
- MITRE technique patterns associated with confirmed threats

**How it's used:**
- Similar past cases injected into agent system prompts
- Known-good IPs/domains skip threat intel lookups
- Confidence scores adjusted based on historical accuracy

---

## Phase 8 — [Productionization, Observability & Refinement](PHASE8.md) 🚧

**Goal:** Reliable, observable, deployable system.

**What gets built:**
- [x] Go HTTP API server (expose pipeline as REST, not just CLI)
- [x] PostgreSQL store (structured findings, audit trail, GORM)
- [x] Redis job queue (handle multiple PCAPs concurrently)
- [x] OpenAPI/Swagger specification (`docs/openapi.yaml`) ✓
- [ ] SSE progress streaming (real-time status to n8n / UI)
- [ ] JWT auth on Go API
- [x] OpenTelemetry tracing (Go + Python) ✓
- [x] Structured logging (slog in Go, structlog in Python) ✓
- [x] Sentry integration (Automated error reporting) ✓
- [x] Advanced Health Checks (/health endpoint) ✓
- [x] Metrics (/metrics for Prometheus) ✓
- [x] Entity Resolution (Host/User tracking) ✓
- [x] Docker + Compose (single command startup) ✓
- [x] Loki/Promtail Log Aggregation ✓
- [x] Grafana Dashboards ✓
- [x] Standalone ChromaDB ✓
- [ ] Cost controls (max tokens per run, LLM spend cap)
- [ ] Retry logic with exponential backoff on all external API calls
- [ ] Secret Management (Vault)
- [ ] Continuous Profiling (Pyroscope)

---

## PCAP Test Data

**Recommended sources:**

| Source | URL | Best For |
|---|---|---|
| Malware Traffic Analysis | malware-traffic-analysis.net | Real malware, C2 traffic |
| PCAP-ATTACK | github.com/sbousseaden/PCAP-ATTACK | ATT&CK mapped samples |
| Wireshark Samples | wiki.wireshark.org/SampleCaptures | Protocol variety |
| Netresec | netresec.com/?page=PcapFiles | CTF + forensics focused |

**Start with:** A malware-traffic-analysis.net sample from 2024-2025
that contains DNS beaconing + HTTP C2 — exercises all 4 sub-agents.

---

## Phase Build Order

- [x] Phase 1 (Go parser)
- [x] Phase 2 (Go enrichment)
- [x] Phase 3 (LangGraph agents)
- [x] Phase 4 (Orchestrator)
- [x] Phase 5 (Reports)
- [ ] Phase 6 (n8n) — see [Phase 9C](PHASE9.md#phase-9c--n8n-delivery-automation)
- [x] Phase 7 (Memory)
- [ ] [Phase 8 (Production)](PHASE8.md) — 🚧 In Progress (Observability & Production Apps)
- [ ] [Phase 9 (Security, Performance & Delivery)](PHASE9.md) — 🚧 In Progress
  - [x] 9A: CORS middleware
  - [ ] 9A: JWT auth, API keys, rate limiting, RBAC, audit logging, Vault
  - [ ] 9B: Redis cache, retry backoff, worker scaling, resource limits, pruning, Pyroscope
  - [ ] 9C: n8n delivery, Slack HITL, email, Jira, S3 archival
- [ ] [Phase 10 (Extended Input Sources)](PHASE9.md#phase-10--extended-input-sources) — SSH, S3, VPC Flows, Zeek, Kafka
- [ ] [Phase 11 (Frontend Dashboard)](PHASE9.md#phase-11--frontend-dashboard) — React + Vite UI (see [UI_PLAN.md](UI_PLAN.md))
- [ ] [Phase 12 (Advanced AI)](PHASE9.md#phase-12--advanced-ai--learning) — cost controls, feedback loop, multi-LLM
- [ ] [Nice to Have](NICE_TO_HAVE.md) — Feature Backlog

---

## Key Design Decisions

| Decision | Choice | Reason |
|---|---|---|
| Parser language | Go | Speed, concurrency, gopacket ecosystem |
| Agent framework | LangGraph | Stateful graphs, HITL support, parallel nodes |
| LLM | Claude Sonnet | Best reasoning for security context, structured outputs |
| Agent↔Go interface | HTTP REST | Language agnostic, easy to test, clear contract |
| Job queue | Redis | Simple, fast, widely supported |
| Vector DB | ChromaDB | Easy local setup, good Python integration |
| Output format | JSON + Markdown | Machine and human readable |
| PCAP source | Public malware samples | No legal risk, reproducible, documented |
