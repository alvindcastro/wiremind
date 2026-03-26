# wiremind

> Multi-agent AI network forensics pipeline. Feed it packets, get back answers.

Wiremind ingests network traffic from any source — a `.pcap` file, a live interface, a remote host, a cloud log, or a stream — and runs a team of specialized AI agents to automatically investigate it, correlate findings, map to MITRE ATT&CK, and produce a human-readable forensics report.

---

## What It Does

```
[ Any Packet Source ]
        ↓
[ Go — Parse & Enrich ]
  Protocol extraction · Flow health · GeoIP · Threat intel · IOC matching
        ↓
[ LangGraph — Multi-Agent Reasoning ]
  DNS Agent · TLS Agent · HTTP Agent · Lateral Movement Agent
        ↓
[ Orchestrator — Correlate & Map ]
  Attack chain · MITRE ATT&CK · Human-in-the-loop checkpoint
        ↓
[ n8n — Deliver ]
  Slack · Email · Jira · Confluence
```

---

## Key Capabilities

**Input-agnostic capture**
Accept packets from PCAP files, live interfaces (`eth0`, `en0`), SSH remote hosts, named pipes, AF_PACKET, S3 archives, Zeek/Suricata logs, VPC flow logs, or Kafka streams — through a single unified adapter interface.

**Flow health analysis**
Detect retransmissions, blocked connections (SYN with no response), zero-window stalls, RST storms, out-of-order packets, and slow flows — turning network health signals into forensic evidence.

**Parallel specialist agents**
Four LangGraph agents run simultaneously, each focused on a protocol slice:
- **DNS Agent** — tunneling, DGA domains, beaconing, unusual record types
- **TLS Agent** — self-signed certs, suspicious SNI, JA3 anomalies, bad cipher suites
- **HTTP Agent** — data exfiltration, C2 check-ins, encoded payloads, web shells
- **Lateral Movement Agent** — port scanning, SMB/RDP/WMI attempts, internal pivoting

**Cross-agent correlation**
The orchestrator merges all findings, reconstructs the attack chain, maps techniques to MITRE ATT&CK, and assigns overall severity and confidence scores.

**Human-in-the-loop**
Pipeline pauses for analyst review before finalizing findings. Analyst can approve, modify, or reject via Slack before the report is delivered.

**Institutional memory**
Every confirmed finding feeds back into a vector database. Future investigations benefit from past cases, known IOCs, and false positive patterns.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Packet capture & parsing | Go · gopacket · libpcap |
| Agent framework | LangGraph · Python |
| LLM | Anthropic Claude |
| Workflow automation | n8n |
| Vector memory | ChromaDB |
| Storage | PostgreSQL · Redis |
| Containerization | Docker · Docker Compose |

---

## Input Sources

| Source | Command |
|---|---|
| PCAP file | `--input file --file capture.pcap` |
| Live interface | `--input live --interface eth0` |
| PCAPNG file | `--input pcapng --file capture.pcapng` |
| stdin / pipe | `tcpdump -w - \| ./wiremind parse --input pipe` |
| SSH remote | `--input ssh --host 10.0.0.5 --user admin --interface eth0` |
| AF_PACKET | `--input afpacket --interface eth0` |
| Zeek logs | `--input zeek --path /var/log/zeek/` |
| S3 archive | `--input s3 --bucket s3://pcap-archive/` |
| VPC flow logs | `--input vpc-flows --provider aws` |
| Kafka stream | `--input kafka --broker kafka:9092 --topic packets` |

---

## Project Structure

```
wiremind/
├── cmd/forensics/          # CLI entrypoint
├── internal/
│   ├── input/              # Packet source adapters (file, live, ssh, s3, kafka...)
│   ├── parser/             # Protocol extractors (dns, tls, http, flow, flow_health)
│   ├── enrichment/         # GeoIP, threat intel, IOC, entropy, beaconing
│   ├── api/                # Go HTTP tool server for LangGraph agents
│   ├── store/              # PostgreSQL + Redis clients
│   └── models/             # Shared structs
├── agents/                 # LangGraph agents (Python)
│   ├── orchestrator.py
│   ├── dns_agent.py
│   ├── tls_agent.py
│   ├── http_agent.py
│   ├── lateral_agent.py
│   └── tools.py
├── n8n/workflows/          # n8n workflow exports
├── config/                 # Config files
└── docker-compose.yml
```

---

## Build Phases

| Phase | Description | Status |
|---|---|---|
| **1** | **Go input adapters + PCAP parser** | 🔨 **In progress** |
| 2 | Go enrichment pipeline | ⏳ Planned |
| 3 | LangGraph sub-agents | ⏳ Planned |
| 4 | Orchestrator + correlation | ⏳ Planned |
| 5 | Report generation | ⏳ Planned |
| 6 | n8n delivery | ⏳ Planned |
| 7 | Memory + learning | ⏳ Planned |
| 8 | Productionization | ⏳ Planned |

---

## Phase 1 — Go Input Adapters & PCAP Parser

**Goal:** Accept packets from any source through a single unified interface, parse
them into structured JSON slices per protocol, and compute flow health metrics.

Everything in phases 2–8 is downstream of this layer. The parsers and agents
never need to know where packets came from.

### Architecture

```
[ Input Source ]          PCAP file | live eth0 | SSH remote | pipe | ...
      ↓
[ PacketSource interface ] single contract all adapters implement
      ↓
[ gopacket.Packet stream ] unified packet channel
      ↓
[ Protocol extractors ]   DNS · TLS · HTTP · TCP flows · ICMP
      ↓
[ Flow health analyzer ]  retransmissions · blocked · slow · zero window
      ↓
[ JSON output ]           one file per protocol slice
```

### Input Adapters

| # | Source | Command | Notes |
|---|---|---|---|
| 1 | PCAP file ✅ | `--input file --file capture.pcap` | Start here |
| 2 | Live interface | `--input live --interface eth0` | Requires root / CAP_NET_RAW |
| 3 | PCAPNG file | `--input pcapng --file capture.pcapng` | Wireshark default export |
| 4 | stdin / pipe | `tcpdump -w - \| ./wiremind parse --input pipe` | Zero disk usage |
| 5 | SSH remote | `--input ssh --host 10.0.0.5 --user admin --interface eth0` | Remote forensics |
| 6 | AF_PACKET | `--input afpacket --interface eth0` | Linux high-throughput |
| 7 | Zeek / Suricata | `--input zeek --path /var/log/zeek/` | Pre-parsed sensor logs |
| 8 | S3 batch | `--input s3 --bucket s3://pcap-archive/` | Historical hunting |
| 9 | VPC flow logs | `--input vpc-flows --provider aws` | Cloud-native coverage |
| 10 | Kafka stream | `--input kafka --broker kafka:9092 --topic packets` | SOC pipeline |

### Output Files

```
output/
├── meta.json           # Capture stats, protocol summary, top talkers
├── flows.json          # TCP/UDP flow records with embedded health
├── flow_health.json    # Retransmissions, blocked flows, slow flows
├── dns.json            # DNS query/response records
├── tls.json            # TLS handshake metadata
├── http.json           # HTTP request/response records
├── icmp.json           # ICMP records
└── raw_stats.json      # Packet counts, byte totals, timing
```

### Flow Health Detection

Every TCP flow is automatically analyzed for network anomalies that double as forensic signals:

| Signal | Detected By | Forensic Relevance |
|---|---|---|
| Retransmission | Duplicate TCP seq number | Unstable C2 channel, lossy exfiltration |
| Out-of-order packets | Seq number regression | Evasion attempts, routing anomalies |
| Zero window | TCP window = 0 in ACK | Exfiltration being throttled |
| RST storm | RST count > 3 on flow | IPS killing connections, scan detection |
| Duplicate ACK | Same ACK repeated > 2× | Packet loss, congestion |
| Blocked flow | SYN with no SYN-ACK | Port scan hitting firewall |
| ICMP unreachable | ICMP type 3 after connect | Port/host blocked |
| Slow flow | Inter-packet gap > 10× baseline | Throttled lateral movement |
| Retransmission storm | Retransmits > 20% of packets | DoS, degraded C2 |

### Quick Start (Phase 1)

**Prerequisites**
```bash
go 1.22+
libpcap-dev      # apt install libpcap-dev  /  brew install libpcap
```

**Install**
```bash
git clone https://github.com/alvindcastro/wiremind
cd wiremind
go mod tidy
go build -o wiremind ./cmd/forensics/
```

**Parse a PCAP file**
```bash
./wiremind parse --input file --file capture.pcap --output ./output/
```

**Capture from a live interface**
```bash
sudo ./wiremind parse --input live --interface eth0 --output ./output/
```

**Pipe from tcpdump**
```bash
sudo tcpdump -i eth0 -w - | ./wiremind parse --input pipe --output ./output/
```

**Capture from a remote host over SSH**
```bash
./wiremind parse --input ssh \
  --host 10.0.0.5 --user admin --interface eth0 \
  --output ./output/
```

**With optional filters**
```bash
./wiremind parse --input file --file capture.pcap \
  --protocols dns,tls,http \
  --start "2026-03-26T00:00:00Z" \
  --end "2026-03-26T01:00:00Z" \
  --output ./output/
```

### Sample Output (`flows.json`)

```json
{
  "flow_id": "flow_a3f9b2",
  "src_ip": "192.168.1.45",
  "dst_ip": "185.220.101.34",
  "src_port": 54321,
  "dst_port": 4444,
  "protocol": "TCP",
  "start_time": "2026-03-26T02:13:44Z",
  "end_time": "2026-03-26T02:13:56Z",
  "packet_count": 142,
  "bytes_total": 204800,
  "direction": "outbound",
  "health": {
    "retransmissions": 14,
    "out_of_order": 3,
    "zero_window_events": 2,
    "rst_count": 0,
    "duplicate_acks": 8,
    "avg_inter_packet_gap_ms": 84.3,
    "max_gap_ms": 1200,
    "completion": "complete",
    "blocked_indicator": false,
    "slow_indicator": true,
    "slow_reason": "retransmission_storm"
  }
}
```

### Phase 1 Go Packages

```
github.com/google/gopacket
github.com/google/gopacket/pcap
github.com/google/gopacket/layers
github.com/google/gopacket/afpacket
golang.org/x/crypto/ssh
github.com/aws/aws-sdk-go-v2/service/s3
github.com/segmentio/kafka-go
github.com/spf13/cobra
```

---

## Environment Variables

```bash
# LLM
ANTHROPIC_API_KEY=

# Threat Intel
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=

# Storage
POSTGRES_URL=postgresql://user:pass@localhost:5432/wiremind
REDIS_URL=redis://localhost:6379

# GeoIP
MAXMIND_DB_PATH=./data/GeoLite2-City.mmdb

# Go tool server
TOOL_SERVER_PORT=8765
```

---

## Sample PCAP Sources

| Source | Best For |
|---|---|
| [malware-traffic-analysis.net](https://malware-traffic-analysis.net) | Real malware, C2 traffic |
| [PCAP-ATTACK](https://github.com/sbousseaden/PCAP-ATTACK) | MITRE ATT&CK mapped samples |
| [Wireshark Samples](https://wiki.wireshark.org/SampleCaptures) | Protocol variety |
| [Netresec](https://netresec.com/?page=PcapFiles) | CTF + forensics focused |

---

## License

MIT
