# wiremind

> Multi-agent AI network forensics pipeline. Feed it packets, get back answers.

Wiremind ingests network traffic from any source and runs a team of specialized AI agents to automatically investigate it, correlate findings, map to MITRE ATT&CK, and produce a forensics report.

---

## Status

✅ **Phase 1 complete** — Go input adapters + PCAP parser
✅ **Phase 2 complete** — Enrichment pipeline, PostgreSQL store, & Go API Server
🚧 **Phase 3 pending** — [LangGraph AI Agents (Python)](PHASE3.md)

---

## Tech Stack

| Layer | Technology |
|---|---|
| Packet capture & parsing | Go · gopacket · libpcap · **ssh** · **s3** · **vpc-logs** |
| Agent framework | LangGraph · Python |
| LLM | Anthropic Claude |
| Workflow automation | n8n |
| Storage | PostgreSQL · Redis |

---

## Phase 1 — Quick Start

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

**Run**
```bash
# PCAP file
./wiremind parse --input file --file capture.pcap --output ./output/

# Live interface
sudo ./wiremind parse --input live --interface eth0 --output ./output/

# Pipe from tcpdump
sudo tcpdump -i eth0 -w - | ./wiremind parse --input pipe --output ./output/
```

---

## License

MIT