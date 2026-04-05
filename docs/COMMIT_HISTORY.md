# Commit History — wiremind

A deep-dive record of every commit: what changed, why the decision was made,
where in the codebase it lives, when it happened, and how the code works.

---

## Table of Contents

1. [Initial repo setup](#1-initial-repo-setup)
2. [Project scaffold — cobra CLI + config loader](#2-project-scaffold--cobra-cli--config-loader)
3. [Core models — packets, flows, protocol events](#3-core-models--packets-flows-protocol-events)
4. [PacketSource interface + factory](#4-packetsource-interface--factory)
5. [PCAPFileSource — first real packets](#5-pcapfilesource--first-real-packets)
6. [Parser dispatch loop + ParseResult skeleton](#6-parser-dispatch-loop--parseresult-skeleton)
7. [Flow tracker extractor](#7-flow-tracker-extractor)
8. [Flow health extractor](#8-flow-health-extractor)
9. [DNS event extractor](#9-dns-event-extractor)
10. [TLS ClientHello extractor](#10-tls-clienthello-extractor)
11. [HTTP extractor with TCP stream reassembly](#11-http-extractor-with-tcp-stream-reassembly)
12. [ICMP event extractor](#12-icmp-event-extractor)
13. [JSON output writer + trim to 4 core sources](#13-json-output-writer--trim-to-4-core-sources)
14. [Wire CLI end-to-end](#14-wire-cli-end-to-end)
15. [Refactor — remove dead helpers](#15-refactor--remove-dead-helpers)
16. [Add gitignore + project docs + sample PCAP fixtures](#16-add-gitignore--project-docs--sample-pcap-fixtures)
17. [Table-driven parser tests](#17-table-driven-parser-tests)
18. [Implement live, pipe, and pcapng sources](#18-implement-live-pipe-and-pcapng-sources)
19. [Input source tests](#19-input-source-tests)

**Phase 2 — Enrichment Pipeline**

20. [Enriched models — ThreatContext, GeoInfo, IOCMatch, EnrichedFlow](#20-enriched-models--threatcontext-geoinfo-iocmatch-enrichedflow)
21. [GeoIP enrichment via MaxMind GeoLite2](#21-geoip-enrichment-via-maxmind-geolite2)
22. [IOC matcher — local blocklist for IPs, domains, and hashes](#22-ioc-matcher--local-blocklist-for-ips-domains-and-hashes)
23. [Shannon entropy scorer for payload analysis](#23-shannon-entropy-scorer-for-payload-analysis)
24. [Beacon detector for C2 heartbeat pattern detection](#24-beacon-detector-for-c2-heartbeat-pattern-detection)
25. [Threat intel enrichment — VirusTotal + AbuseIPDB](#25-threat-intel-enrichment--virustotal--abuseipdb)
26. [Wire enrichment pipeline](#26-wire-enrichment-pipeline)
27. [Go HTTP API server with tool endpoints](#27-go-http-api-server-with-tool-endpoints)
28. [PostgreSQL store for enriched findings](#28-postgresql-store-for-enriched-findings)
29. [Integrate enrichment and API into CLI](#29-integrate-enrichment-and-api-into-cli)
30. [Redis job queue and worker mode](#30-redis-job-queue-and-worker-mode)
31. [Brainstorm and plan expanded input sources](#31-brainstorm-and-plan-expanded-input-sources)
32. [Brainstorm and plan "nice to have" features](#32-brainstorm-and-plan-nice-to-have-features)
33. [Brainstorm and plan Phase 8 Productionization and Observability](#33-brainstorm-and-plan-phase-8-productionization-and-observability)
34. [Refine Phase 8 with System Reliability & Observability ideas](#34-refine-phase-8-with-system-reliability--observability-ideas)

**Phase 3 — LangGraph AI Agents**

35. [Python infrastructure & API client (Phase 3.1)](#35-start-phase-31-python-infrastructure--base-setup)
36. [Specialist AI agents: DNS, TLS, HTTP, Lateral, Beaconing (Phase 3.2)](#36-phase-32-specialist-ai-agents)
    - Step 41: Architecture docs update
    - Step 42: RAG & knowledge store (Phase 3.3)
    - Step 43: Orchestrator & multi-agent flow (Phase 3.4)
    - Step 44: AI integration verification & E2E tests (Phase 3.5)
    - Step 45: Correlation & reporting (Phase 3.6)

**Phase 8 — Productionization & Observability**

    - Step 45: n8n, Loki, Promtail integration
    - Step 46: Prometheus metrics, Sentry, Entity Resolution
    - Step 47: Docker ecosystem expansion
    - Step 48: Production ecosystem (n8n, Loki, Promtail)
    - Step 49: Job Management API (Phase A)
49. [OpenAPI/Swagger specification](#49-openapiswagger-specification-for-wiremind-api)
50. [Advanced Search & Filtering API (Phase B)](#step-50---2026-04-03)
51. [Configuration & Control API (Phase C)](#step-51---2026-04-03)
52. [SSE Progress Streaming (Phase D)](#step-52---2026-04-03)

**E2E Bring-up Fixes**

53. [Infrastructure fixes — Dockerfile, `serve` command, Docker Compose, advisory lock](#step-53---2026-04-03--1cf5525)
54. [Data-path fixes — `IPAddr` type, FlowID propagation, agent field names](#step-54---2026-04-03--67457dd)
55. [Add UI service to Docker Compose (Phase 7 - U7.5)](#55-add-ui-service-to-docker-compose-phase-7---u75)

---

## 55. Add UI service to Docker Compose (Phase 7 - U7.5)

**Commits:** `pending`
**Date:** 2026-04-04

### What
Added the `wiremind-ui` service to the main `docker-compose.yaml` file. This service builds the React frontend from the sibling `wiremind-ui` repository and serves it via Nginx on port 3001. It depends on the `forensics` API service.

### Why
To enable a single-command bring-up of the entire Wiremind stack, including the frontend. This follows the architecture where the UI is served by Nginx, which also proxies API requests to the Go backend, simplifying CORS and deployment.

### Where
```
docker-compose.yaml
docs/UI_PLAN_WS.md
```

---

## 1. Initial repo setup

**Commits:** `d236887`, `2ed766b`, `9161cb1`, `b0091dd`, `51bde10`
**Date:** 2026-03-26

### What
Added a `.gitignore` (with a brief incorrect `.idea/`-only version, then the correct broad one) and an initial `README.md` that was later slimmed down to reflect Phase 1 scope.

### Why
Every repo needs a `.gitignore` before any real files are committed so that IDE files, build artifacts, and environment files never land in git history. The README establishes intent and is the first thing anyone reads.

### Where
```
.gitignore
.idea/.gitignore   (added then removed — mistake, replaced by root .gitignore)
README.md
```

### How
`.gitignore` excludes:
- GoLand/VSCode IDE folders (`.idea/`, `.vscode/`)
- Go build artifacts (`/forensics`, `*.exe`, `/output/`)
- Environment files (`.env`, `*.env`)
- MaxMind DB files (`*.mmdb`) — large binary, not committed
- Python virtualenvs and `__pycache__`
- OS noise (`*.DS_Store`, `Thumbs.db`)

---

## 2. Project scaffold — cobra CLI + config loader

**Commit:** `84fee53`
**Date:** 2026-03-27

### What
Created the Go module and the minimal skeleton that makes `./forensics parse --help` work.

### Why
Phase 1 is built incrementally — each step must compile before the next begins. The scaffold is step 0: it establishes the module path, the CLI entry point, and the config layer so that all later code has a home.

### Where
```
go.mod                    — module wiremind, Go 1.22+, declares dependencies
go.sum                    — locked dependency checksums
cmd/forensics/main.go     — cobra root command + parse subcommand (stub)
config/config.go          — loads config.yaml + honours env var overrides
config/config.yaml        — default values
```

### How

**`go.mod`** declares `module wiremind` and pulls in:
- `github.com/spf13/cobra` — CLI framework
- `gopkg.in/yaml.v3` — config file parsing

**`config/config.yaml`** defines defaults used throughout:
```yaml
output_dir: "./output"
log_level: "info"
tool_server_port: 8765
pcap:
  snapshot_len: 65535
  promiscuous: false
  timeout_ms: 30
```

**`config/config.go`** exposes a `Load(path string) (*Config, error)` function that:
1. Opens and YAML-decodes the file at `path`
2. Calls `applyEnvOverrides` to let `OUTPUT_DIR`, `LOG_LEVEL`, `TOOL_SERVER_PORT` override any file value
3. Returns the populated `*Config` or a wrapped error

**`cmd/forensics/main.go`** registers a `parse` subcommand but its `RunE` is a no-op at this stage. Flag definitions (`--input`, `--file`, `--interface`, `--output`, `--config`) are already wired so the `--help` output is useful from day one.

---

## 3. Core models — packets, flows, protocol events

**Commit:** `1685b17`
**Date:** 2026-03-27

### What
Defined all the data shapes the pipeline produces and consumes. No logic — only structs.

### Why
Every extractor, every output file, and eventually every LangGraph agent tool works with these types. Defining them first means all subsequent code has a stable target to compile against. It also forces a clear answer to "what do I want to know about a DNS event?" before writing any parsing logic.

### Where
```
internal/models/packet.go   — RawPacketMeta
internal/models/flow.go     — Flow, FlowHealth, FlowState
internal/models/events.go   — DNSEvent, TLSEvent, HTTPEvent, ICMPEvent
```

### How

**`RawPacketMeta`** (`packet.go`) is the lowest-level type. It represents one packet regardless of protocol:
```go
type RawPacketMeta struct {
    Timestamp time.Time
    SrcIP     net.IP
    DstIP     net.IP
    SrcPort   uint16
    DstPort   uint16
    Protocol  string   // "TCP", "UDP", "ICMP", …
    Size      int
    FlowID    string   // derived 5-tuple hash — links events to flows
}
```

**`Flow`** (`flow.go`) represents a reconstructed conversation identified by its 5-tuple. Key fields:
- `StartTime` / `LastSeen` — timing window of the conversation
- `PacketCount` / `ByteCount` — volume metrics
- `State FlowState` — TCP state machine (`SYN`, `ESTABLISHED`, `FIN`, `RST`, `UNKNOWN`)

**`FlowHealth`** (`flow.go`) tracks anomaly signals on a per-flow basis:
- `Retransmissions` — duplicate sequence numbers detected
- `RSTCount` — forcible teardowns
- `ZeroWindowCount` — receiver backpressure signals
- `DupACKCount` — fast-retransmit precursor
- `Blocked bool` — synthesised flag: true when RST seen or ≥3 zero-windows

**Protocol events** (`events.go`) are intentionally flat (no nested structs beyond `DNSQuestion`/`DNSAnswer`) to serialise cleanly to JSON and be easy for an LLM to reason about:
- `DNSEvent` — query or response; holds questions + RR answers with type/TTL/data
- `TLSEvent` — ClientHello only; captures SNI, cipher suites, supported TLS versions
- `HTTPEvent` — one request or one response; `Direction` field distinguishes them
- `ICMPEvent` — type/code pair with a human-readable `TypeName`

All events carry a `FlowID` so they can be joined back to the flow that carried them.

---

## 4. PacketSource interface + factory

**Commit:** `424a7fc`
**Date:** 2026-03-27

### What
Defined the single abstraction that decouples the parser from all input sources.

### Why
The parser must be completely unaware of where packets come from. Whether reading a `.pcap` file, sniffing a live interface, or consuming a Kafka stream, the parser loop is identical. The interface is the seam that makes this possible. Defining it before any concrete source means the parser can be written once and never touched again as new sources are added.

### Where
```
internal/input/source.go    — PacketSource interface, SourceMeta, SourceConfig, NewPacketSource factory
internal/input/pcap_file.go — placeholder struct (empty, to be filled in next commit)
go.mod / go.sum             — adds github.com/google/gopacket
```

### How

**`PacketSource`** interface:
```go
type PacketSource interface {
    Open() error
    Packets() <-chan gopacket.Packet
    Meta() SourceMeta
    Close() error
}
```

- `Open()` — allocates OS resources (file handle, socket, etc.). Starts the background reader goroutine.
- `Packets()` — returns a read-only channel. The parser ranges over it. The source closes the channel when exhausted.
- `Meta()` — returns static metadata (type, description, start time). Used for the `meta.json` output file.
- `Close()` — releases resources. Called via `defer` in the CLI.

**`SourceConfig`** is a flat bag of optional fields. Each adapter reads only what it needs:
```go
type SourceConfig struct {
    FilePath  string   // file / pcapng / pipe
    Interface string   // live
}
```

**`NewPacketSource`** is a simple switch that maps a `SourceType` string to its constructor. At this stage, `SourceLive`, `SourcePipe`, and `SourcePCAPNG` return `errors.New("not implemented")` stubs. `SourceFile` returns the real adapter (added next commit).

---

## 5. PCAPFileSource — first real packets

**Commit:** `a784c07`
**Date:** 2026-03-27

### What
Implemented the first concrete `PacketSource` — reads a `.pcap` file and emits packets on a channel.

### Why
Every extractor added afterwards (flow, DNS, TLS, HTTP, ICMP) needs real packets to be developed and tested against. The file source is the safest starting point: it is deterministic, repeatable, and requires no network access.

### Where
```
internal/input/pcap_file.go
go.mod / go.sum — adds github.com/google/gopacket/pcap (libpcap binding)
```

### How

**`PCAPFileSource.Open()`**:
1. Calls `pcap.OpenOffline(path)` — opens the file via libpcap
2. Records `SourceMeta` (type, description, timestamp)
3. Creates a buffered channel (`make(chan gopacket.Packet, 100)`)
4. Launches `go readPackets()` — the background goroutine

**`readPackets()`**:
```go
src := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
src.NoCopy = true  // avoids a copy per packet — important for performance
for pkt := range src.Packets() {
    s.packets <- pkt
}
// channel is closed by defer close(s.packets) — signals the parser loop to stop
```

`NoCopy = true` tells gopacket to reuse its internal buffer. The parser must not retain a reference to packet bytes after the next packet arrives — but since all extractors copy the data they need into their event structs immediately, this is safe and saves significant allocation overhead.

**`Close()`** calls `s.handle.Close()`. Because the handle is closed, the `src.Packets()` range in `readPackets()` terminates naturally, and `defer close(s.packets)` fires, cleanly signalling the parser loop.

---

## 6. Parser dispatch loop + ParseResult skeleton

**Commit:** `e69689b`
**Date:** 2026-03-27

### What
Added the core parse loop — the single function that consumes a `PacketSource` and returns a `ParseResult`.

### Why
The loop is the backbone of Phase 1. Every extractor added in the next six commits plugs into this loop. Writing the skeleton first (with placeholder calls to extractors that return nil) means the loop compiles and can be tested before any extractor is complete.

### Where
```
internal/parser/pcap.go      — Parse(), RawStats, ParseResult
internal/parser/flow.go      — stub
internal/parser/flow_health.go — stub
internal/parser/dns.go       — stub
internal/parser/tls.go       — stub
internal/parser/http.go      — stub
internal/parser/icmp.go      — stub
```

### How

**`ParseResult`** is what the JSON writer will eventually serialise:
```go
type ParseResult struct {
    Meta       input.SourceMeta
    Stats      RawStats
    Flows      []models.Flow
    FlowHealth []models.FlowHealth
    DNS        []models.DNSEvent
    TLS        []models.TLSEvent
    HTTP       []models.HTTPEvent
    ICMP       []models.ICMPEvent
}
```

**`Parse(src PacketSource, cfg *Config) ParseResult`** is the main loop:
```go
for pkt := range src.Packets() {
    // 1. update RawStats (packet count, byte count, protocol histogram)
    // 2. ft.update(pkt)     — flow tracker
    // 3. ha.update(pkt)     — HTTP assembler (feeds TCP segments)
    // 4. extractDNS(pkt)    — stateless extractors append to result slices
    // 5. extractTLS(pkt)
    // 6. extractICMP(pkt)
}
result.Flows, result.FlowHealth = ft.results()
result.HTTP = ha.flush()   // drain reassembled HTTP streams
```

**`trackProtocol`** updates the protocol histogram by inspecting the network layer type. For non-IP frames (ARP, etc.) it falls back to the link layer type.

---

## 7. Flow tracker extractor

**Commit:** `424249c`
**Date:** 2026-03-27

### What
Filled in `internal/parser/flow.go` with the stateful flow tracker — the only component in the parser that maintains state across packets.

### Why
Every other event (DNS, TLS, HTTP, ICMP) carries a `FlowID` that links it to a flow. The flow tracker must therefore run first on every packet so that by the time the stateless extractors run, the flow already exists and its ID is derivable. It also drives the TCP state machine so the output captures connection lifecycle.

### Where
```
internal/parser/flow.go
```

### How

**`flowTracker`** maintains three maps keyed by flow ID:
- `flows map[string]*models.Flow` — the live flow state
- `health map[string]*models.FlowHealth` — anomaly counters (used by flow_health.go)
- `seqSeen map[string]map[uint32]bool` — set of TCP sequence numbers seen per flow (retransmit detection)

**`canonicalID`** is the key function that makes flows bidirectional. Given a 5-tuple, it always produces the same ID regardless of which direction a packet is travelling:
```go
a := "srcIP:srcPort"
b := "dstIP:dstPort"
if a <= b {
    return a + "-" + b + "-" + proto   // canonical form
}
return b + "-" + a + "-" + proto       // swap so smaller is always first
```
This means packet from A→B and packet from B→A both map to the same flow ID, correctly grouping both halves of a conversation.

**`nextTCPState`** drives a simple TCP state machine per flow:
```
RST flag → FlowStateRST
FIN flag → FlowStateFIN
SYN (no ACK) → FlowStateSYN
ACK (from SYN or UNKNOWN) → FlowStateEstablished
otherwise → keep current state
```

**`flowIDFromPacket`** is a helper used by all stateless extractors to derive the same canonical flow ID from a packet without having to call the tracker. This ensures DNS/TLS/HTTP/ICMP events always link to the same flow ID as the `flows.json` entries.

---

## 8. Flow health extractor

**Commit:** `186dc59`
**Date:** 2026-03-27

### What
Added `internal/parser/flow_health.go` — detects TCP anomalies per flow.

### Why
Flow health data is a primary signal for threat detection. Excessive retransmissions can indicate network issues or port scanning. Zero-window storms suggest a receiver being overwhelmed (a sign of DoS). RSTs indicate forcible connection teardowns. These signals feed directly into the enrichment layer's threat scoring in Phase 2.

### Where
```
internal/parser/flow_health.go   — updateHealth() method on flowTracker
```

### How

**`updateHealth(flowID string, tcp *layers.TCP)`** is called from `flowTracker.update()` for every TCP packet. It updates the `FlowHealth` record for the flow:

- **RST**: increments `RSTCount`, sets `Blocked = true` immediately. A RST always means the connection was refused or forcibly torn down.

- **Zero window** (`tcp.Window == 0 && tcp.ACK`): increments `ZeroWindowCount`. Sets `Blocked = true` if ≥ 3 zero-window segments are seen — this threshold avoids false positives from transient flow control.

- **Retransmission**: checks whether `tcp.Seq` has been seen before on this flow. If yes, increments `Retransmissions`. SYN and FIN packets are skipped because their sequence numbers are used differently in the TCP handshake and do not represent retransmitted data.

`Blocked = true` is the synthesised summary flag that the enrichment layer can use directly without needing to inspect individual counters.

---

## 9. DNS event extractor

**Commit:** `e3fde2d`
**Date:** 2026-03-27

### What
Filled in `internal/parser/dns.go` — extracts `DNSEvent` structs from packets that carry a DNS layer.

### Why
DNS is the most information-rich protocol for threat hunting. Domain lookups reveal C2 infrastructure, data exfiltration via DNS tunnelling, and malware beaconing patterns. Nearly every attack involves DNS at some stage. Capturing every query and response with its questions and answers enables the LangGraph agents to spot patterns like `NXDOMAIN` storms, fast-flux domains, or high-entropy subdomain lookups.

### Where
```
internal/parser/dns.go
internal/parser/flow.go    — added flowIDFromPacket helper (shared by all extractors)
```

### How

**`extractDNS(pkt)`** checks for `layers.LayerTypeDNS`. If present, it builds a `DNSEvent`:
- `dns.QR` (query/response bit) → `IsResponse`
- `dns.ID` → `QueryID` (ties queries to their responses)
- `dns.ResponseCode.String()` → `RCode` (`"NOERROR"`, `"NXDOMAIN"`, etc.)
- Iterates `dns.Questions` and `dns.Answers`

**`dnsRecordData`** formats the data field for each answer record type:
- `A` / `AAAA` → IP address string
- `CNAME` / `PTR` / `NS` → domain name string
- `MX` → `"priority name"` format
- `TXT` → space-joined strings
- `SOA` → `"mname rname serial=N"` format
- Unknown → `"(raw N bytes)"` so nothing is silently lost

---

## 10. TLS ClientHello extractor

**Commit:** `a887cb9`
**Date:** 2026-03-27

### What
Filled in `internal/parser/tls.go` — manually parses TLS ClientHello messages from raw TCP payloads.

### Why
The SNI (Server Name Indication) field in a TLS ClientHello reveals the destination hostname even for encrypted traffic. This is critical for threat hunting because HTTPS traffic can be inspected at the metadata level without decryption. The cipher suite list is also forensically valuable — old or weak suites indicate legacy clients or potential downgrade attacks.

**Why raw parsing instead of gopacket's TLS layer?** gopacket can detect that a TCP payload is TLS, but its TLS layer does not decode ClientHello internals (SNI, cipher suites, extensions). Manual parsing is necessary to extract these fields.

### Where
```
internal/parser/tls.go
```

### How

**`extractTLS(pkt)`** inspects the raw TCP payload:
1. Checks `p[0] == 0x16` (TLS record type: Handshake) and `p[1] == 0x03` (TLS major version)
2. Checks `p[5] == 0x01` (Handshake type: ClientHello)
3. If both match, begins manual field-by-field parsing of the ClientHello body:

```
ClientHello body layout (offset 9):
  [2]  legacy_version
  [32] random
  [1]  session_id_length
  [N]  session_id
  [2]  cipher_suites_length
  [N]  cipher_suites (2 bytes each)
  [1]  compression_methods_length
  [N]  compression_methods
  [2]  extensions_length
  [N]  extensions (type[2] + length[2] + data)
```

Extensions parsed:
- `0x0000` (server_name) → `parseSNI()` extracts the `host_name` entry
- `0x002b` (supported_versions) → `parseSupportedVersions()` extracts the list; the first entry overrides `legacy_version` since TLS 1.3 always reports `0x0303` in the legacy field

**`tlsCipherSuiteName`** maps known IANA cipher suite uint16 codes to their names. Includes all common TLS 1.2 suites, TLS 1.3 suites, and GREASE values. Unknown suites fall back to `"0x%04x"` — nothing is silently dropped.

---

## 11. HTTP extractor with TCP stream reassembly

**Commit:** `8dcb73b`
**Date:** 2026-03-27

### What
Filled in `internal/parser/http.go` — reassembles TCP streams and parses HTTP request/response pairs from them.

### Why
HTTP is the highest-value protocol for detecting web-based attacks (SQLi, command injection, credential theft, C2 over HTTP). However, HTTP cannot be extracted from individual packets — a single HTTP request may be split across many TCP segments. TCP stream reassembly is required first.

This is the most complex extractor in Phase 1.

### Where
```
internal/parser/http.go
internal/parser/pcap.go    — added ha.update(pkt) call to the main loop
```

### How

**Architecture** — three layers:

1. **`httpAssembler`** — the top-level stateful component. Wraps gopacket's `tcpassembly.Assembler`. Called once per packet via `ha.update(pkt)`. At end-of-capture, `ha.flush()` drains all incomplete streams and returns collected events.

2. **`httpStreamFactory`** — implements `tcpassembly.StreamFactory`. The assembler calls `New(netFlow, transport)` whenever it sees a new TCP stream. The factory creates an `httpStream` and launches it in its own goroutine. A `sync.WaitGroup` tracks all active streams so `flush()` can wait for all to finish.

3. **`httpStream`** — one goroutine per TCP half-connection. Reads reassembled bytes from a `tcpreader.ReaderStream` and feeds them into Go's standard `net/http` parser:
    - Streams to known HTTP ports (80, 8080, 8000, etc.) → `http.ReadRequest` loop
    - All other streams → `http.ReadResponse` loop

**Key decisions:**
- `isRequest` is determined at stream creation by checking the destination port against `httpPorts`. This correctly handles both sides of a connection.
- Body bytes are counted but discarded (`io.Copy(io.Discard, body)`) — sending raw body bytes to the LLM is explicitly prohibited by the project conventions.
- `http.ReadRequest` / `http.ReadResponse` are called in a `for` loop to handle HTTP/1.1 keep-alive connections where multiple requests flow over a single TCP connection.
- `flowID()` calls the same `canonicalID()` function as the flow tracker, ensuring HTTP events carry the same flow ID as the `flows.json` entries they correspond to.

---

## 12. ICMP event extractor

**Commit:** `92965c6`
**Date:** 2026-03-27

### What
Filled in `internal/parser/icmp.go` — extracts `ICMPEvent` from ICMPv4 and ICMPv6 packets.

### Why
ICMP is used in several attack patterns: ping sweeps (network discovery), ICMP tunnelling (covert channel), and TTL-based traceroutes (reconnaissance). Capturing type/code pairs with human-readable names makes these patterns visible in the output without requiring the analyst to look up ICMP type tables.

### Where
```
internal/parser/icmp.go
```

### How

**`extractICMP(pkt)`** checks for ICMPv4 first, then ICMPv6. gopacket exposes these as separate layer types (`LayerTypeICMPv4`, `LayerTypeICMPv6`), so both must be checked.

**`icmpv4TypeName(type, code)`** maps common type/code pairs to readable strings:
- Type 0 → `EchoReply`
- Type 3 → `DestUnreachable/HostUnreachable` etc. (code disambiguated)
- Type 8 → `EchoRequest`
- Type 11 → `TimeExceeded/TTLExceeded` or `TimeExceeded/FragReassembly`
- Unknown → `Unknown(type/code)` — nothing silently dropped

**`icmpv6TypeName`** handles the ICMPv6 equivalents including Neighbor Discovery messages (types 133–137) which are important for IPv6 network analysis.

---

## 13. JSON output writer + trim to 4 core sources

**Commit:** `16f2c20`
**Date:** 2026-03-27

### What
Two changes in one commit:
1. Added `internal/output/writer.go` — serialises a `ParseResult` to 8 JSON files
2. Trimmed the input source factory from 10 stubs to 4 real-ish stubs (`file`, `pcapng`, `live`, `pipe`)

### Why

**Output writer:** The parse pipeline is now complete. It needs a way to materialise results to disk so the CLI can be wired and humans can inspect the output. JSON is the natural format — it's human-readable, trivially consumed by the LangGraph Python agents, and self-describing.

**Source trim:** The original factory had 10 stubs (SSH, AF_PACKET, Zeek, S3, VPC flows, Kafka). After review, these are Phase 3+ concerns. Keeping 10 half-implemented stubs in the factory adds noise with no benefit. The 4 remaining sources (file, pcapng, live, pipe) cover all realistic Phase 1 and Phase 2 use cases.

### Where
```
internal/output/writer.go
internal/input/source.go   — factory trimmed to 4 cases
internal/input/live.go     — added Open() stub returning error
internal/input/pcapng.go   — added Open() stub returning error
internal/input/pipe.go     — added Open() stub returning error
```

### How

**`WriteJSON(result ParseResult, dir string) error`**:
1. Creates the output directory (`os.MkdirAll` — no error if already exists)
2. Iterates a static slice of `{name, data}` pairs
3. For each: marshals to indented JSON, writes to `dir/name`

Output files written:

| File | Contents |
|---|---|
| `meta.json` | Source type/description + `written_at` timestamp |
| `raw_stats.json` | Packet count, byte count, duration, protocol histogram |
| `flows.json` | All reconstructed TCP/UDP flows |
| `flow_health.json` | Per-flow anomaly counters |
| `dns.json` | All DNS query/response events |
| `tls.json` | All TLS ClientHello events (SNI, ciphers) |
| `http.json` | All reassembled HTTP request/response pairs |
| `icmp.json` | All ICMP/ICMPv6 events |

`meta.json` is wrapped in a `runMeta` envelope that adds `written_at` (UTC). This gives every output set an audit timestamp independent of the captured traffic timestamps.

---

## 14. Wire CLI end-to-end

**Commit:** `6e36e03`
**Date:** 2026-03-27

### What
Connected the `parse` cobra command to the real pipeline: `NewPacketSource → Open → Parse → WriteJSON`.

### Why
Steps 1–13 built all the components. This commit is the first moment the binary can be run against a real PCAP file and produce meaningful output. It's the integration point that proves all the pieces fit together.

### Where
```
cmd/forensics/main.go   — runParse() filled in
```

### How

**`runParse()`** orchestrates the pipeline in four stages:

```
1. config.Load(flagConfig)          → *Config
2. input.NewPacketSource(type, cfg) → PacketSource
3. src.Open() + defer src.Close()
4. parser.Parse(src, cfg)           → ParseResult
5. output.WriteJSON(result, dir)
```

Error handling uses `fmt.Errorf("context: %w", err)` at every call site — consistent with the project convention. The `%w` verb preserves the original error for `errors.Is`/`errors.As` callers.

`slog` structured logging is initialised with a `TextHandler` at `INFO` level. Every stage logs its start, completion, and key metrics (packet count, flow count, output dir). This makes progress visible on the terminal and provides a lightweight audit trail without requiring a log aggregator.

The `--output` flag value overrides `cfg.OutputDir` if provided, giving the CLI flag priority over the config file — the expected precedence order.

---

## 15. Refactor — remove dead helpers

**Commit:** `8aba240`
**Date:** 2026-03-27

### What
Removed unused helper functions from `pcap.go`, simplified ICMP formatting in `icmp.go`, and fixed a minor HTTP header issue.

### Why
After wiring the CLI end-to-end, a code review found several helpers that were written speculatively during the parser skeleton phase but were never called. Dead code increases cognitive overhead and can confuse future readers (and the LLM agents) about what is actually in use.

### Where
```
internal/parser/pcap.go   — removed unused helper(s)
internal/parser/icmp.go   — simplified type name formatting (removed redundant switch arm)
internal/parser/http.go   — minor header field fix
```

### How
The removals were straightforward — functions with no callers, identified by the Go compiler's unused-function detection and manual review. No behaviour changed; this is a pure dead-code removal.

---

## 16. Add gitignore + project docs + sample PCAP fixtures

**Commit:** `23aee9a`
**Date:** 2026-03-27

### What
Added a `.gitignore` entry for output files, project planning documents (`CLAUDE.md`, `PHASE1.md`, `PHASE2.md`, `PLANNING.md`, `ARCHITECTURE.md`), and a sample PCAP fixture file.

### Why
Planning documents capture the architectural reasoning and phase-by-phase build order — information that cannot be derived from the code alone. The sample PCAP is needed by the parser tests added in the next commit. The `.gitignore` update prevents accidental commits of generated `output/` files which can be large and are not source code.

### Where
```
.gitignore              — added /output/ exclusion
CLAUDE.md               — persistent project context for every Claude Code session
PHASE1.md               — 10-step Phase 1 checklist
PHASE2.md               — 13-step Phase 2 checklist
PLANNING.md             — high-level project roadmap
ARCHITECTURE.md         — system architecture notes
scripts/sample_pcaps/   — sample .pcap files for tests
```

---

## 17. Table-driven parser tests

**Commit:** `420e019`
**Date:** 2026-03-27

### What
Added table-driven tests for all parser components, plus a sample PCAP fixture (`chargen-tcp.pcap`).

### Why
All Phase 1 extractors were written and manually tested, but had no automated coverage. Table-driven tests are the Go idiomatic way to express "given this input, expect this output" across many cases in one test function. They also serve as living documentation of the expected behaviour of each extractor.

### Where
```
internal/parser/pcap_test.go
internal/parser/flow_test.go
internal/parser/flow_health_test.go
internal/parser/dns_test.go
internal/parser/tls_test.go
internal/parser/http_test.go
internal/parser/icmp_test.go
scripts/sample_pcaps/chargen-tcp.pcap
```

### How

**`pcap_test.go`** is the integration-level test. It runs `Parse()` against `chargen-tcp.pcap` and asserts:
- At least 1 flow was detected
- `TotalPackets > 0`
- `TotalBytes > 0`
- `StartTime` is before `EndTime`

This proves the full pipeline works end-to-end on a real file.

**`flow_test.go`** tests `canonicalID` directly — the most important correctness property is that the same two endpoints always produce the same ID regardless of packet direction. Bidirectional pairs are explicitly in the test table.

**`flow_health_test.go`** drives the `flowTracker` with synthetic TCP packets (constructed with `layers.TCP`) to verify:
- A RST packet triggers `RSTCount++` and `Blocked = true`
- A repeated sequence number triggers `Retransmissions++`
- Three zero-window packets trigger `Blocked = true`

**Protocol extractor tests** (`dns_test.go`, `tls_test.go`, `http_test.go`, `icmp_test.go`) assert that extractors return `nil` for packets that do not carry the relevant protocol — preventing false positive events.

---

## 18. Implement live, pipe, and pcapng sources

**Commit:** `6e096b6`
**Date:** 2026-03-27

### What
Replaced the stub implementations for `LiveSource`, `PipeSource`, and `PCAPNGSource` with full working adapters.

### Why
The CLI is wired and tests pass. These three sources are the most useful beyond PCAP file: live capture for real-time monitoring, pipe for integration with `tcpdump`, and pcapng for modern capture tools (Wireshark, tshark). All three are needed to make the binary genuinely useful before moving to Phase 2.

### Where
```
internal/input/live.go
internal/input/pipe.go
internal/input/pcapng.go
```

### How

**`LiveSource`** (`live.go`):
- Calls `pcap.OpenLive(interface, snapLen, promiscuous, pcap.BlockForever)`
- `snapLen = 65535` — captures the full packet (no truncation)
- `promiscuous = true` — captures all traffic on the interface, not just traffic addressed to this host
- `pcap.BlockForever` — the read call never times out; `Close()` is the only way to stop it
- Channel buffer is `1000` (vs `100` for file) — live traffic can burst faster than the parser can process

Unlike file sources, the live source channel **never closes on its own**. The consumer (CLI) must call `Close()` which internally closes the pcap handle, causing the background `src.Packets()` loop to return an error and exit, which then triggers `defer close(s.packets)`.

**`PCAPNGSource`** (`pcapng.go`):
- Identical to `PCAPFileSource` in implementation
- `pcap.OpenOffline()` auto-detects pcap vs pcapng format — gopacket handles both
- The distinction exists purely at the `SourceType` level for accurate metadata reporting

**`PipeSource`** (`pipe.go`):
- If `FilePath == ""`, reads from `os.Stdin` — enables `tcpdump -i eth0 -w - | forensics parse --input pipe`
- If `FilePath != ""`, opens a named pipe or regular file
- Uses `pcap.OpenOfflineFile(*os.File)` — the libpcap variant that accepts an `io.Reader` rather than a path
- `os.Stdin` is never closed (it is not owned by the source); other files are closed in `Close()`

---

## 19. Input source tests

**Commit:** `1e396e5`
**Date:** 2026-03-27

### What
Added unit/integration tests for the three new input source adapters.

### Why
The three sources cover distinct code paths and failure modes. Tests catch regressions when the source interface or underlying library changes, and verify each source handles the error cases (missing file, empty interface name) without panicking.

### Where
```
internal/input/pcapng_test.go
internal/input/live_test.go
internal/input/pipe_test.go
```

### How

**`pcapng_test.go`** verifies:
- `newPCAPNGSource` requires a non-empty `FilePath`
- `Open()` fails gracefully for a non-existent file
- `Open()` succeeds against `chargen-tcp.pcap` (pcap format — gopacket accepts it via the pcapng source since `OpenOffline` auto-detects)
- At least one packet is emitted on the channel

**`live_test.go`** verifies:
- `newLiveSource` requires a non-empty `Interface`
- Opening a non-existent interface returns an error (not a panic)
- The test skips opening a real interface since CI environments typically have no permission to do so

**`pipe_test.go`** verifies:
- `newPipeSource` succeeds even with no config (stdin is the default)
- Opening a non-existent named pipe returns an error
- Piping from `chargen-tcp.pcap` via a file reader emits packets correctly

---

## 21. GeoIP enrichment via MaxMind GeoLite2

**Date:** 2026-04-02

### What
Added `internal/enrichment/geoip.go` — `GeoIPEnricher` wraps two optional MaxMind GeoLite2 databases (City + ASN) and exposes a single `Lookup(ip) *GeoInfo` call.

### Why
GeoIP is the first enrichment signal added to a flow — it tells you where traffic is going geographically. Knowing that a connection is to an IP in a country you don't operate in, or in an ASN associated with hosting providers commonly used for C2, is a fast triage signal without any external API call.

---

## 22. IOC matcher — local blocklist for IPs, domains, and hashes

**Date:** 2026-04-02

### What
Added `internal/enrichment/ioc.go` — `IOCMatcher` loads flat blocklist files into memory and exposes `MatchIP`, `MatchDomain`, and `MatchHash` lookups.

### Why
IOC matching is the fastest and cheapest threat signal: no network call, no external dependency, sub-microsecond lookup. Loading blocklists from public feeds (Feodo Tracker, abuse.ch) at startup means every IP and domain in a parsed PCAP is instantly checked against known malicious infrastructure without waiting on an API.

---

## 23. Shannon entropy scorer for payload analysis

**Date:** 2026-04-02

### What
Added `internal/enrichment/entropy.go` — a pure `Shannon([]byte) float64` function plus a stateful `EntropyScorer` that accumulates payload bytes per flow and returns per-flow entropy scores.

### Why
Encrypted and packed traffic looks statistically random — high entropy is the defining characteristic. Shannon entropy gives a single number (0–8 bits/byte) that instantly separates plaintext from encrypted/packed payloads.

---

## 24. Beacon detector for C2 heartbeat pattern detection

**Date:** 2026-04-02

### What
Added `internal/enrichment/beacon.go` — `BeaconDetector` accumulates per-packet timestamps per flow and flags flows whose inter-arrival time coefficient of variation (CV = stddev/mean) falls below a configurable threshold (0.1).

### Why
C2 malware typically phones home on a fixed schedule. Unlike human-driven traffic, automated beaconing has extremely low jitter. This signal is effective even against encrypted traffic as it operates only on timestamps.

---

## 25. Threat intel enrichment — VirusTotal + AbuseIPDB

**Date:** 2026-04-03

### What
Added `internal/enrichment/threatintel.go` — `ThreatIntelEnricher` queries VirusTotal and AbuseIPDB concurrently, caches results in a TTL map, and applies per-API rate limiting.

### Why
Local IOC lists catch known-bad indicators, but threat intel APIs add real-time intelligence from the broader security community. VirusTotal aggregates 70+ antivirus engines; AbuseIPDB is the canonical source for crowd-reported malicious IPs.

---

## 26. Wire enrichment pipeline

**Date:** 2026-04-03

### What
Added `internal/enrichment/pipeline.go` — `Enrich()` function that wires all six enrichers (GeoIP, IOC, Entropy, Beacon, Threat Intel) into a single call.

### Why
Connects independent enrichers so a single call returns a fully annotated `EnrichedResult`. The parser was also updated to expose per-flow payload bytes and packet timestamps.

---

## 28. PostgreSQL store for enriched findings

**Date:** 2026-04-03

### What
Implemented `internal/store/postgres.go` using GORM. Defined database models for flows, events (DNS, TLS, HTTP, ICMP), and enriched data in `internal/models/`. Updated the pipeline to persist results to PostgreSQL when enabled in `config.yaml`.

### Why
Transitions the system from purely ephemeral in-memory storage to a persistent, distributed store. This is required for audit trails, cross-job correlation, and to allow multiple LangGraph agents to access shared forensics history.

---

## 29. Integrate enrichment and API into CLI

**Date:** 2026-04-03

### What
Updated `cmd/forensics/main.go` to run the enrichment pipeline by default and added a `--serve` flag to start the HTTP API server after parsing.

### Why
Finalizes the Phase 2 Go-side implementation, making enrichment and the API server accessible via the primary CLI tool.

## Phase 2 — Summary

At the end of Phase 2 (Go-side), the binary:

1. **Enriches every flow and protocol event** with:
   - **GeoIP & ASN** (MaxMind)
   - **IOC Match** (Local blocklists)
   - **Entropy score** (Payload analysis)
   - **Beaconing indicators** (C2 heartbeat detection)
   - **Threat Intel scores** (VirusTotal & AbuseIPDB)
2. **Exposes a REST API** on port 8765 for agent tool calls.
3. **Supports a `--serve` flag** for immediate API access after parsing.
4. **Maintains backward compatibility** with Phase 1 raw JSON output.

The enrichment layer is now ready to support the LangGraph agents in Phase 3.

---

## Phase 1 — Summary
4. **Logs structured output** via `slog` at every stage
5. **Has table-driven tests** covering all extractors and input adapters

The entire parser and output layer is agnostic to the input source — the `PacketSource` interface is the only seam between them.

---

---

# Phase 2 — Enrichment Pipeline

---

## 20. Enriched models — ThreatContext, GeoInfo, IOCMatch, EnrichedFlow

**Commit:** TBD (Phase 2, Step 1)
**Date:** 2026-04-02

### What
Added `internal/models/enriched.go` — all the output shapes the enrichment layer produces.
Added `internal/models/enriched_test.go` — JSON round-trip and omitempty tests for every type.

No logic. Pure struct and constant definitions.

### Why
The same reason core models were defined before any parser logic in Phase 1: every enricher written in Steps 2–6 needs a stable type to compile against. Defining the shapes first forces an explicit answer to design questions like "what do I want to know about a threat context?" before writing a single line of lookup logic.

**Why not put `EnrichedResult` here too?**
`EnrichedResult` (the top-level output of the enrichment pipeline, analogous to `ParseResult`) needs `input.SourceMeta` and `parser.RawStats`. Since `parser` already imports `models`, putting `EnrichedResult` in `models` would create a circular import. It will be defined in the `enrichment` package in Step 7 when the pipeline is wired.

### Where
```
internal/models/enriched.go       — new types and constants
internal/models/enriched_test.go  — 10 tests
```

### How

**`GeoInfo`** — geographic + network metadata for one IP address. Fields populated by MaxMind GeoLite2 in Step 2:
```
IP, CountryCode, CountryName, City, Latitude, Longitude, ASN, ASNOrg
```

**`IOCType`** / **`IOCSeverity`** — typed string constants, not bare strings. This prevents mismatches like `"IP"` vs `"ip"` at call sites. JSON serialises to lowercase (`"ip"`, `"domain"`, `"hash"`, `"low"` … `"critical"`).

**`IOCMatch`** — a single hit against the local blocklist. Carries `Source` (which feed it came from: `"feodo-tracker"`, `"abuse.ch"`, `"custom"`) and optional `Tags` (omitted from JSON when empty via `omitempty`).

**`ThreatIntelResult`** — the response from one external API call. `Score` is intentionally generic (VirusTotal: positives count; AbuseIPDB: confidence score 0–100). `LastReportedAt` is `omitempty` because not all APIs return this field.

**`ThreatContext`** — the aggregation type. One `ThreatContext` per unique IP or domain. Holds:
- `*GeoInfo` — pointer so nil serialises as absent (not `{}`)
- `[]IOCMatch` — local blocklist hits
- `[]ThreatIntelResult` — external API results
- `IsMalicious bool` — synthesised summary flag (any hit → true)
- `ThreatScore int` — 0–100 risk score computed by the pipeline in Step 7

**`EnrichedFlow`** — the central enriched type. Wraps `Flow` + `*FlowHealth` (already collected by the parser) and adds:
- `SrcThreat` / `DstThreat` — one `ThreatContext` per endpoint IP
- `EntropyScore float64` — Shannon entropy of the TCP/UDP payload (0–8 bits/byte); high values (>7.2) indicate encryption or packing. Populated in Step 4.
- `IsBeacon bool` + `BeaconInterval float64` + `BeaconJitter float64` — C2 heartbeat pattern results from Step 5

**`EnrichedDNSEvent`** — wraps `DNSEvent` + `[]ThreatContext` for each queried domain (a query can contain multiple questions).

**`EnrichedTLSEvent`** — wraps `TLSEvent` + `*ThreatContext` for the SNI hostname.

**`EnrichedHTTPEvent`** — wraps `HTTPEvent` + `*ThreatContext` for the `Host` header value.

**`EnrichedICMPEvent`** — wraps `ICMPEvent` + src/dst `*ThreatContext`. ICMP scans are a common recon technique so threat context on both endpoints is valuable.

**Tests** cover:
- Full JSON marshal → unmarshal round-trip for `ThreatContext` and `EnrichedFlow` with all fields populated
- `omitempty` correctness: nil pointer fields (`Geo`, `SrcThreat`, `DstThreat`, `FlowHealth`, `SNIThreat`, `HostThreat`) and zero-value float fields (`BeaconInterval`, `BeaconJitter`) must not appear in JSON output
- All `IOCType` and `IOCSeverity` constants serialise to the expected lowercase strings

---

## 21. GeoIP enrichment via MaxMind GeoLite2

**Commit:** TBD (Phase 2, Step 2)
**Date:** 2026-04-02

### What
Added `internal/enrichment/geoip.go` — `GeoIPEnricher` wraps two optional MaxMind GeoLite2 databases (City + ASN) and exposes a single `Lookup(ip) *GeoInfo` call.

Added `internal/enrichment/geoip_test.go` — 7 tests (5 pass always, 2 skip unless real DBs are present).

Extended `config/config.go` and `config/config.yaml` with a `geoip` section (`city_db_path`, `asn_db_path`) and two new env var overrides (`MAXMIND_DB_PATH`, `MAXMIND_ASN_DB_PATH`).

Added dependency: `github.com/oschwald/geoip2-golang v1.13.0`.

### Why
GeoIP is the first enrichment signal added to a flow — it tells you where traffic is going geographically. Knowing that a connection is to an IP in a country you don't operate in, or in an ASN associated with hosting providers commonly used for C2, is a fast triage signal without any external API call.

**Why two separate databases?**
MaxMind publishes City and ASN data as separate `.mmdb` files. The City DB has no ASN fields and the ASN DB has no geo fields — you need both to get the full picture. Both are optional: if only one is configured, the other's fields are silently zero-valued in the result.

**Why not return an error from `Lookup`?**
Individual lookup failures (e.g. IP not in the database) are non-fatal and expected — private IPs, new allocations, and internal addresses all miss. Returning an error would force every caller to handle it for a near-guaranteed non-event. Instead, failures are logged at `DEBUG` and a partial result is returned. The caller gets what the DB knows; silence is not a bug.

**Why short-circuit private IPs?**
MaxMind databases contain no data for RFC1918, loopback, link-local, or unspecified addresses. Querying them would return an error or empty record every time. Short-circuiting avoids the log noise and the DB round-trip for traffic that will never have geo data.

### Where
```
internal/enrichment/geoip.go       — GeoIPEnricher, isPrivateIP helper
internal/enrichment/geoip_test.go  — 7 tests
config/config.go                   — GeoIPConfig struct, added to Config, env overrides
config/config.yaml                 — geoip section with default paths
go.mod / go.sum                    — geoip2-golang v1.13.0, maxminddb-golang v1.13.0
```

### How

**`GeoIPEnricher`** holds two `*geoip2.Reader` pointers, either of which can be nil:
```go
type GeoIPEnricher struct {
    city *geoip2.Reader  // nil if CityDBPath was empty
    asn  *geoip2.Reader  // nil if ASNDBPath was empty
}
```

**`NewGeoIPEnricher(cityDBPath, asnDBPath string)`** requires at least one non-empty path. Each path is opened independently; a failure on one does not affect the other.

**`Lookup(ip net.IP) *models.GeoInfo`**:
1. Always sets `info.IP = ip.String()`
2. Returns immediately for private IPs (no DB query)
3. If `e.city != nil`, calls `city.City(ip)` — fills CountryCode, CountryName, City, Latitude, Longitude
4. If `e.asn != nil`, calls `asn.ASN(ip)` — fills ASN, ASNOrg
5. Per-lookup errors are debug-logged, never propagated

**`isPrivateIP`** iterates a hardcoded list of private CIDRs (RFC1918, loopback, link-local, IPv6 equivalents) and checks `network.Contains(ip)`. Returns true for `ip.IsUnspecified()` (0.0.0.0 / `::`) as well.

**Tests:**
- `TestNewGeoIPEnricher_NoPaths` — both paths empty → error
- `TestNewGeoIPEnricher_MissingCityFile` — non-existent path → error
- `TestNewGeoIPEnricher_MissingASNFile` — non-existent path → error
- `TestIsPrivateIP` — 14 cases: 10 private (RFC1918, loopback, link-local, IPv6), 4 public
- `TestLookup_PrivateIP_ReturnsStubbedResult` — zero `GeoIPEnricher` (both DBs nil); private IPs return result with only `IP` set, no country/ASN fields
- `TestLookup_PublicIP_WithRealDB` — skipped unless `MAXMIND_DB_PATH` env var is set; verifies 8.8.8.8 → CountryCode "US"
- `TestLookup_ASN_WithRealDB` — skipped unless `MAXMIND_ASN_DB_PATH` is set; verifies 8.8.8.8 → non-zero ASN

---

## 22. IOC matcher — local blocklist for IPs, domains, and hashes

**Commit:** TBD (Phase 2, Step 3)
**Date:** 2026-04-02

### What
Added `internal/enrichment/ioc.go` — `IOCMatcher` loads flat blocklist files into memory and exposes `MatchIP`, `MatchDomain`, and `MatchHash` lookups.

Added `internal/enrichment/ioc_test.go` — 15 tests covering all match paths, edge cases, and error handling.

Extended `config/config.go` with `IOCSourceConfig` and `IOCConfig`, and `config/config.yaml` with default Feodo Tracker + abuse.ch source entries.

### Why
IOC matching is the fastest and cheapest threat signal: no network call, no external dependency, sub-microsecond lookup. Loading blocklists from public feeds (Feodo Tracker, abuse.ch) at startup means every IP and domain in a parsed PCAP is instantly checked against known malicious infrastructure without waiting on an API.

**Why plain flat files instead of a database?**
Public IOC feeds publish as plain text (one indicator per line). Parsing them directly avoids a schema migration every time a new feed is added. The in-memory map gives O(1) lookups — the overhead of loading even a 100k-entry feed at startup is milliseconds.

**Why does a missing file produce a warning instead of an error?**
A brand-new deployment may not have every feed downloaded yet. Failing hard would prevent the binary from running at all. A warning lets the operator know the file is absent without blocking the rest of the pipeline.

**Why is inline comment stripping needed?**
Several public feeds embed metadata inline (e.g. `1.2.3.4 # Emotet C2`). Without stripping, the entire line including the comment becomes the indicator and every lookup misses.

**Why support CIDR ranges?**
Several IP blocklists include /24 or /16 entries for entire malicious hosting ranges. CIDR support means those feeds work without pre-expansion. CIDRs are stored in a separate slice because they require `network.Contains(ip)` rather than a map key lookup — but in practice there are very few CIDRs in typical feeds, so the linear scan is negligible.

### Where
```
internal/enrichment/ioc.go       — IOCMatcher, cidrEntry
internal/enrichment/ioc_test.go  — 15 tests
config/config.go                 — IOCSourceConfig, IOCConfig, added to Config
config/config.yaml               — ioc.sources with two default feed entries
```

### How

**`IOCMatcher`** holds three maps and a CIDR slice:
```
ips     map[string][]IOCMatch  — key: normalised IP string ("1.2.3.4")
cidrs   []cidrEntry            — CIDR ranges, checked linearly
domains map[string][]IOCMatch  — key: lowercase domain, trailing dot stripped
hashes  map[string][]IOCMatch  — key: lowercase hex string
```

Each map value is a `[]IOCMatch` (not a single entry) because the same indicator can appear in multiple feeds with different source/severity metadata — all hits are returned.

**`LoadFile(path, source, iocType, severity)`**:
1. Opens the file; missing files log a warning and return `nil` (not an error)
2. Scans line by line via `bufio.Scanner`
3. Strips inline `# comments` and trims whitespace
4. Dispatches to `addIP`, `addDomain`, or `addHash` based on `iocType`

**`addIP`** detects CIDRs by checking for `/`. Valid CIDRs go to `m.cidrs`; plain IPs are normalised via `net.ParseIP(raw).String()` (so `1.02.3.4` and `1.2.3.4` map to the same key). Invalid values are debug-logged and skipped.

**`addDomain`** lowercases and strips the trailing dot (DNS responses often include it). **`addHash`** lowercases the hex string.

**`MatchIP(ip)`** checks the exact map first, then iterates `m.cidrs`. Both result slices are appended so callers see all sources that matched.

**`MatchDomain(domain)`** / **`MatchHash(hash)`** normalise the input the same way as `add*` and do a single map lookup.

**Tests** (15, all pass without any external files):
- `TestLoadFile_MissingFile_IsWarningNotError` — non-existent path returns nil error, zero entries
- `TestLoadFile_CommentsAndBlankLines` — `#` lines, blank lines, inline comments all filtered; 3 IPs loaded from 6-line file
- `TestMatchIP_ExactHit` — loaded IP matches with correct source/severity/type
- `TestMatchIP_Miss` — unloaded IP returns empty slice
- `TestMatchIP_CIDR` — /24 range: 2 addresses inside hit, 2 outside miss
- `TestMatchIP_InvalidEntriesSkipped` — `"not-an-ip"` and `"also-bad/32"` skipped; only valid entry loaded
- `TestMatchDomain_Hit` — exact domain match
- `TestMatchDomain_CaseInsensitive` — `"Evil.Example.COM"` matches `"evil.example.com"` queries
- `TestMatchDomain_TrailingDotStripped` — `"c2.example.com."` matches `"c2.example.com"` entry
- `TestMatchDomain_Miss` — non-matching domain returns empty slice
- `TestMatchHash_Hit` — uppercase hash in file matches lowercase query
- `TestMatchHash_Miss` — non-matching hash returns empty slice
- `TestMatchIP_MultipleSources` — same IP loaded from two feeds; both `IOCMatch` entries returned
- `TestCounts` — verifies `Counts()` returns correct totals across types

---

## 23. Shannon entropy scorer for payload analysis

**Commit:** TBD (Phase 2, Step 4)
**Date:** 2026-04-02

### What
Added `internal/enrichment/entropy.go` — a pure `Shannon([]byte) float64` function plus a stateful `EntropyScorer` that accumulates payload bytes per flow and returns per-flow entropy scores.

Added `internal/enrichment/entropy_test.go` — 16 tests covering the math, edge cases, and accumulator behaviour.

### Why
Encrypted and packed traffic looks statistically random — high entropy is the defining characteristic. Shannon entropy gives a single number (0–8 bits/byte) that instantly separates:
- **Plaintext** (HTTP, DNS responses, uncompressed data) ≈ 4–5 bits/byte
- **Compressed** (gzip, deflate) ≈ 6–7 bits/byte
- **Encrypted / packed** (TLS payload, malware packer output, AES) ≥ 7.5 bits/byte

A flow scoring above `HighEntropyThreshold` (7.2) without a known TLS ClientHello is a suspicious signal — it may be encrypted C2, a custom protocol, or packed malware transferring over a non-standard port.

**Why 7.2 as the threshold?**
At 7.2 bits/byte the false-positive rate against legitimate compressed traffic (gzip HTTP responses) is low, while AES ciphertext reliably exceeds it. The threshold is a named constant so it can be tuned without hunting for magic numbers.

**Why decouple from gopacket?**
`Update(flowID string, payload []byte)` takes the already-extracted bytes rather than a raw `gopacket.Packet`. The caller (the parse loop or enrichment pipeline in Step 7) is responsible for extracting the transport payload. This keeps `entropy.go` a pure computation module with no external dependencies — easier to test and reuse.

**Why cap at `DefaultMaxSampleBytes` (4 KB)?**
For entropy estimation, a few KB is more than enough — Shannon entropy converges quickly. Accumulating the full multi-MB payload of a large file transfer would waste memory with no accuracy gain. The cap also means memory usage is bounded to `4096 × number_of_active_flows`.

### Where
```
internal/enrichment/entropy.go       — Shannon, IsHighEntropy, EntropyScorer
internal/enrichment/entropy_test.go  — 16 tests
```

### How

**`Shannon(data []byte) float64`**:
1. Counts byte frequencies into a `[256]int` array (one pass, O(n))
2. Computes `H = -Σ p(b) * log₂(p(b))` over all 256 possible byte values
3. Zero-count bytes contribute 0 (skipped to avoid `log2(0)`)

Result is exact for the input distribution. An all-same-byte input gives exactly 0. All 256 bytes equally present gives exactly 8.0.

**`EntropyScorer`** state:
```
samples   map[string][]byte   // flowID → accumulated bytes
maxSample int                 // cap per flow (default 4096)
```

**`Update(flowID, payload)`**:
- Ignores empty flowID or empty payload
- Computes `remaining = maxSample - len(current_sample)`; if ≤ 0, returns immediately
- Appends at most `remaining` bytes — prevents both over-allocation and partial writes past the cap

**`Score(flowID)`** — calls `Shannon(samples[flowID])`; returns 0 for unknown flows.

**`Scores()`** — iterates the map and scores every flow. Used by the pipeline in Step 7 to populate `EnrichedFlow.EntropyScore`.

**Tests:**
- `TestShannon_Empty` — nil and empty slice both return 0
- `TestShannon_SingleByte` — 100× the same byte → entropy 0
- `TestShannon_TwoEqualValues` — 50/50 split → entropy 1.0 (verified within 0.001)
- `TestShannon_AllBytes_MaxEntropy` — 256 distinct bytes → entropy 8.0 (within 0.0001)
- `TestShannon_Plaintext_LowEntropy` — English text → score in [3.5, 5.5]
- `TestShannon_HighEntropy_LooksEncrypted` — LCG pseudo-random bytes → score ≥ 7.5
- `TestIsHighEntropy` — 6 threshold boundary cases including exactly 7.2
- `TestEntropyScorer_DefaultMaxSample` — passing 0 to constructor uses DefaultMaxSampleBytes
- `TestEntropyScorer_Update_AccumulatesPayload` — two Updates produce non-zero score
- `TestEntropyScorer_Update_EmptyFlowIDIgnored` — no entry created for `""`
- `TestEntropyScorer_Update_EmptyPayloadIgnored` — nil and empty slice produce no entry
- `TestEntropyScorer_Update_CapsAtMaxSample` — buffer never exceeds maxSample bytes
- `TestEntropyScorer_Update_StopsAfterCapReached` — second update after full cap is ignored
- `TestEntropyScorer_Score_UnknownFlow` — unknown flowID returns 0
- `TestEntropyScorer_Scores_MultipleFlows` — two flows with different payloads scored independently
- `TestEntropyScorer_HighEntropyFlow_DetectedCorrectly` — pseudo-random payload triggers `IsHighEntropy`

---

## 24. Beacon detector for C2 heartbeat pattern detection

**Commit:** TBD (Phase 2, Step 5)
**Date:** 2026-04-02

### What
Added `internal/enrichment/beacon.go` — `BeaconDetector` accumulates per-packet timestamps per flow and flags flows whose inter-arrival time coefficient of variation (CV = stddev/mean) falls below a configurable threshold.

Added `internal/enrichment/beacon_test.go` — 14 tests with synthetic timestamp sequences.

### Why
C2 malware typically phones home on a fixed schedule (every 30s, 60s, 5 minutes). Unlike human-driven traffic where inter-arrival times are highly variable, automated beaconing has extremely low jitter. The coefficient of variation captures this: a perfect 30-second heartbeat has CV = 0; human browsing has CV >> 1.

This signal is effective even against encrypted traffic — it operates only on timestamps, not on packet content.

**Why CV < 0.1 as the threshold?**
A CV of 0.1 means the standard deviation is 10% of the mean interval. Real C2 frameworks (Cobalt Strike, Metasploit handlers) add configurable jitter to evade exactly this detection. At 0.1, we catch low/no-jitter beacons while avoiding false positives from periodic system processes.

**Why require a minimum interval (default 1s)?**
TCP operates below the second scale for ACKs, window probes, and retransmissions. Without a floor, every TCP flow looks like a perfect beacon. `DefaultMinBeaconInterval = 1s` filters this housekeeping traffic out entirely.

**Why require a minimum packet count (default 5)?**
Two packets have exactly one IAT — you cannot compute a meaningful standard deviation from one number. Five packets give four IATs, which is the practical minimum for a CV that won't be wildly skewed by a single outlier.

**Why population stddev instead of sample stddev?**
We're characterising the observed jitter in the captured traffic, not estimating a population parameter. Population stddev (divide by n) is the correct measure for "how regular is this specific set of inter-arrival times?"

### Where
```
internal/enrichment/beacon.go       — BeaconDetector, BeaconResult, iatMean, iatStddev
internal/enrichment/beacon_test.go  — 14 tests
```

### How

**`BeaconDetector`** state:
```
timestamps   map[string][]time.Time   // flowID → packet timestamps
minPackets   int                      // minimum timestamps required (default 5)
maxJitter    float64                  // CV threshold (default 0.1)
minInterval  time.Duration            // minimum mean IAT (default 1s)
```

**`Update(flowID, ts)`** appends `ts` to the slice for `flowID`. Empty flowID is ignored.

**`analyze([]time.Time)`** — the core computation:
1. Return zero `BeaconResult` if fewer than `minPackets` timestamps
2. Defensive sort by timestamp (guards against minor PCAP reordering)
3. Compute IATs: `iats[i] = sorted[i+1] - sorted[i]` in seconds
4. Compute mean IAT; return early (not a beacon) if `mean == 0 || mean < minInterval`
5. Compute population stddev; compute `CV = stddev / mean`
6. Return `BeaconResult{IsBeacon: CV <= maxJitter, Interval: mean, Jitter: CV}`

**`Results()`** calls `analyze` on every flow and returns `map[string]BeaconResult`. Used by the enrichment pipeline in Step 7 to populate `EnrichedFlow.IsBeacon`, `BeaconInterval`, `BeaconJitter`.

**`makeTimestamps` test helper** generates deterministic timestamp sequences with configurable interval and per-packet jitter fractions — avoids time.Now() non-determinism in tests.

**Tests:**
- `TestNewBeaconDetector_Defaults` — 0 args produce correct defaults
- `TestAnalyze_TooFewPackets_NoBeacon` — 4 timestamps (< 5 min) → zero result
- `TestAnalyze_UnknownFlow_ZeroResult` — unknown flowID → zero result
- `TestAnalyze_PerfectBeacon` — 10× perfect 30s interval → IsBeacon true, Interval 30.0, Jitter 0
- `TestAnalyze_LowJitter_IsBeacon` — ±5% jitter around 60s → IsBeacon true
- `TestAnalyze_HighJitter_NotBeacon` — ±50–150% jitter → IsBeacon false
- `TestAnalyze_BelowMinInterval_NotBeacon` — 1ms interval → IsBeacon false, Interval still set
- `TestUpdate_EmptyFlowID_Ignored` — empty flowID → no map entry created
- `TestAnalyze_UnsortedTimestamps` — shuffled perfect beacon → IsBeacon true (sort corrects order)
- `TestResults_MultipleFlows` — beacon + noisy flow both scored correctly
- `TestIatMean` — nil/empty/single/multi cases
- `TestIatStddev` — known result: `[2,4,4,4,5,5,7,9]` → stddev 2.0
- `TestIatStddev_Uniform_IsZero` — all same value → stddev 0
- `TestIatStddev_Empty` — nil → 0

---

## 25. Threat intel enrichment — VirusTotal + AbuseIPDB

**Commit:** TBD (Phase 2, Step 6)
**Date:** 2026-04-02

### What
Added `internal/enrichment/threatintel.go` — `ThreatIntelEnricher` queries VirusTotal and AbuseIPDB concurrently, caches results in a TTL map, and applies per-API rate limiting.

Added `internal/enrichment/threatintel_test.go` — 16 tests using `httptest.Server` mocks; no real API keys required.

Extended `config/config.go` with `ThreatIntelConfig` (cache TTL, HTTP timeout) and env var overrides for `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY`. Added `threat_intel` defaults to `config.yaml`.

Added dependency: `golang.org/x/time v0.15.0` (for `rate.Limiter`).

### Why
Local IOC lists catch known-bad indicators, but threat intel APIs add real-time intelligence from the broader security community. VirusTotal aggregates 70+ antivirus engines; AbuseIPDB is the canonical source for crowd-reported malicious IPs. Together they provide confidence scores that the LangGraph agents can reason about.

**Why async concurrent calls?**
Both APIs are independent — there is no reason to wait for VT before starting AbuseIPDB. Goroutines with a `sync.WaitGroup` parallelise the calls, cutting latency roughly in half for IPs that get checked by both.

**Why `golang.org/x/time/rate` over a DIY limiter?**
`rate.Limiter.Wait(ctx)` is context-aware — it returns immediately if the context is cancelled rather than sleeping past the deadline. This is critical: if the user hits Ctrl-C mid-enrichment, the rate limiter unblocks immediately instead of holding goroutines open.

**Why `rate.Every(15*time.Second)` for VirusTotal?**
VT free tier is 4 requests/minute = 1 per 15 seconds. Using `rate.NewLimiter(rate.Every(15*time.Second), 4)` gives a burst of 4 (use them all at once at startup) then refills at 1 per 15s — correct behaviour for a short-burst forensic session.

**Why in-memory TTL cache instead of Redis (which is Step 10)?**
Redis isn't running yet and won't be until Step 10. The TTL cache provides the same "don't re-query the same IP" guarantee within a session. The cache is also thread-safe (`sync.RWMutex`) for use with concurrent `Enrich` calls from `EnrichBatch`.

**Why skip AbuseIPDB for domains?**
AbuseIPDB only accepts IP addresses. Querying a domain would return a 422 error. The `isIP` check before launching the AbuseIPDB goroutine eliminates this error class entirely.

**Why `vtMaliciousThreshold = 3`?**
A single engine flagging an IP is common for new/uncommon IPs (false positive from heuristic scanners). Requiring at least 3 engines reduces noise while still catching genuinely malicious indicators.

### Where
```
internal/enrichment/threatintel.go       — ThreatIntelEnricher, ttlCache, vtResponse, aipResponse
internal/enrichment/threatintel_test.go  — 16 tests
config/config.go                         — ThreatIntelConfig, env overrides
config/config.yaml                       — threat_intel section with defaults
go.mod / go.sum                          — golang.org/x/time v0.15.0
```

### How

**`ttlCache`** — `sync.RWMutex`-protected `map[string]cacheEntry`. Read path acquires `RLock` (non-blocking for concurrent readers). Write path acquires full `Lock`. Expired entries are detected at read time (lazy eviction) — no background goroutine needed for a forensics session cache.

**`ThreatIntelEnricher`** fields:
```
cache       *ttlCache
httpClient  *http.Client       // shared, with configured Timeout
vtLimiter   *rate.Limiter      // 4/min, burst 4
aipLimiter  *rate.Limiter      // ~1/86s, burst 10
vtBaseURL   string             // overrideable for tests
aipBaseURL  string             // overrideable for tests
```

**`Enrich(ctx, indicator)`** flow:
1. Skip private IPs immediately
2. Cache hit → return cached results
3. Launch VT goroutine (if key configured): `vtLimiter.Wait(ctx)` → `queryVirusTotal`
4. Launch AbuseIPDB goroutine (if key configured AND indicator is an IP): `aipLimiter.Wait(ctx)` → `queryAbuseIPDB`
5. `wg.Wait()` — collects both results (or fewer if context cancelled or API errored)
6. Cache result, return

**`EnrichBatch(ctx, indicators)`** — semaphore channel of size `batchConcurrency = 5` bounds concurrent indicator goroutines. Each goroutine acquires a semaphore slot, calls `Enrich`, releases the slot.

**Tests** (all use `httptest.NewServer`, no real API keys, rate limiters set to `rate.Inf`):
- `TestEnrich_NoKeys_ReturnsEmpty` — both keys empty → 0 results, no HTTP calls
- `TestEnrich_PrivateIP_Skipped` — 192.168.x.x → 0 results, server never called
- `TestEnrich_VirusTotal_MaliciousIP` — score 10 → Malicious true, tags/timestamp populated
- `TestEnrich_VirusTotal_CleanIP` — score 1 < threshold → Malicious false
- `TestEnrich_VirusTotal_NotFound_GracefulSkip` — 404 → 0 results, no panic
- `TestEnrich_VirusTotal_Domain` — verifies `/domains/` URL path is used for non-IPs
- `TestEnrich_AbuseIPDB_HighScore` — score 90 → Malicious true
- `TestEnrich_AbuseIPDB_LowScore` — score 10 → Malicious false
- `TestEnrich_AbuseIPDB_SkippedForDomain` — domain indicator → AbuseIPDB server never called
- `TestEnrich_BothAPIs_BothResults` — both keys set → 2 results, one per source
- `TestEnrich_CacheHit_SecondCallSkipsAPI` — second call → atomic counter shows only 1 HTTP call
- `TestTTLCache_HitAndMiss` — set/get round-trip
- `TestTTLCache_ExpiredEntry` — 10ms TTL, sleep 20ms → miss
- `TestTTLCache_Size` — overwrite same key counts as 1
- `TestEnrichBatch_MultipleIndicators` — 3 indicators → result map has all 3 keys
- `TestEnrich_ContextCancelled_ReturnsPartial` — context timeout 50ms, server handler respects `r.Context().Done()` → test completes in ~50ms

---

## 26. feat: wire enrichment pipeline (GeoIP + IOC + entropy + beacon + threat intel)

**What changed:**
- `internal/enrichment/pipeline.go` — new file; `EnrichedResult` struct and `Enrich()` function that wires all six enrichers into a single call
- `internal/parser/pcap.go` — added `PayloadSamples map[string][]byte` and `FlowTimestamps map[string][]time.Time` fields (tagged `json:"-"`) to `ParseResult`, plus `samplePayload()` and `sampleTimestamp()` helpers populated in the parse loop
- `internal/enrichment/pipeline_test.go` — new file; 13 tests covering `normDomain`, `isMalicious`, `computeThreatScore`, and end-to-end `Enrich` scenarios

**Why:**
Steps 1–6 each produced an independent enricher; Step 7 connects them so a single `Enrich(ctx, ParseResult, cfg)` call returns a fully annotated `EnrichedResult`. The parser needed to expose per-flow payload bytes and packet timestamps so entropy and beacon stages have their input data.

**Where:**
- `internal/enrichment/pipeline.go` — new
- `internal/parser/pcap.go` — `ParseResult` struct, `Parse()` loop, two new helpers
- `internal/enrichment/pipeline_test.go` — new

**When:** 2026-04-02

**How it works:**

`EnrichedResult` lives in the `enrichment` package (not `models`) to avoid a circular import: it references `parser.RawStats` and `input.SourceMeta`, and `parser` already imports `models`.

`Enrich()` stages (in order):
1. **GeoIP** — open MaxMind DB if configured; silently skipped if DB path is empty or file not found
2. **IOC** — load all blocklist files from `cfg.IOC.Sources`; parsing errors per-file are logged and skipped
3. **Entropy** — `EntropyScorer` pre-populated from `result.PayloadSamples`; `entropy.Scores()` returns a `map[flowID]float64`
4. **Beacon** — `BeaconDetector` pre-populated from `result.FlowTimestamps`; `beacon.Results()` returns a `map[flowID]BeaconResult`
5. **Threat intel** — `ThreatIntelEnricher` created only if at least one API key is configured
6. **Assemble** — `buildIPContexts` and `buildDomainContexts` collect unique IPs/domains, run all enrichers, set `IsMalicious` and `ThreatScore`; results assembled into enriched slices

`buildIPContexts` deduplicates IPs from `result.Flows` only (ICMP events reuse the same context map via IP lookup). `buildDomainContexts` deduplicates across DNS questions, TLS SNI fields, and HTTP Host headers.

`computeThreatScore` synthesises a 0–100 risk score:
- IOC Critical → +90, High → +70, Medium → +50, Low → +30
- VirusTotal malicious → +50, AbuseIPDB malicious → +40
- Capped at 100

`normDomain` lowercases and strips trailing dots without importing `strings`, avoiding an unnecessary dependency.

**Parser changes** (`pcap.go`):
- `PayloadSamples` and `FlowTimestamps` carry enrichment-only data; `json:"-"` ensures they are never serialised in the output JSON
- `samplePayload()` caps accumulation at `maxPayloadSampleBytes = 4096` per flow
- `sampleTimestamp()` caps at `maxTimestampsPerFlow = 100` per flow
- Both are populated immediately after `ft.update(pkt)` in the main parse loop

**Test highlights:**
- `TestEnrich_IOCMatchMarksFlowMalicious` — temp IOC file with src IP → `SrcThreat.IsMalicious = true`, `ThreatScore = 70`
- `TestEnrich_BeaconDetectedThroughPipeline` — 10 timestamps 1 s apart → `IsBeacon = true`
- `TestEnrich_EntropyScoreAttached` — 256-byte ascending payload → `EntropyScore > 0`
- `TestEnrich_DNSEventsEnriched` — 2 DNS questions: 1 in IOC list → 2 domain contexts, 1 malicious
- `TestEnrich_HTTPHostEnriched` — uppercase Host header matched via `normDomain`
- `TestEnrich_GeoIPPathNotFoundSkipped` — non-existent DB path → no error returned

---

## 30. Redis job queue and worker mode

**Date:** 2026-04-03

### What
Implemented `internal/queue/redis.go` using `go-redis/v9`. Added a `Job` struct for PCAP processing tasks. Updated `cmd/forensics/main.go` with a new `worker` command that consumes jobs from Redis and processes them using the forensics pipeline. Added an `--async` flag to the `parse` command to enqueue jobs instead of processing them immediately.

### Why
Decouples PCAP ingestion from processing, allowing the system to scale horizontally with multiple worker instances. This also enables the LangGraph agents to submit jobs and receive notifications once processing is complete, which is a key requirement for Phase 3.

### Where
```
internal/queue/redis.go   — Job struct, RedisQueue (Publish/Consume)
cmd/forensics/main.go     — worker command, --async flag logic
config/config.go          — RedisConfig, env overrides
config/config.yaml        — redis section
go.mod / go.sum           — github.com/redis/go-redis/v9, github.com/google/uuid
```

### How
The `worker` command uses `BRPop` (Blocking Right Pop) to wait for jobs on a Redis list. When a job is received, it opens the PCAP file, runs the parser and enrichment pipeline, writes JSON outputs, and optionally persists results to PostgreSQL. It respects OS signals (SIGTERM/SIGINT) for graceful shutdown using `signal.NotifyContext`.

The `--async` flag in the `parse` command generates a unique UUID for the job, serializes the request to JSON, and pushes it to the Redis list using `LPush`.

---

## 31. Brainstorm and plan expanded input sources

**Date:** 2026-04-03

### What
Expanded the planned input sources for the forensics pipeline beyond just PCAP files and live interfaces. Added a detailed roadmap for Phase 1.5 in `PLANNING.md` covering SSH remote capture, S3/Cloud storage streaming, VPC Flow Logs, SIEM logs (Zeek/Suricata), and high-performance eBPF/AF_PACKET capture.

### Why
Forensics doesn't always start with a local PCAP file. In modern cloud and enterprise environments, the evidence is often in an S3 bucket, on a remote server, or in the form of metadata logs (VPC Flow). By planning these adapters now, we ensure the `PacketSource` interface remains robust and that the multi-agent AI pipeline can ingest data from anywhere a threat might hide.

### Where
```
PLANNING.md  — added Build Priority table and Phase 1.5 tasks
README.md    — updated tech stack to reflect planned cloud/remote sources
prompt.txt   — brainstormed ideas
```

### How
The brainstorming process identified several high-value categories:
1. **Remote Capture:** SSH streaming from target hosts.
2. **Cloud-Native:** VPC Flow Logs and direct S3 PCAP streaming.
3. **Pre-parsed Logs:** Zeek/Suricata integration to leverage existing infrastructure.
4. **Enterprise Streams:** Kafka consumption for real-time SOC pipelines.
5. **High-Performance:** AF_PACKET and eBPF for 10Gbps+ links where libpcap might drop packets.

Each source will implement the existing `PacketSource` interface, ensuring that the downstream parser and AI agents remain completely agnostic to the data origin.

---

## 32. Brainstorm and plan "nice to have" features

**Date:** 2026-04-03

### What
Brainstormed and documented a backlog of "nice to have" features and future enhancements for `wiremind`. Created `NICE_TO_HAVE.md` to track these ideas and updated `PLANNING.md` and `README.md` to reference the new roadmap.

### Why
While the core MVP (Phase 1–3) focuses on the forensics pipeline and AI agents, there are many high-value features like a web dashboard, advanced protocol extractors (SMB/RPC), local LLM support, and SIEM exports that would significantly improve the user experience and forensic depth. Capturing these ideas in a structured backlog ensures they aren't lost and helps guide future development once the MVP is stable.

### Where
```
NICE_TO_HAVE.md  — new backlog document
PLANNING.md      — linked new roadmap
README.md        — linked future roadmap in status section
prompt.txt       — brainstormed ideas
```

### How
The brainstorming identified five key areas for enhancement:
1. **UX & Visualization:** Web dashboard, interactive flow graphs, and TUI.
2. **Protocol Depth:** SMB, RPC, Database protocols, and ICS/OT support.
3. **AI/ML Innovation:** Local LLMs (Ollama), statistical anomaly detection, and AI-driven PII masking.
4. **Ecosystem Integration:** Wireshark plugins and direct SIEM (Splunk/Elastic) exports.
5. **Enterprise Readiness:** Multi-tenancy, audit logging, and encrypted storage.

---

## 33. Brainstorm and plan observability and refinement

**Date:** 2026-04-03

### What
Brainstormed and documented a comprehensive roadmap for Phase 8 (Productionization, Observability & Refinement). Created `PHASE8.md` with detailed tasks for health checks, structured logging, Prometheus metrics, OpenTelemetry tracing, and SSE progress streaming. Updated `PLANNING.md` to link and reflect the new observability roadmap.

### Why
As `wiremind` transitions from a CLI tool to a distributed, persistent forensics engine, observability becomes critical. Analysts and automated systems (n8n, LangGraph) need real-time visibility into job status, system health, and performance bottlenecks. These refinements ensure the system is not only functional but also reliable, scalable, and easy to debug in production environments.

### Where
```
PHASE8.md    — new roadmap for Phase 8
PLANNING.md  — linked Phase 8 to PHASE8.md and updated checklist
prompt.txt   — brainstormed ideas
```

### How
The brainstorming identified three key pillars for Phase 8:
1. **Infrastructure & Scalability:** Docker Compose orchestration, JWT authentication, and horizontal worker scaling.
2. **Observability & Monitoring:** A unified `/health` API, structured `slog` logging, Prometheus metrics for packet rates/latencies, and OpenTelemetry for distributed tracing.
3. **Refinement & Optimization:** Redis-backed persistent caching for external API results, intelligent rate limiting, and automated resource pruning.

These tasks were structured as a tickable checklist in `PHASE8.md`, providing a clear path to production readiness.

## 33. Brainstorm and plan Phase 8 Productionization and Observability

**Date:** 2026-04-03

### What
Created `PHASE8.md` and updated `PLANNING.md` to include a comprehensive roadmap for transforming `wiremind` into a production-grade system. This includes Infrastructure (Docker, Auth, Worker scaling), Observability (Health checks, Metrics, Tracing, SSE), and Refinement (Caching, Rate limiting).

### Why
As the core forensics and enrichment logic stabilized, it became necessary to plan the operational aspects of the system. This phase ensures that the tool is not just functional but also reliable, observable, and scalable for real-world deployment.

### Where
```
PHASE8.md       - New detailed roadmap for productionization
PLANNING.md     - Updated with Phase 8 status and links
```

### How
The plan categorizes tasks into three main buckets:
- **Infrastructure**: Transitioning from single-process CLI to a distributed, containerized system.
- **Observability**: Implementing standard monitoring patterns (Health checks, Prometheus metrics, OTel tracing).
- **Refinement**: Optimizing performance and resource usage (Redis caching, rate limiting, automated cleanup).

---

## 34. Refine Phase 8 with System Reliability & Observability ideas

**Date:** 2026-04-03

### What
Updated `PHASE8.md` and `PLANNING.md` with specific reliability and observability tasks imported from the `prompt.txt` project template. Added structured logging (`log/slog`), Sentry integration, advanced health checks, Prometheus metrics endpoints, and Entity Resolution.

### Why
To ensure `wiremind` follows modern Go best practices for observability and reliability. Incorporating tasks like Sentry integration and Entity Resolution adds significant value for long-term maintenance and complex forensics scenarios (e.g., tracking a host across IP changes).

### Where
```
PHASE8.md       - Updated Checklist and added Entity Resolution detail
PLANNING.md     - Synchronized checklist with refined Phase 8 tasks
```

### How
- **Structured Logging**: Migrating all `fmt.Printf` and basic `log` calls to `slog` for better parsing by log aggregators.
- **Sentry**: Providing automated error reporting for critical failures in scrapers or API calls.
- **Entity Resolution**: Establishing a framework to correlate disparate network events back to a single host or user entity, improving the quality of AI agent reasoning.

---

## 35. Start Phase 3.1: Python Infrastructure & Base Setup

**Date:** 2026-04-03

### What
Initialized the Python-based AI agent infrastructure for `wiremind`. Created the `python/` directory with a `pyproject.toml` (Poetry-ready) and implemented the core API client and LangGraph state management.

### Why
Phase 3 transitions `wiremind` from a data-collection engine into an autonomous analysis platform. Establishing a robust Python environment with standard dependencies (`langchain`, `langgraph`, `httpx`, `fastapi`) and a type-safe client ensures the upcoming specialist agents can easily consume and reason about the forensics data provided by the Go API.

### Where
```
python/pyproject.toml      - Project configuration and dependencies
python/src/wiremind/client.py - Async Python client for the Wiremind Go API
python/src/wiremind/state.py  - ForensicsState definition for LangGraph
python/tests/test_client.py   - Unit tests for the API client (with httpx/respx mocking)
PHASE3.md                     - Updated checklist for Phase 3.1 (Steps 1, 2, 3)
```

### How
- **Project Structure**: Followed standard Python package layouts (`src/` layout) and initialized with `pyproject.toml`.
- **API Client**: Implemented `WiremindClient` using `httpx` for async communication with the `/api/v1` endpoints (Flows, DNS, TLS, HTTP, ICMP, Stats).
- **State Management**: Defined `ForensicsState` using `TypedDict` and `Annotated` to manage agent findings, evidence, and task tracking within LangGraph.
- **Testing**: Added `pytest` and `respx` for mock-based testing of the API client to ensure reliability.

---

## 36. Phase 3.2: Specialist AI Agents

**Date:** 2026-04-03

### What
Implemented the core "Expert Council" of specialist agents in Python using the LangGraph state. These agents include DNS, TLS/HTTP, Lateral Movement, and Beaconing experts.

### Why
Each specialist agent brings domain-specific knowledge to the analysis process. By separating concerns, the DNS agent can focus on DGA/tunneling while the Lateral Movement agent tracks internal SMB/RPC anomalies. This modular approach allows for scalable, complex reasoning that goes beyond simple threshold-based alerts.

### Where
```
python/src/wiremind/agents/specialists.py - Core implementation of DNS, TLS, HTTP, LM, and Beacon agents
python/tests/test_specialists.py           - Comprehensive async unit tests for agent logic
PHASE3.md                                  - Updated checklist for Phase 3.2 (Steps 4, 5, 6, 7)
```

### How
- **Agent Design**: Created individual agent classes (`DNSAgent`, `TLSAgent`, etc.) that consume data from the `WiremindClient` and contribute to the `ForensicsState`.
- **Logic**: Implemented heuristics for DGA detection (query length), weak TLS ciphers (RC4), unusual User-Agents (curl/requests), and internal SMB/RPC flows.
- **Validation**: Added 5 new async tests using `pytest-asyncio` and `unittest.mock` to ensure agents correctly identify threats from API data.

### Phase 35: API Roadmap & Brainstorming
- **Brainstormed** the expansion of the Wiremind API to support advanced forensics and AI integration.
- **Defined** a roadmap for Job Management, Advanced Search, and Configuration APIs in `API_PLAN.md`.
- **Recommended** a REST-first architecture for agent compatibility with optional gRPC for high-performance internal tasks.
- **Updated** `README.md` and `PLANNING.md` to reflect the new API expansion goals.

### Step 41: Update Architecture Documentation

### What
Refactored `ARCHITECTURE.md` to reflect the current state of the project, including the transition to a multi-language, distributed architecture with enrichment and AI agents.

### Why
The original documentation was focused on Phase 1 (Go Parser). With the completion of Phase 2 (Enrichment, API, DB) and the start of Phase 3 (AI Agents), the documentation needed to be updated to serve as an accurate reference for the system's cross-component interactions.

### Where
```
ARCHITECTURE.md - Major rewrite of diagrams, package map, and design decisions.
```

### How
- **Diagrams**: Updated the "Data Flow" diagram to include the Redis Job Queue, Enrichment Pipeline, PostgreSQL Store, and Python AI Agents.
- **Package Map**: Added descriptions for `internal/enrichment`, `internal/api`, `internal/store`, `internal/queue`, and the new `python/` directory.
- **Support**: Explicitly documented pure-Go `pcapgo` support for Windows/Linux offline analysis.
- **Agent Architecture**: Added a new section for the Python-based specialist agents (DNS, TLS, HTTP, LM, Beacon).
- **Design Decisions**: Added new principles regarding REST-first integration, distributed scaling, and "Go for Speed, Python for Brains".

### Step 50: Production Ecosystem Expansion (n8n, Loki, Promtail)
**Date:** 2026-04-03
**Status:** Brainstormed & Integrated
**Changes:**
- Expanded `docker-compose.yaml` with **n8n** (workflow automation) and **Loki/Promtail** (log aggregation).
- Refined Phase 8 roadmap in `PHASE8.md` with 23 specific productionization steps.
- Created `scripts/promtail.yml` for centralized log shipping.
- Linked new infrastructure components to `PLANNING.md` and updated phase statuses.
**Notes:** The project now has a complete observability and automation stack including metrics, logs, tracing, and workflow orchestration.

### Step 45: Implement Phase 3.6 (Correlation & Reporting)

### What
Implemented the attack chain correlation engine and forensics report generator in Python.

### Why
To synthesize findings from multiple specialist agents into a coherent, human-readable narrative. Correlation links disparate events (e.g., DNS -> TLS -> C2) into a structured attack chain mapped to MITRE ATT&CK, making it easier for SOC analysts to understand the full scope of a threat.

### Key Changes
- **Correlation Engine**: Created `python/src/wiremind/agents/correlation.py` to link agent findings via IP/temporal heuristics.
- **Report Generator**: Developed `python/src/wiremind/agents/reporting.py` for executive summaries and technical report generation in Markdown and JSON.
- **Workflow Integration**: Updated the LangGraph `Orchestrator` to include `correlation` and `reporting` nodes in the analysis graph.
- **Testing**: Added unit tests in `python/tests/test_correlation.py` and `python/tests/test_reporting.py` to verify logic.

### How
- **Logic**: Implemented an `AttackChainConstructor` that builds a directed graph of security events, mapping specialist agent findings to MITRE tactics and techniques.
- **Summary**: Implemented a `SummaryGenerator` that calculates overall risk levels, identifies key MITRE mappings, and provides recommended response actions.
- **Orchestration**: Seamlessly integrated correlation and reporting into the existing AI analysis pipeline, ensuring all runs produce a final executive summary.

### Step 44: Implement Phase 3.5 (AI Integration Verification & End-to-End Tests)

### What
Implemented the main entry point for the AI forensics CLI and verified the multi-agent system through comprehensive end-to-end tests.

### Why
To ensure the entire AI forensics pipeline—from data ingestion via the Go API to multi-agent analysis—is functional and ready for production workflows. This also establishes a CLI entry point for executing AI analysis from the command line.

### Key Changes
- **Main CLI**: Created `python/src/wiremind/main.py` as the main entry point for AI forensics analysis.
- **End-to-End Testing**: Developed `python/tests/test_e2e.py` verifying coordination across DNS, TLS, HTTP, and Lateral Movement agents.
- **Findings Standardization**: Refactored `specialists.py` to produce structured findings with `severity`, `agent`, and `description` for reporting.
- **Infrastructure**: Configured `pytest-asyncio` auto-mode in `pyproject.toml` for reliable async testing.

### Step 43: Implement Phase 3.4 (Orchestrator & Multi-Agent Flow)

### What
Implemented the central orchestrator and standardized tooling interface for AI agents.

### Why
To coordinate between specialized agents (DNS, TLS, HTTP, etc.) and provide them with standardized tools for deep-packet investigation via the Go API. LangGraph ensures a stateful, predictable analysis workflow.

### Key Changes
- **Orchestrator**: Developed the LangGraph-based `Orchestrator` in `python/src/wiremind/agents/orchestrator.py` that sequences specialist agent analysis.
- **Tooling Interface**: Created a decorator-based `WiremindTool` system in `python/src/wiremind/tools/base.py` for standardizing agent capabilities.
- **Core Tools**: Implemented `search_flows`, `get_stats`, and `deep_dive_ip` in `python/src/wiremind/tools/core.py`.
- **Testing**: Added comprehensive async tests in `python/tests/test_orchestrator.py` for agent coordination and tool execution.

### Step 42: Implement Phase 3.3 (RAG & Knowledge Store)

### What
Initialized the RAG infrastructure for AI agents, including a knowledge store for MITRE ATT&CK techniques and security playbooks.

### Why
Specialist AI agents need access to domain-specific security knowledge to accurately identify threats and provide actionable recommendations. RAG provides this context without requiring model fine-tuning.

### Where
```
python/src/wiremind/knowledge/vectorstore.py - Knowledge store manager.
python/src/wiremind/knowledge/ingestor.py - Knowledge ingestion and seeding.
python/src/wiremind/knowledge/consultant.py - Security Consultant tool for agents.
python/src/wiremind/agents/specialists.py - Integrated RAG into DNSAgent.
python/tests/test_rag.py - Comprehensive tests for the RAG system.
```

### How
- **Store**: Implemented a lightweight, keyword-based document store for compatibility with Windows/Torch constraints.
- **Ingestion**: Created a seeding script to populate the store with initial MITRE ATT&CK and playbook data.
- **Consultant**: Developed the `SecurityConsultant` tool to provide a standard interface for agents to query knowledge.
- **Integration**: Updated `DNSAgent` to enrich its findings with MITRE context retrieved via the consultant.
- **Verification**: Verified the entire flow with a new test suite and confirmed it works on the local Windows environment.

### Step 41: Brainstorming IDE & Repository Strategy
- **Architectural Decision**: Keep the project in a single mono-repo for now to ensure tight coupling and consistency between the Go-based parser/API and the Python-based AI agents.
- **Workflow Recommendation**: Use specialized JetBrains tools for each domain: **GoLand** for the root/Go core and **PyCharm** specifically for the `python/` directory. This leverages the best language-specific support while maintaining a single source of truth.
- **New Documentation**: Created `IDE_GUIDE.md` to help developers set up their workspace across multiple IDEs in the same repository.
- **Updated Roadmaps**: Refined `PLANNING.md` and `ARCHITECTURE.md` to reflect the polyglot development workflow and mono-repo philosophy.

### Step 45: Implement Phase 8 Steps 4, 7, and 8 (Docker, Health Checks & Structured Logging)

### What
Implemented the core productionization infrastructure, including Docker orchestration, advanced health checks, and structured logging.

### Why
To transform the `wiremind` forensics engine into a reliable, containerized, and observable system. Docker Compose enables one-command startup of the entire polyglot stack (Go, Python, Postgres, Redis), while health checks and structured logging provide critical observability for production deployments.

### How
- **Dockerization**: Created multi-stage `Dockerfile` for Go core and Python AI agents, optimizing for image size and security.
- **Orchestration**: Developed `docker-compose.yaml` to manage service dependencies (Postgres, Redis, API, Worker, Agents).
- **Health Checks**: Implemented `/health` endpoint in `internal/api/server.go` with PostgreSQL connectivity validation via a new `Ping()` method in `internal/store/postgres.go`.
- **Structured Logging**: Initialized `structlog` in Python with a new `wiremind.logger` module and updated the CLI entry point to use it. Confirmed Go's existing use of `slog` for consistent observability.
- **Status**: Steps 4, 7, and 8 of Phase 8 are completed. The system is now ready for distributed, containerized execution.

---

### Step 46: Implement Phase 8 Steps 9, 12, and 13 (Prometheus Metrics, Sentry & Entity Resolution)

### What
Implemented Prometheus metrics, Sentry error tracking, and initial Entity Resolution schema.

### Why
To complete the critical observability and refinement milestones of Phase 8, ensuring the system can be monitored at scale, tracked for errors, and correlate fragmented network observations into persistent identities.

### How
- **Prometheus Metrics**: Added `/metrics` endpoint to the Go API server using `prometheus/client_golang`. Instrumented core API handlers with request total counters and duration histograms.
- **Sentry Integration**: Added Sentry initialization to Go (`cmd/forensics/main.go`) and Python (`python/src/wiremind/logger.py`) components. Added `SentryConfig` to `config.go` and updated `config.yaml`.
- **Entity Resolution**: Created `internal/models/entity.go` with `Entity` and `EntityObservation` models to support host/user tracking and correlation. Registered new models in `PostgresStore.AutoMigrate()`.
- **Dependencies**: Added `github.com/getsentry/sentry-go` and `github.com/prometheus/client_golang` to Go, and `sentry-sdk` and `prometheus-client` to Python.
- **Status**: Steps 9, 12, and 13 of Phase 8 are completed.

---

### Step 47: Phase 8 Infrastructure Expansion (Docker Ecosystem)

### What
Brainstormed and integrated a suite of complementary services into the Wiremind Docker ecosystem, including Prometheus, Grafana, Jaeger, and Standalone ChromaDB.

### Why
To transform the forensics engine from a standalone set of services into a complete, observable, and automated security operations platform. These tools enable real-time visualization, deep analysis of AI agent reasoning, and persistent knowledge storage.

### How
- **Prometheus & Grafana**: Integrated Prometheus for automated metric scraping and Grafana for dashboarding and visualization. Created `scripts/prometheus.yml` for service discovery.
- **Jaeger (Distributed Tracing)**: Added Jaeger to the `docker-compose.yaml` to support future OpenTelemetry instrumentation across the Go and Python components.
- **Standalone ChromaDB**: Migrated AI agents' vector storage from local ephemeral files to a dedicated, persistent ChromaDB server for improved reliability and shared knowledge.
- **Roadmap Update**: Refined `PHASE8.md` to include new milestones for standalone infrastructure and workflow automation.
- **Status**: Infrastructure expansion brainstorm and integration completed.

---

### Step 48: Expand Production Ecosystem with n8n, Loki, and Promtail (Phase 8)

### What
Integrated n8n (workflow automation) and Loki/Promtail (log aggregation) into the Wiremind Docker infrastructure.

### Why
To complete the initial productionization roadmap by enabling automated security response workflows and centralized, searchable log management across the polyglot (Go/Python) stack.

### How
- **Workflow Automation**: Added **n8n** to `docker-compose.yaml` to support automated post-analysis triggers (Slack alerts, Jira tickets, S3 archiving).
- **Log Aggregation**: Integrated **Loki** and **Promtail** for high-performance, centralized log storage and querying.
- **Log Shipping**: Created `scripts/promtail.yml` to automatically ship logs from all containerized services to Loki.
- **Roadmap Refinement**: Expanded `PHASE8.md` with a 23-task checklist covering advanced production features like Secret Management (Vault) and Continuous Profiling (Pyroscope).
- **Status**: Production ecosystem expansion and documentation update completed.

---

### Step 49: Implement Phase A of API Roadmap (Job Management)

### What
Implemented the Job and Task Management API endpoints (Phase A) to support asynchronous PCAP processing and persistent job status tracking.

### Why
To transition the API from a static result viewer into a functional forensics controller. Job management enables AI agents and external tools to submit PCAPs for background analysis, monitor their progress, and retrieve results systematically via a persistent database store.

### Where
```
internal/models/job.go - Job model and status definitions.
internal/store/postgres.go - Database methods for job persistence and retrieval.
internal/api/server.go - New REST endpoints (POST /jobs, GET /jobs, GET /jobs/:id).
cmd/forensics/main.go - Updated worker and server logic to use persistent jobs.
internal/api/server_test.go - Integration tests for job submission.
```

### How
- **Models**: Created a new `Job` model with `Pending`, `Processing`, `Completed`, and `Failed` statuses, including packet and flow counts.
- **Store**: Added `SaveJob`, `GetJob`, and `GetJobs` methods to `PostgresStore` and updated the migration loop.
- **API**: Implemented `handleSubmitJob`, `handleListJobs`, and `handleGetJob` handlers. Integrated `uuid` for unique job identification and `redis` for async enqueuing.
- **Worker**: Updated the background worker to transition job statuses in the database as it progresses through parsing and enrichment.
- **Metrics**: Refactored API metrics to use a global registration pattern to support multiple server instances in unit tests.
- **Verification**: Added comprehensive tests in `server_test.go` and verified the full job lifecycle (Submit -> Enqueue -> Status).
- **Status**: Phase A of the `API_PLAN.md` is completed.

---

## 49. OpenAPI/Swagger specification for Wiremind API

**Commit:** `[SHA]`
**Date:** 2026-04-03

### What
Defined the complete OpenAPI 3.0.3 specification for the Wiremind API in `docs/openapi.yaml`.

### Why
To provide a clear, machine-readable contract for all API endpoints, including Job management, Enriched Flows, and Protocol events. This enables automated documentation, client generation, and consistent integration for AI agents and external tools.

### Where
```
docs/openapi.yaml - Full OpenAPI 3.0.3 specification.
API_PLAN.md - Updated Step D2 to completed.
PHASE8.md - Updated Step 11 to completed.
PLANNING.md - Updated Phase 8 status to reflect OpenAPI completion.
```

### How
- **Specification**: Created `docs/openapi.yaml` using OpenAPI 3.0.3 syntax.
- **Paths**: Documented all v1 endpoints: `/flows`, `/jobs`, `/jobs/{id}`, `/dns`, `/tls`, `/http`, `/icmp`, `/stats`, `/health`, and `/metrics`.
- **Schemas**: Defined comprehensive schemas for `Job`, `EnrichedFlow`, `ThreatContext`, `GeoInfo`, and all protocol events, matching the GORM models and JSON outputs.
- **Responses**: Documented success and error status codes (200, 400, 404, 500, 501) for each operation.

### ---------------------------------------------------------------------------
## [Step 50] - 2026-04-03
### What
Implemented Phase B (Advanced Search & Filtering) of the API roadmap.

### Why
To enable complex forensics queries and efficient data retrieval for AI agents and security analysts. This includes filtering by IPs, protocols, and domains, and an aggregate view of malicious findings.

### Where
```
internal/store/postgres.go - Added GetFlows (filtered), GetDNSEvents (filtered), GetTLSEvents (filtered), GetHTTPEvents (filtered), GetICMPEvents (filtered), and GetThreats.
internal/api/server.go - Added /api/v1/flows/search and /api/v1/threats, and integrated filters into existing protocol endpoints.
docs/openapi.yaml - Documented the new search parameters and aggregate threat view.
API_PLAN.md - Marked Step B1, B2, and B3 as completed.
internal/store/postgres_test.go - Updated tests to verify filtering and threat retrieval.
```

### How
- **Store**: Implemented GORM subqueries to filter enriched records based on properties of their associated core models (e.g., filtering `EnrichedFlow` by `Flow.SrcIP`).
- **API**: Extended `handleFlows`, `handleDNS`, `handleTLS`, and `handleHTTP` to extract query parameters and pass them to the store layer.
- **Search**: Added `/api/v1/flows/search` as a dedicated search alias and `/api/v1/threats` to retrieve all malicious or high-entropy flows.
- **Verification**: Verified the implementation with unit tests in `internal/store/postgres_test.go` and `internal/api/server_test.go`.

### ---------------------------------------------------------------------------
## [Step 51] - 2026-04-03
### What
Implemented Phase C (Configuration & Control) of the API roadmap.

### Why
To enable dynamic runtime configuration and control over the forensics pipeline. This includes managing custom IOC lists, adjusting enrichment thresholds, and initiating live captures via the REST API for AI agents and automation.

### Where
```
internal/models/config.go - Added Config, IOCEntry, and CaptureJob models.
internal/store/postgres.go - Added SaveConfig, GetConfig, SaveIOCEntry, DeleteIOCEntry, GetIOCEntries, SaveCaptureJob, GetCaptureJobs, and UpdateCaptureJobStatus.
internal/api/server.go - Added /api/v1/config/ioc, /api/v1/config/pipeline, /api/v1/capture/start, and /api/v1/capture/stop.
internal/enrichment/pipeline.go - Exported IOC field to allow dynamic updates.
docs/openapi.yaml - Documented Phase C endpoints and schemas.
API_PLAN.md - Marked Step C1, C2, and C3 as completed.
PHASE2.md - Updated Step 14 as completed.
```

### How
- **Models**: Created `Config`, `IOCEntry`, and `CaptureJob` GORM models for persistent configuration.
- **Store**: Implemented persistence methods and updated `AutoMigrate` in `internal/store/postgres.go`.
- **API**: Developed REST handlers for IOC management (CRUD on custom indicators), pipeline configuration (patching runtime settings), and live capture (start/stop jobs).
- **Dynamic Updates**: Exported the `IOC` matcher in the enrichment pipeline to allow real-time indicator injection via the `/api/v1/config/ioc` endpoint.
- **Verification**: Verified the implementation with unit tests in `internal/store/postgres_test.go` and `internal/api/server_test.go`.

### ---------------------------------------------------------------------------
## [Step 52] - 2026-04-03
### What
Implemented Phase D (Monitoring & Observability) SSE Progress Streaming.

### Why
To provide real-time status updates for long-running forensics jobs. Server-Sent Events (SSE) enable AI agents, user interfaces, and external orchestrators to monitor the precise state of a job (Pending, Processing, Completed, Failed) without polling.

### Where
```
internal/api/server.go - Implemented GET /api/v1/jobs/{id}/stream endpoint with SSE.
docs/openapi.yaml - Added SSE endpoint specification.
API_PLAN.md - Marked Step D3 as completed.
PHASE8.md - Marked Step 24 as completed.
internal/api/server_test.go - Added unit tests for job progress streaming.
```

### How
- **API**: Implemented `handleJobStream` which uses `http.Flusher` to send real-time events. It polls the database every 2 seconds for status changes and streams the JSON-serialized `Job` object to the client.
- **Lifecycle**: The stream automatically terminates when the job reaches a terminal state (`Completed` or `Failed`) or when the client disconnects.
- **OpenAPI**: Updated `docs/openapi.yaml` with the `text/event-stream` response type and path parameters.
- **Verification**: Verified the implementation with `TestServerJobStream` using `httptest.NewRecorder` and background status updates to trigger stream termination.

### ---------------------------------------------------------------------------
## [Step 53] - 2026-04-03 · `1cf5525`
### What
Infrastructure fixes to get the full Docker Compose stack booting cleanly end-to-end.

### Why
First real boot of all 11 services together exposed a series of ordering and compatibility issues: the Go image was too old, the `forensics` container exited immediately because the old `parse --serve` command required a PCAP path, Jaeger v1 reached end-of-life, Postgres wasn't ready before the app connected, and two containers raced through `AutoMigrate` at the same time causing a duplicate-key error on the Postgres system catalog.

### Where
```
Dockerfile                    — base image bump
cmd/forensics/main.go         — new serve command
docker-compose.yaml           — Jaeger v2, Postgres healthcheck, service ordering
internal/store/postgres.go    — advisory lock, DisableForeignKeyConstraintWhenMigrating, DoNothing upserts
internal/api/server.go        — /api/v1/config and /api/v1/capture handler additions
internal/api/server_test.go   — corresponding tests
python/Dockerfile             — dependency layer fix
python/pyproject.toml         — sentry-sdk added
```

### How

**Dockerfile** — `golang:1.22-alpine` → `golang:1.24-alpine`. `go.mod` declared `go 1.24` so the old image failed at `go mod download`.

**`cmd/forensics/main.go`** — Added standalone `serve` cobra command (`runServe`). The old `parse --serve` flag required `--file` and exited immediately in Docker when none was supplied. `serve` initializes the enrichment pipeline, connects to Postgres and Redis, then blocks serving the API — no PCAP required. Also added the missing `"wiremind/internal/models"` import (caused a build failure: `undefined: models.JobProcessing`).

**`docker-compose.yaml`**:
- `forensics` command: `["parse", "--serve"]` → `["serve"]`
- Jaeger: `jaegertracing/all-in-one:latest` → `jaegertracing/jaeger:latest` (v1 EOL)
- Prometheus host port: `9090` → `9091` (port already in use on dev machine)
- Added `pg_isready -U postgres` healthcheck to `postgres` service with 10 retries
- Changed `forensics` and `worker` `depends_on` to `condition: service_healthy` so they wait for Postgres to pass its health check before connecting

**`internal/store/postgres.go`**:
- Added `DisableForeignKeyConstraintWhenMigrating: true` to `gorm.Config` — GORM was creating a backwards FK (`flows → enriched_flows`) which then blocked all inserts
- Wrapped `AutoMigrate` with a Postgres advisory lock (`pg_advisory_lock(7743382910)`) so concurrent startups of `forensics` and `worker` don't race through schema creation and hit `duplicate key value violates unique constraint "pg_type_typname_nsp_index"`
- Replaced `db.Save()` calls in `SaveEnrichedResult` with `clause.OnConflict{DoNothing: true}` + `Session{FullSaveAssociations: false}` + `Omit(clause.Associations)` — GORM's `Save` was re-inserting associations and hitting unique constraints on every call

**`python/pyproject.toml`** — Added `sentry-sdk = "^2.0.0"`. The agents container crashed immediately with `ModuleNotFoundError: No module named 'sentry_sdk'` because the dependency was imported in `logger.py` but missing from the project file.

### ---------------------------------------------------------------------------
## [Step 54] - 2026-04-03 · `67457dd`
### What
Data-path fixes to make the full pipeline produce correct results: enriched flows persisting correctly to Postgres, IP addresses scanning without errors, and AI agent specialists reading the correct fields from the API response.

### Why
After the stack booted (Step 53), results were still wrong in three distinct ways:
1. Only 1 of 194 enriched flows was being written to Postgres — all flows had an empty `FlowID`
2. Querying `/api/v1/flows` returned a database error — pgx was returning `inet` columns as Go `string` but `net.IP` has no `sql.Scanner` implementation
3. All 5 AI agent specialists returned 0 findings — they used flat field names (e.g. `log.get("query")`) but the API returns nested structs (`event.questions[].name`)

### Where
```
internal/enrichment/pipeline.go           — FlowID propagation fix
internal/models/ip.go                     — new custom IPAddr type (sql.Scanner + driver.Valuer)
internal/models/flow.go                   — inet→text, net.IP→IPAddr
internal/models/events.go                 — inet→text, net.IP→IPAddr for ICMPEvent
internal/parser/flow.go                   — models.IPAddr() cast when constructing Flow
internal/parser/icmp.go                   — ipsFromPacket return type change
internal/store/postgres.go                — complementary upsert fixes
python/src/wiremind/agents/specialists.py — all 5 specialists: correct nested field paths + IOC detection
python/src/wiremind/main.py               — ForensicsState fields fix, WIREMIND_API_URL env var
```

### How

**`internal/enrichment/pipeline.go`** — `EnrichedFlow` was constructed without setting `FlowID`. Since `FlowID` is the unique key, all 194 enriched flows had an empty string key — the first insert succeeded, and every subsequent one was silently skipped by `DoNothing`. Fix: added `FlowID: f.FlowID` when building the struct.

**`internal/models/ip.go`** (new file) — Created `type IPAddr net.IP` with:
- `sql.Scanner` — converts `string` (how pgx returns text columns) → `net.IP` via `net.ParseIP`
- `driver.Valuer` — converts `net.IP` → `string` for writes
- `MarshalJSON` / `UnmarshalJSON` — preserves dotted-decimal string representation in JSON
- `String()` — delegates to `net.IP.String()`

The root cause: GORM columns typed `gorm:"type:inet"` with `net.IP` fields worked fine for writes (pgx accepts `net.IP` as a parameter) but failed on reads because pgx returns inet values as `string`, and `*net.IP` has no `Scan(interface{})` method.

**`internal/models/flow.go`** and **`events.go`** — Changed `SrcIP net.IP gorm:"type:inet"` → `SrcIP IPAddr gorm:"type:text"` and same for `DstIP`. Switching to `text` avoids pgx format negotiation entirely; the custom type handles all conversions.

**`internal/parser/flow.go`** — Cast raw `net.IP` bytes to `models.IPAddr` when constructing `models.Flow`: `SrcIP: models.IPAddr(cSrcIP)`.

**`internal/parser/icmp.go`** — Changed `ipsFromPacket` return type from `(src, dst net.IP)` to `(src, dst models.IPAddr)` and removed the `"net"` import.

**`python/src/wiremind/agents/specialists.py`** — All 5 specialists were using field names from a flat hypothetical schema. The Go API returns enriched wrapper structs with nested protocol events. Corrected field paths per agent:

| Agent | Was | Now |
|---|---|---|
| DNSAgent | `log.get("query")` / `log.get("status")` | `log["event"]["questions"][i]["name"]` / `log["event"]["rcode"]` |
| TLSAgent | `log.get("sni")` / `log.get("cipher_suite")` | `log["event"]["sni"]` / `log["event"]["cipher_suites"]` (list) |
| HTTPAgent | `log.get("user_agent")` | `log["event"]["user_agent"]` |
| LateralMovementAgent | `flow.get("src_ip")` / `flow.get("dest_port")` | `flow["flow"]["src_ip"]` / `flow["flow"]["dst_port"]` |
| BeaconingAgent | `flow.get("enriched", {}).get("beacon")` | `flow.get("is_beacon")` (top-level) |

Also added IOC-based detections in each agent: `sni_threat.is_malicious` → `TLS_MALICIOUS_SNI`, `host_threat.is_malicious` → `HTTP_MALICIOUS_HOST`, `dst_threat.is_malicious` → `FLOW_MALICIOUS_DESTINATION`.

**`python/src/wiremind/main.py`** — Fixed `ForensicsState` initialization to use current field names (`findings`, `flows`, `evidence`, `next_steps`, `summary` instead of old `flow_id`, `messages`, `context`, `next_agent`). Added `os.environ.get("WIREMIND_API_URL", "http://localhost:8765")` as the default for `--url` so the `WIREMIND_API_URL` environment variable set in Docker Compose is respected.

### Result
After these fixes the full E2E pipeline produces:

| Metric | Value |
|---|---|
| Packets processed | 11,562 |
| Flows to Postgres | 194 (was 1) |
| DNS / TLS / HTTP / ICMP events | 169 / 65 / 4 / 3 |
| AI findings | **2,816** (was 0) |
| Analysis time (agents) | ~124 ms |
