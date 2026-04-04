# Phase 1 — Go Input Adapters & PCAP Parser
## Coding Flow Breakdown

---

## Checklist

- [x] **Step 1** — Project scaffold (`go.mod`, cobra CLI stub, config loader)
- [x] **Step 2** — Core models (`RawPacketMeta`, `Flow`, `FlowHealth`, protocol events)
- [x] **Step 3** — `PacketSource` interface + factory (10 stubs)
- [x] **Step 4** — PCAP file source (`PCAPFileSource` — first real packets)
- [x] **Step 5** — Parser dispatch loop (`Parse(source, cfg) → ParseResult`)
- [x] **Step 6a** — Extractor: flow tracker
- [x] **Step 6b** — Extractor: flow health
- [x] **Step 6c** — Extractor: DNS
- [x] **Step 6d** — Extractor: TLS
- [x] **Step 6e** — Extractor: HTTP (TCP stream reassembly)
- [x] **Step 6f** — Extractor: ICMP
- [x] **Step 7** — JSON output writer (8 files to `--output` dir)
- [x] **Step 8** — Wire CLI end-to-end (`parse --input file` works)
- [x] **Step 9a** — Input source: PCAPNG
- [x] **Step 9b** — Input source: live interface
- [x] **Step 9c** — Input source: stdin/pipe
- [x] **Step 10** — Table-driven tests + sample PCAP fixtures

---

### Step 1 — Project Scaffold
**What:** Repo skeleton, go.mod, cobra CLI wired up but doing nothing yet.
```
go.mod
cmd/forensics/main.go        ← cobra root + "parse" subcommand stub
config/config.go             ← load config.yaml + env overrides
config/config.yaml           ← defaults (output dir, timeouts, etc.)
```
**Verify:** `./forensics parse --help` prints something.

> **Commit:**
> ```
> git commit -m "feat: scaffold project with cobra CLI and config loader"
> ```

---

### Step 2 — Core Models
**What:** Define all the structs everything else will produce and consume. No logic yet.
```
internal/models/packet.go    ← RawPacketMeta (timestamp, src/dst, proto, size)
internal/models/flow.go      ← Flow + FlowHealth structs
internal/models/events.go    ← DNSEvent, TLSEvent, HTTPEvent, ICMPEvent
```
**Reason:** parsers, input adapters, and output all depend on these. Define the shapes before writing any logic.

> **Commit:**
> ```
> git commit -m "feat: add core models for packets, flows, and protocol events"
> ```

---

### Step 3 — PacketSource Interface + Factory
**What:** The single contract all input sources implement. Nothing produces real packets yet.
```
internal/input/source.go     ← PacketSource interface, SourceMeta, NewPacketSource() factory
```
Stub all 10 cases in the factory returning `errors.New("not implemented")` — just wire the switch.

> **Commit:**
> ```
> git commit -m "feat: add PacketSource interface and factory with stubs for all 10 sources"
> ```

---

### Step 4 — PCAP File Source (Source 1)
**What:** First real adapter. Reads a `.pcap` file and emits `gopacket.Packet` on a channel.
```
internal/input/pcap_file.go  ← PCAPFileSource implements PacketSource
```
This is the only source you need for everything that follows. All other sources come later.

> **Commit:**
> ```
> git commit -m "feat: implement PCAPFileSource — first working packet source"
> ```

---

### Step 5 — Core Parser (dispatch loop)
**What:** Reads from a `PacketSource`, inspects each packet's layer types, routes to the right extractor.
```
internal/parser/pcap.go      ← Parse(source PacketSource, cfg Config) → ParseResult
```
`ParseResult` holds slices of all event types + raw stats. Fill this loop in as you add extractors.

> **Commit:**
> ```
> git commit -m "feat: add parser dispatch loop with ParseResult skeleton"
> ```

---

### Step 6 — Protocol Extractors (one at a time)
Build in this order — each takes a `gopacket.Packet`, returns an event or nil:

```
internal/parser/flow.go          ← TCP/UDP flow tracker (map[FlowKey]*Flow, updates state per packet)
internal/parser/flow_health.go   ← plugs into flow tracker, detects retransmits/RST/zero-window
internal/parser/dns.go           ← extracts DNSEvent from DNS layer
internal/parser/tls.go           ← extracts TLSEvent from TLS ClientHello
internal/parser/http.go          ← reassembles TCP streams → HTTP request/response
internal/parser/icmp.go          ← extracts ICMPEvent
```

**Build order:** flow → flow_health → dns → tls → http → icmp
- Flow must come first — all other extractors reference `FlowID`
- HTTP is hardest (needs TCP stream reassembly via `gopacket/tcpassembly`)

> **Commit after each extractor:**
> ```
> git commit -m "feat: add flow tracker extractor"
> git commit -m "feat: add flow health extractor (retransmits, RST, zero-window)"
> git commit -m "feat: add DNS event extractor"
> git commit -m "feat: add TLS ClientHello extractor"
> git commit -m "feat: add HTTP extractor with TCP stream reassembly"
> git commit -m "feat: add ICMP event extractor"
> ```

---

### Step 7 — JSON Output Writer
**What:** Takes `ParseResult`, writes all the JSON files to `--output` dir.
```
internal/output/writer.go    ← WriteJSON(result ParseResult, dir string) error
```
Writes: `meta.json`, `flows.json`, `flow_health.json`, `dns.json`, `tls.json`, `http.json`, `icmp.json`, `raw_stats.json`

> **Commit:**
> ```
> git commit -m "feat: add JSON output writer for all ParseResult fields"
> ```

---

### Step 8 — Wire the CLI
**What:** Connect the `parse` command to the real pipeline.
```
cmd/forensics/main.go        ← parse command calls NewPacketSource → Parse → WriteJSON
```
**At this point `./forensics parse --input file --file capture.pcap --output ./output/` works end-to-end.**

> **Commit:**
> ```
> git commit -m "feat: wire parse command end-to-end — NewPacketSource → Parse → WriteJSON"
> ```

---

### Step 9 — Remaining Input Sources
Now that the pipeline works with PCAP file, add the other sources one at a time. Each only needs to implement `PacketSource` — the parser and output don't change:

```
internal/input/live.go       ← libpcap live capture
internal/input/pipe.go       ← stdin reader
internal/input/pcapng.go     ← PCAPNG file (near-free, gopacket handles it)
internal/input/ssh.go        ← SSH → remote tcpdump → pipe back
internal/input/afpacket.go   ← AF_PACKET (Linux only)
internal/input/zeek.go       ← parse Zeek conn/dns/http logs into models
internal/input/s3.go         ← stream PCAP from S3
internal/input/vpc_flows.go  ← AWS/Azure/GCP flow log parsing
internal/input/kafka.go      ← Kafka consumer
```

> **Commit after each source:**
> ```
> git commit -m "feat: add live interface input source"
> git commit -m "feat: add stdin/pipe input source"
> git commit -m "feat: add PCAPNG input source"
> git commit -m "feat: add SSH remote capture input source"
> git commit -m "feat: add AF_PACKET input source"
> git commit -m "feat: add Zeek log input source"
> git commit -m "feat: add S3 input source"
> git commit -m "feat: add VPC flow logs input source"
> git commit -m "feat: add Kafka stream input source"
> ```

---

### Step 10 — Tests
**What:** Table-driven tests against real (small) PCAP fixtures.
```
internal/parser/dns_test.go
internal/parser/flow_test.go
internal/parser/flow_health_test.go
...
scripts/sample_pcaps/          ← drop small .pcap fixtures here
```

> **Commit:**
> ```
> git commit -m "test: add table-driven parser tests with sample PCAP fixtures"
> ```

---

## Summary

```
1. Scaffold + CLI stub
2. Models (shapes first)
3. PacketSource interface + factory
4. PCAP file source          ← first real packets
5. Parser dispatch loop
6. Extractors: flow → health → dns → tls → http → icmp
7. JSON writer
8. Wire CLI end-to-end       ← first working binary
9. Remaining 9 input sources (one at a time)
10. Tests
```

Each step compiles and is independently testable before moving to the next.
Steps 1–8 give you a working tool. Step 9 is additive with zero risk to what's already built.
