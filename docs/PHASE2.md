# Phase 2 — Enrichment Pipeline & Go API Server
## Coding Flow Breakdown

Phase 1 produced structured JSON from raw packets.
Phase 2 makes that data *actionable* — enriching each event with threat context,
detecting behavioural patterns, exposing everything via a tool API for the LangGraph agents.

---

## Checklist

- [x] **Step 1** — Enriched models (`EnrichedFlow`, `EnrichedEvent`, `ThreatContext`)
- [x] **Step 2** — GeoIP enrichment (MaxMind GeoLite2 — city, country, ASN)
- [x] **Step 3** — IOC matcher (local blocklist — IPs, domains, hashes)
- [x] **Step 4** — Entropy scorer (payload randomness → detects encryption/packing)
- [x] **Step 5** — Beacon detector (inter-arrival timing → C2 heartbeat patterns)
- [x] **Step 6** — Threat intel integration (VirusTotal + AbuseIPDB — async, rate-limited)
- [x] **Step 7** — Enrichment pipeline (wire Steps 1–6 into `Enrich(ParseResult) EnrichedResult`)
- [x] **Step 8** — Go HTTP API server (`internal/api/server.go` — tool endpoints for LangGraph)
- [x] **Step 9** — PostgreSQL store (structured findings, audit trail)
- [x] **Step 10** — Redis job queue (async job dispatch between CLI and agents)
- [x] **Step 11** — Wire CLI (`forensics parse --serve` + enrichment integrated)
- [x] **Step 12** — Docker Compose (postgres, redis, chromadb in one `docker-compose up`)
- [x] **Step 13** — Tests
- [x] **Step 14** — Configuration & Control API (Phase C)

---

### Step 1 — Enriched Models
**What:** Define the output shapes of the enrichment layer. No logic yet.
```
internal/models/enriched.go   ← EnrichedFlow, ThreatContext, GeoInfo, IOCMatch
```
**Why first:** every enricher in Steps 2–6 produces these shapes. Define them before any logic.

> **Commit:**
> ```
> git commit -m "feat: add enriched models (ThreatContext, GeoInfo, IOCMatch)"
> ```

---

### Step 2 — GeoIP Enrichment
**What:** For every unique IP in a ParseResult, look up city, country, and ASN via MaxMind GeoLite2.
```
internal/enrichment/geoip.go  ← GeoIPEnricher — wraps oschwald/geoip2-golang
```
Requires `GeoLite2-City.mmdb` — free download from MaxMind (needs account).
Config path via `MAXMIND_DB_PATH` env var.

> **Commit:**
> ```
> git commit -m "feat: add GeoIP enrichment via MaxMind GeoLite2"
> ```

---

### Step 3 — IOC Matcher
**What:** Match IPs, domains, and file hashes against a local blocklist (flat files or embedded).
```
internal/enrichment/ioc.go    ← IOCMatcher — loads lists, matches against events
```
Sources: public feeds (abuse.ch, Feodo Tracker, custom). Loaded once at startup.

> **Commit:**
> ```
> git commit -m "feat: add IOC list matcher for IPs, domains, and hashes"
> ```

---

### Step 4 — Entropy Scorer
**What:** Score payload randomness per flow. High entropy → likely encrypted or packed traffic.
```
internal/enrichment/entropy.go ← EntropyScorer — Shannon entropy on TCP/UDP payloads
```
Threshold ~7.2 bits/byte flags suspicious payloads (normal English text ≈ 4.5, AES ≈ 7.9+).

> **Commit:**
> ```
> git commit -m "feat: add Shannon entropy scorer for payload analysis"
> ```

---

### Step 5 — Beacon Detector
**What:** Detect regular inter-packet timing patterns consistent with C2 beaconing.
```
internal/enrichment/beacon.go  ← BeaconDetector — jitter analysis on flow timestamps
```
A flow with stddev/mean < 0.1 (low jitter) on inter-arrival times is flagged as a beacon candidate.

> **Commit:**
> ```
> git commit -m "feat: add beacon detector for C2 heartbeat pattern detection"
> ```

---

### Step 6 — Threat Intel Integration
**What:** Query VirusTotal and AbuseIPDB for known malicious IPs/domains.
```
internal/enrichment/threatintel.go ← ThreatIntelEnricher — async, rate-limited HTTP calls
```
- Results are cached (Redis or in-memory TTL map) to avoid re-querying
- Rate limited: VirusTotal free = 4 req/min, AbuseIPDB = 1000 req/day
- Non-blocking: enrichment continues even if API is slow

> **Commit:**
> ```
> git commit -m "feat: add threat intel enrichment (VirusTotal + AbuseIPDB)"
> ```

---

### Step 7 — Enrichment Pipeline
**What:** Wire all enrichers into a single `Enrich()` call.
```
internal/enrichment/pipeline.go ← Enrich(ParseResult, cfg) → EnrichedResult
```
The parse command becomes: `Parse → Enrich → WriteJSON`.

> **Commit:**
> ```
> git commit -m "feat: wire enrichment pipeline (GeoIP + IOC + entropy + beacon + threat intel)"
> ```

---

### Step 8 — Go HTTP API Server
**What:** Expose enriched data as HTTP tool endpoints for LangGraph agents.
```
internal/api/server.go  ← HTTP server on :8765
```

Endpoints:
```
GET  /flows          → []EnrichedFlow
GET  /dns            → []DNSEvent
GET  /tls            → []TLSEvent
GET  /http           → []HTTPEvent
GET  /icmp           → []ICMPEvent
GET  /threats        → []ThreatContext  (IOC + threat intel hits)
GET  /beacons        → []BeaconCandidate
GET  /stats          → RawStats
```

> **Commit:**
> ```
> git commit -m "feat: add Go HTTP API server with tool endpoints for LangGraph"
> ```

---

### Step 9 — PostgreSQL Store (**COMPLETED**)
**What:** Persist enriched findings to PostgreSQL for audit trail and cross-job correlation.
- [x] Define GORM models for flows, DNS, HTTP, TLS, ICMP, and enriched data.
- [x] Implement `internal/store/postgres.go` with `AutoMigrate`.
- [x] Implement `SaveEnrichedResult` for batch persistence.
- [x] Integrate persistence into the output writer and main pipeline.
- [x] Update API server to query from Postgres if enabled.

> **Commit:**
> ```
> git commit -m "feat: add PostgreSQL store for enriched findings"
> ```

---

### Step 10 — Redis Job Queue (**COMPLETED**)
**What:** Publish and consume parse jobs from Redis for asynchronous processing.
- [x] Implement `internal/queue/redis.go` with Job publisher and consumer.
- [x] Add `worker` command to CLI to process jobs in the background.
- [x] Add `--async` flag to `parse` command to enqueue jobs.

> **Commit:**
> ```
> git commit -m "feat: add Redis job queue and worker mode"
> ```

---

### Step 11 — Wire CLI
**What:** Hook enrichment into `parse` and add `--serve` flag.
```
cmd/forensics/main.go   — enrichment into parse + --serve flag
```
`parse` → now runs the enrichment pipeline by default after parsing.
`--serve` → starts the HTTP API server after parsing/enrichment.

> **Commit:**
> ```
> git commit -m "feat: integrate enrichment into parse and add --serve flag"
> ```

---

### Step 12 — Docker Compose
**What:** Single command to bring up all infrastructure.
```
docker-compose.yml      ← postgres, redis, chromadb
Dockerfile.go           ← builds the forensics binary
```
`docker-compose up -d` → everything ready for `forensics serve`.

> **Commit:**
> ```
> git commit -m "feat: add Docker Compose for postgres, redis, and chromadb"
> ```

---

### Step 13 — Tests
Table-driven tests for:
```
internal/enrichment/geoip_test.go
internal/enrichment/ioc_test.go
internal/enrichment/entropy_test.go
internal/enrichment/beacon_test.go
internal/api/server_test.go
```

> **Commit:**
> ```
> git commit -m "test: add enrichment and API server tests"
> ```

---

## Summary

```
1.  Enriched models        ← shapes first
2.  GeoIP enrichment
3.  IOC matcher
4.  Entropy scorer
5.  Beacon detector
6.  Threat intel           ← async, rate-limited
7.  Enrichment pipeline    ← wire 2–6
8.  HTTP API server        ← LangGraph tool endpoints
9.  PostgreSQL store
10. Redis job queue
11. Wire CLI               ← serve + --enrich
12. Docker Compose
13. Tests
```

Steps 1–7 extend the parse pipeline.
Step 8 is the bridge to Phase 3 (LangGraph agents).
Steps 9–12 are infrastructure — can be done in parallel.
