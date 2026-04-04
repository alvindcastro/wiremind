# NICE_TO_HAVE.md — Wiremind Feature Backlog

This document tracks "nice to have" features and future enhancements that are outside the core MVP but would add significant value to the project.

---

## 🎨 Visualization & UI

> **Full plan is in [UI_PLAN.md](UI_PLAN.md)** — phased breakdown, tech stack decision,
> tasks, and WebStorm setup. The items below are now tracked there.

- [x] **Step N1: Web Dashboard** → Phase 4 in UI_PLAN.md
- [x] **Step N2: Flow Graph Visualization** → Phase 5 in UI_PLAN.md (Cytoscape.js)
- [ ] **Step N3: Real-time Stats Terminal UI (TUI)**
  - A `bubbletea` based TUI for the CLI to show live parsing progress and top talkers.

## 🔍 Advanced Protocol Extractors
- [ ] **Step N4: SMB/RPC Extractor**
  - Parse SMB commands (file access, tree connect) for lateral movement detection.
  - Extract RPC calls for sensitive service enumeration.
- [ ] **Step N5: Database Protocol Parsers**
  - Support MySQL/Postgres/MSSQL protocol extraction.
  - Detect SQL injection or unauthorized data access in cleartext traffic.
- [ ] **Step N6: Industrial/OT Protocols**
  - Support Modbus, DNP3, or BACnet for ICS/SCADA forensics.

## 🤖 Enhanced AI & ML
- [ ] **Step N7: Local LLM Support**
  - Integrate with Ollama or vLLM to allow running agents fully offline for air-gapped environments.
- [ ] **Step N8: Anomaly Detection Models**
  - Use lightweight ML models (Isolation Forest, etc.) in Go to flag statistically unusual flows before agent analysis.
- [ ] **Step N9: Automated PCAP Masking**
  - AI-driven PII/Sensitive data masking in PCAP payloads before sending to cloud LLMs.

## 🛠 Tooling & Integration
- [ ] **Step N10: Wireshark Plugin (Lua)**
  - A Wireshark plugin that calls the Wiremind API to show "Agent Verdicts" directly in the Wireshark UI.
- [ ] **Step N11: EDR/SIEM Export**
  - Direct export to Splunk HEC, Elastic Common Schema (ECS), or Sentinel.
- [ ] **Step N12: PCAP Carving**
  - Automatically extract files (EXEs, PDFs, ZIPs) from HTTP/SMB streams and send them to a sandbox (e.g., Cuckoo or Any.Run).

## 🛡 Security & Hardening
- [ ] **Step N13: Encrypted Database**
  - Support transparent data encryption (TDE) for the PostgreSQL store.
- [ ] **Step N14: Audit Logging**
  - Full audit trail of which analyst viewed which finding and what modifications they made.
- [ ] **Step N15: Multi-tenancy**
  - Support multiple organizations/clients in the same database with strict data isolation.
