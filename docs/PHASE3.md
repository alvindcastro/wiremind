### Phase 3: LangGraph AI Agents (Python)

This phase focuses on the integration of Large Language Models (LLMs) and LangGraph to create an autonomous network forensics analysis system. The Python-based agents will consume data from the Go API, analyze it using specialized security knowledge, and correlate findings into human-readable attack chains.

---

#### 🏗️ Phase 3.1: Python Infrastructure & Base Setup
- [x] **Step 1: Project Skeleton**
  - Initialize `python/` directory with `pyproject.toml` (Poetry/UV).
  - Install core dependencies: `langchain`, `langgraph`, `pydantic`, `httpx`, `fastapi`.
- [x] **Step 2: API Client Layer**
  - Implement a Python client to interact with the Wiremind Go API (`/api/v1/flows`, `/dns`, etc.).
  - Add robust error handling and retry logic for network stability.
- [x] **Step 3: State Management**
  - Define the global `ForensicsState` for LangGraph (current findings, pending tasks, evidence graph).

#### 🕵️ Phase 3.2: Specialist Agents (The "Expert Council")
- [x] **Step 4: DNS Specialist Agent**
  - Focus: DGA detection, Tunneling, and NXDOMAIN spikes.
  - Tools: GeoIP lookup, WHOIS enrichment, passive DNS history.
- [x] **Step 5: TLS/HTTP Specialist Agent**
  - Focus: JA3/JA4 fingerprinting, SNI mismatches, and unusual User-Agents.
  - Tools: Cipher suite analysis, certificate validation.
- [x] **Step 6: Lateral Movement Agent**
  - Focus: Internal scanning, RPC/SMB anomalies, and credential spraying.
  - Tools: Internal flow mapping, hop-count analysis.
- [x] **Step 7: Beaconing & C2 Agent**
  - Focus: Validating jitter/entropy scores from the Go engine.
  - Tools: Time-series analysis, known C2 profile matching.

#### 📚 Phase 3.3: RAG & Knowledge Store
- [x] **Step 8: Knowledge Base Integration**
  - Implement a document store for historical analysis and threat intel.
  - Added fallback keyword-based matching for environment compatibility (Windows/Torch).
- [x] **Step 9: Local Knowledge Base**
  - Ingested MITRE ATT&CK techniques and internal security playbooks.
  - Implemented `SecurityConsultant` tool for agents to query best practices.

#### 🎮 Phase 3.4: Orchestrator & Multi-Agent Flow
- [x] **Step 10: The Orchestrator (Supervisor)**
  - Implement the main LangGraph router to dispatch tasks to specialists.
  - Handle task prioritization based on initial risk scores from the Go engine.
- [x] **Step 11: Tooling Interface**
  - Create a standardized `WiremindTool` decorator for all agent actions.
  - Implement a "Search" tool for agents to deep-dive into specific flows.

#### 🏁 Phase 3.5: AI Integration Verification & End-to-End Tests
- [x] **Step 12: AI Forensics Entry Point**
  - Implement `python/src/wiremind/main.py` as the main CLI for AI analysis.
  - Added automated flow discovery and orchestrator invocation.
- [x] **Step 13: End-to-End Orchestration Tests**
  - Developed `python/tests/test_e2e.py` to verify multi-agent collaboration.
  - Mocked full API response lifecycle for DNS, TLS, HTTP, and Flow analytics.
- [x] **Step 14: Test Infrastructure Hardening**
  - Configured `pytest-asyncio` auto-mode and consolidated settings in `pyproject.toml`.
  - Refactored specialist findings to include structured `severity` and `description` fields for reporting.

#### 🔗 Phase 3.6: Correlation & Reporting
- [x] **Step 15: Attack Chain Constructor**
  - Implement `AttackChainConstructor` in `python/src/wiremind/agents/correlation.py`.
  - Logic to link disparate findings (e.g., DNS lookup -> TLS connection -> Data exfiltration).
  - Mapping findings to MITRE ATT&CK techniques based on specialist agent labels.
- [x] **Step 16: Executive Summary Generator**
  - Implement `SummaryGenerator` in `python/src/wiremind/agents/reporting.py`.
  - Use structured finding data to generate human-readable summaries for SOC analysts.
  - Export final reports in Markdown/JSON formats via the main CLI entry point.
- [x] **Step 17: Correlation & Reporting Tests**
  - Create `python/tests/test_correlation.py` and `python/tests/test_reporting.py` to verify logic.
  - Integrated into the existing end-to-end test suite.

---

#### 🚀 Future Outlook (Phase 4+)
- **Active Response:** Suggesting firewall rules or EDR isolation.
- **Human-in-the-Loop:** Interactive CLI/UI for steering agent investigations.
- **Multimodal Analysis:** Analyzing screenshots of malicious payloads or PCAP-to-Image visualizations.
