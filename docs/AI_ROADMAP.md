# AI & Integration Roadmap

This document captures longer-horizon AI and integration ideas for the `wiremind`
architecture. Codex-ready TDD task prompts for these themes live in
[CODEX_TASK_PROMPTS.md](CODEX_TASK_PROMPTS.md), and active execution checklists
live in [CODEX_PHASE_CHECKLISTS.md](CODEX_PHASE_CHECKLISTS.md).

## 1. Agentic Engineering & GenAI Workflows
*   **Reasoning Loops (ReAct/CoT):** Upgrade the current LangGraph agents (DNS, TLS, HTTP, Lateral, Beacon) to use explicit reasoning loops. Instead of simple parallel nodes, implement a loop where agents can request more "packet context" from the Go API until they reach a definitive conclusion.
*   **Multi-Model Orchestration:** Introduce **Gemini 1.5 Pro (Vertex AI)** for long-context analysis (e.g., correlating thousands of flows across an entire PCAP) while keeping Claude for quick, focused tactical analysis.
*   **Tool-Calling:** Refine the JSON tool-calling interface between Python agents and the Go API to allow agents to "deep-dive" into specific hex payloads or request entropy calculations on-the-fly.

## 2. AI Cost Governance

The canonical cost plan lives in [AI_COSTING.md](AI_COSTING.md). The execution
lane is Phase 8B in [CODEX_PHASE_CHECKLISTS.md](CODEX_PHASE_CHECKLISTS.md).

*   **Provider-Neutral Pricing:** Load model prices from config or versioned fixtures by provider, model, currency, unit size, and effective date. Do not hardcode current vendor prices in tests or runtime code.
*   **Budget Gates:** Estimate input/output token cost before each future model call, reserve budget, and fail closed with structured `budget_exhausted` metadata when budget is insufficient.
*   **Actual Usage Accounting:** Reconcile preflight estimates with fake-provider usage first, then provider-reported tokens after live integrations exist.
*   **Cost Observability:** Track selected provider, model, purpose, token usage, estimated cost, actual cost, budget remaining, skipped-call reason, fallback reason, and pricing version in traces/logs/reports without raw prompt or packet content.
*   **Optimization Loop:** Measure spend next to quality metrics such as precision, recall, evidence completeness, severity correctness, cost per finding, and cost per confirmed true positive.

## 3. Data Foundation & AI Pipelines
*   **Unstructured Ingestion:** Create a `python/ingestion` service to process security advisories (PDFs), vendor blogs, and threat reports. Use **Vertex AI Search** to index these into the ChromaDB vector store so agents have "current" threat intelligence.
*   **Automated dbt/Dataform:** Implement a pipeline to transform raw PostgreSQL flow data into "AI-ready" tables (e.g., flattening nested TLS fields, calculating delta-T between flows) to simplify LLM prompt context.
*   **AI Observability:** Integrate **RAGAS** or **Vertex AI Evaluation** to measure agent precision and recall against known malware PCAP "ground truth" labels.

## 4. Integration & Cloud-Native Development
*   **Terraform IaC:** Provide a `deploy/terraform` directory to spin up the entire stack on Google Cloud:
    *   **Cloud Run:** For the Go API and Python Agent Orchestra.
    *   **Cloud SQL:** Managed PostgreSQL.
    *   **Memorystore:** Managed Redis for the job queue.
    *   **Vertex AI:** For Gemini and embedding models.
*   **Event-Driven Workflows:** Use **Google Cloud Pub/Sub** to trigger a wiremind scan whenever a new PCAP is dropped into a GCS bucket. Use **Cloud Workflows** to orchestrate the end-to-end process from ingestion to Slack/Jira reporting.
*   **Legacy Integration:** Build a secure webhook bridge to push findings into common Enterprise SOC tools (ServiceNow, Jira, or custom proprietary databases) as suggested in the brainstorm.

## 5. Agile Execution & Quality
*   **Daily Contributions:** Define a clear Definition of Done (DoD) for new agent types:
    1.  Test PCAP provided.
    2.  Go extractor implemented.
    3.  Python agent reasoning loop tested.
    4.  MITRE ATT&CK mapping verified.
*   **Technical Validation:** Maintain a "Gold Standard" PCAP library for regression testing of the AI reasoning logic.
