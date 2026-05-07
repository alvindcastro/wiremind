# AI & Integration Roadmap (from Brainstorming)

This document maps the ideas from `docs/brainstorm.txt` to the `wiremind` architecture.

## 1. Agentic Engineering & GenAI Workflows
*   **Reasoning Loops (ReAct/CoT):** Upgrade the current LangGraph agents (DNS, TLS, HTTP, Lateral, Beacon) to use explicit reasoning loops. Instead of simple parallel nodes, implement a loop where agents can request more "packet context" from the Go API until they reach a definitive conclusion.
*   **Multi-Model Orchestration:** Introduce **Gemini 1.5 Pro (Vertex AI)** for long-context analysis (e.g., correlating thousands of flows across an entire PCAP) while keeping Claude for quick, focused tactical analysis.
*   **Tool-Calling:** Refine the JSON tool-calling interface between Python agents and the Go API to allow agents to "deep-dive" into specific hex payloads or request entropy calculations on-the-fly.

## 2. Data Foundation & AI Pipelines
*   **Unstructured Ingestion:** Create a `python/ingestion` service to process security advisories (PDFs), vendor blogs, and threat reports. Use **Vertex AI Search** to index these into the ChromaDB vector store so agents have "current" threat intelligence.
*   **Automated dbt/Dataform:** Implement a pipeline to transform raw PostgreSQL flow data into "AI-ready" tables (e.g., flattening nested TLS fields, calculating delta-T between flows) to simplify LLM prompt context.
*   **AI Observability:** Integrate **RAGAS** or **Vertex AI Evaluation** to measure agent precision and recall against known malware PCAP "ground truth" labels.

## 3. Integration & Cloud-Native Development
*   **Terraform IaC:** Provide a `deploy/terraform` directory to spin up the entire stack on Google Cloud:
    *   **Cloud Run:** For the Go API and Python Agent Orchestra.
    *   **Cloud SQL:** Managed PostgreSQL.
    *   **Memorystore:** Managed Redis for the job queue.
    *   **Vertex AI:** For Gemini and embedding models.
*   **Event-Driven Workflows:** Use **Google Cloud Pub/Sub** to trigger a wiremind scan whenever a new PCAP is dropped into a GCS bucket. Use **Cloud Workflows** to orchestrate the end-to-end process from ingestion to Slack/Jira reporting.
*   **Legacy Integration:** Build a secure webhook bridge to push findings into common Enterprise SOC tools (ServiceNow, Jira, or custom proprietary databases) as suggested in the brainstorm.

## 4. Agile Execution & Quality
*   **Daily Contributions:** Define a clear Definition of Done (DoD) for new agent types:
    1.  Test PCAP provided.
    2.  Go extractor implemented.
    3.  Python agent reasoning loop tested.
    4.  MITRE ATT&CK mapping verified.
*   **Technical Validation:** Maintain a "Gold Standard" PCAP library for regression testing of the AI reasoning logic.
