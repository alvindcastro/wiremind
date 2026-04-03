from typing import Dict, Any, List, Optional, Literal, Annotated, TypedDict
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage, SystemMessage
from langgraph.graph import StateGraph, END
from wiremind.state import ForensicsState
from wiremind.client import WiremindClient
from wiremind.agents.specialists import DNSAgent, TLSAgent, HTTPAgent, LateralMovementAgent, BeaconingAgent
from wiremind.knowledge.consultant import SecurityConsultant

class Orchestrator:
    """
    Main LangGraph-based Orchestrator for Wiremind.
    It coordinates between specialists and manages the analysis flow.
    """
    def __init__(self, client: WiremindClient, consultant: Optional[SecurityConsultant] = None):
        self.client = client
        self.consultant = consultant
        self.dns_agent = DNSAgent(client, consultant)
        self.tls_agent = TLSAgent(client, consultant)
        self.http_agent = HTTPAgent(client, consultant)
        self.lateral_agent = LateralMovementAgent(client, consultant)
        self.beacon_agent = BeaconingAgent(client, consultant)

    def _should_continue(self, state: ForensicsState) -> Literal["dns", "tls", "http", "lateral", "beacon", "end"]:
        """
        Routing logic for the graph. In a real LLM implementation, 
        this would be a decision by the Supervisor LLM.
        """
        # Current logic: execute agents in sequence for complete analysis
        # In the future, this will be dynamic based on findings
        
        # Simple sequence control using a temporary list in state (if we had one)
        # For now, let's look at what's missing in findings
        if not any(f.get("type").startswith("DNS") for f in state["findings"]):
            return "dns"
        if not any(f.get("type").startswith("TLS") for f in state["findings"]):
            return "tls"
        if not any(f.get("type").startswith("HTTP") for f in state["findings"]):
            return "http"
        if not any(f.get("type").startswith("LATERAL") for f in state["findings"]):
            return "lateral"
        if not any(f.get("type").startswith("C2") for f in state["findings"]):
            return "beacon"
        
        return "end"

    async def call_dns(self, state: ForensicsState) -> ForensicsState:
        result = await self.dns_agent.run(state)
        state["findings"].extend(result["findings"])
        return state

    async def call_tls(self, state: ForensicsState) -> ForensicsState:
        result = await self.tls_agent.run(state)
        state["findings"].extend(result["findings"])
        return state

    async def call_http(self, state: ForensicsState) -> ForensicsState:
        result = await self.http_agent.run(state)
        state["findings"].extend(result["findings"])
        return state

    async def call_lateral(self, state: ForensicsState) -> ForensicsState:
        result = await self.lateral_agent.run(state)
        state["findings"].extend(result["findings"])
        return state

    async def call_beacon(self, state: ForensicsState) -> ForensicsState:
        result = await self.beacon_agent.run(state)
        state["findings"].extend(result["findings"])
        return state

    def create_graph(self):
        """Creates the LangGraph workflow."""
        workflow = StateGraph(ForensicsState)

        # Define nodes
        workflow.add_node("dns", self.call_dns)
        workflow.add_node("tls", self.call_tls)
        workflow.add_node("http", self.call_http)
        workflow.add_node("lateral", self.call_lateral)
        workflow.add_node("beacon", self.call_beacon)

        # Build graph
        workflow.set_entry_point("dns") # Start with DNS usually
        
        workflow.add_edge("dns", "tls")
        workflow.add_edge("tls", "http")
        workflow.add_edge("http", "lateral")
        workflow.add_edge("lateral", "beacon")
        workflow.add_edge("beacon", END)

        return workflow.compile()

    async def run(self, initial_state: Optional[ForensicsState] = None) -> ForensicsState:
        """Executes the orchestrator graph."""
        if initial_state is None:
            initial_state = {
                "findings": [],
                "evidence": {},
                "mitre_mapping": {},
                "pending_tasks": ["initial_analysis"]
            }
        
        app = self.create_graph()
        final_state = await app.ainvoke(initial_state)
        return final_state
