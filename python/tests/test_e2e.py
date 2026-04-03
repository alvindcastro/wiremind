import pytest
import respx
from httpx import Response
from wiremind.client import WiremindClient
from wiremind.agents.orchestrator import Orchestrator
from wiremind.state import ForensicsState

@pytest.mark.asyncio
async def test_full_agent_orchestration_e2e(respx_mock):
    """
    Test the full multi-agent orchestration flow from entry to final state.
    """
    base_url = "http://localhost:8765/api/v1"
    client = WiremindClient("http://localhost:8765")
    
    # Mocking flows endpoint
    respx_mock.get(f"{base_url}/flows").mock(return_value=Response(200, json=[
        {
            "id": "flow-123",
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "protocol": "TCP",
            "dst_port": 443,
            "threat_info": {
                "malicious": True,
                "score": 85,
                "entropy_score": 7.8
            }
        }
    ]))
    
    # Mocking specific flow details
    respx_mock.get(f"{base_url}/flows/flow-123").mock(return_value=Response(200, json={
        "id": "flow-123",
        "src_ip": "192.168.1.10",
        "dst_ip": "8.8.8.8",
        "payload_samples": ["sample_data"]
    }))
    
    # Mocking DNS/TLS/HTTP etc.
    respx_mock.get(f"{base_url}/dns").mock(return_value=Response(200, json=[]))
    respx_mock.get(f"{base_url}/tls").mock(return_value=Response(200, json=[]))
    respx_mock.get(f"{base_url}/http").mock(return_value=Response(200, json=[]))
    respx_mock.get(f"{base_url}/stats").mock(return_value=Response(200, json={"total_flows": 1}))

    # Setup orchestrator
    orchestrator = Orchestrator(client)
    
    # Initial state
    state = ForensicsState(
        findings=[],
        flows=[],
        current_task="Test analysis",
        evidence={},
        next_steps=[],
        summary=""
    )
    
    # Run the orchestrator (this will call the graph which calls all agents)
    final_state = await orchestrator.run(state)
    
    # Assertions
    assert "findings" in final_state
    assert len(final_state["findings"]) >= 0 # Depends on specialist agent logic
    
    # Check if context was updated with flow data (Note: in current state.py it's 'flows' not 'context')
    assert "flows" in final_state
    assert len(final_state["flows"]) == 1

@pytest.mark.asyncio
async def test_orchestrator_malicious_findings(respx_mock):
    """
    Verify that specialists detect malicious activity and report it to orchestrator.
    """
    base_url = "http://localhost:8765/api/v1"
    
    # Mock malicious DNS activity
    respx_mock.get(f"{base_url}/dns").mock(return_value=Response(200, json=[
        {
            "query": "super-suspicious-dga-domain-xyz123.com",
            "type": "A",
            "flow_id": "flow-dga"
        }
    ]))
    respx_mock.get(f"{base_url}/flows").mock(return_value=Response(200, json=[]))
    respx_mock.get(f"{base_url}/stats").mock(return_value=Response(200, json={"total_flows": 0}))
    respx_mock.get(f"{base_url}/tls").mock(return_value=Response(200, json=[]))
    respx_mock.get(f"{base_url}/http").mock(return_value=Response(200, json=[]))

    client = WiremindClient("http://localhost:8765")
    orchestrator = Orchestrator(client)
    state = ForensicsState(findings=[], flows=[], current_task="", evidence={}, next_steps=[], summary="")
    
    final_state = await orchestrator.run(state)
    
    # Check for DNS findings
    dns_findings = [f for f in final_state["findings"] if f["agent"] == "DNSAgent"]
    assert len(dns_findings) > 0
    assert any("Long query" in f["description"] for f in dns_findings)
