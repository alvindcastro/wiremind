import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock
from wiremind.client import WiremindClient
from wiremind.agents.orchestrator import Orchestrator
from wiremind.tools.core import CoreTools, SearchQuery
from wiremind.tools.base import ToolRegistry

@pytest.fixture
def mock_client():
    client = MagicMock(spec=WiremindClient)
    client.get_flows = AsyncMock(return_value=[
        {"src_ip": "10.0.0.1", "dest_ip": "8.8.8.8", "protocol": "udp", "dest_port": 53},
        {"src_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "protocol": "tcp", "dest_port": 445}
    ])
    client.get_dns = AsyncMock(return_value=[
        {"query": "malicious.domain.com", "client_ip": "10.0.0.1", "status": "NXDOMAIN"}
    ])
    client.get_tls = AsyncMock(return_value=[
        {"sni": "suspicious.site", "src_ip": "10.0.0.1", "cipher_suite": "TLS_RSA_WITH_RC4_128_SHA"}
    ])
    client.get_http = AsyncMock(return_value=[
        {"user_agent": "curl/7.68.0", "src_ip": "10.0.0.1"}
    ])
    client.get_stats = AsyncMock(return_value={"total_flows": 2})
    return client

@pytest_asyncio.fixture
async def orchestrator(mock_client):
    return Orchestrator(mock_client)

@pytest.mark.asyncio
async def test_orchestrator_run(orchestrator):
    initial_state = {
        "findings": [],
        "evidence": {},
        "mitre_mapping": {},
        "pending_tasks": []
    }
    
    final_state = await orchestrator.run(initial_state)
    
    assert "findings" in final_state
    # Check if we have findings from different specialists
    types = [f["type"] for f in final_state["findings"]]
    assert "DNS_NXDOMAIN" in types
    assert "TLS_WEAK_CIPHER" in types
    assert "HTTP_CLI_AGENT" in types
    assert "LATERAL_MOVEMENT_SMB" in types

@pytest.mark.asyncio
async def test_core_tools(mock_client):
    tools = CoreTools(mock_client)
    
    # Test search_flows
    query = SearchQuery(ip="10.0.0.1")
    results = await tools.search_flows(query)
    assert len(results) == 2
    
    # Test get_stats
    stats = await tools.get_stats()
    assert stats["total_flows"] == 2
    
    # Test deep_dive_ip
    dive = await tools.deep_dive_ip(SearchQuery(ip="10.0.0.1"))
    assert len(dive["flows"]) == 2
    assert len(dive["dns"]) == 1
    assert len(dive["tls"]) == 1
    assert len(dive["http"]) == 1

def test_tool_registry():
    registry = ToolRegistry()
    mock_client_inst = MagicMock(spec=WiremindClient)
    tools = CoreTools(mock_client_inst)
    
    registry.register(tools.search_flows)
    registry.register(tools.get_stats)
    
    registered = registry.list_tools()
    assert len(registered) == 2
    assert any(t.name == "search_flows" for t in registered)
    assert any(t.name == "get_stats" for t in registered)
