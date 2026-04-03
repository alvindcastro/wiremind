import pytest
from unittest.mock import AsyncMock
from wiremind.agents.specialists import (
    DNSAgent, TLSAgent, HTTPAgent, LateralMovementAgent, BeaconingAgent
)
from wiremind.state import ForensicsState

@pytest.fixture
def mock_client():
    return AsyncMock()

@pytest.fixture
def empty_state():
    return ForensicsState(
        flows=[],
        findings=[],
        current_task="Test Task",
        evidence={},
        next_steps=[],
        summary=""
    )

@pytest.mark.asyncio
async def test_dns_agent(mock_client, empty_state):
    mock_client.get_dns.return_value = [
        {"query": "extremelylongdganameprobalytoolong.com", "status": "NOERROR"},
        {"query": "legit.com", "status": "NXDOMAIN"}
    ]
    agent = DNSAgent(mock_client)
    result = await agent.run(empty_state)
    
    assert len(result["findings"]) == 2
    assert result["findings"][0]["type"] == "DNS_DGA_SUSPICION"
    assert result["findings"][1]["type"] == "DNS_NXDOMAIN"

@pytest.mark.asyncio
async def test_tls_agent(mock_client, empty_state):
    mock_client.get_tls.return_value = [
        {"sni": "google.com", "cipher_suite": "TLS_RSA_WITH_RC4_128_SHA"}
    ]
    agent = TLSAgent(mock_client)
    result = await agent.run(empty_state)
    
    assert len(result["findings"]) == 1
    assert result["findings"][0]["type"] == "TLS_WEAK_CIPHER"

@pytest.mark.asyncio
async def test_http_agent(mock_client, empty_state):
    mock_client.get_http.return_value = [
        {"user_agent": "curl/7.68.0"}
    ]
    agent = HTTPAgent(mock_client)
    result = await agent.run(empty_state)
    
    assert len(result["findings"]) == 1
    assert result["findings"][0]["type"] == "HTTP_CLI_AGENT"

@pytest.mark.asyncio
async def test_lateral_movement_agent(mock_client, empty_state):
    mock_client.get_flows.return_value = [
        {"src_ip": "192.168.1.10", "dest_ip": "10.0.0.5", "dest_port": 445}
    ]
    agent = LateralMovementAgent(mock_client)
    result = await agent.run(empty_state)
    
    assert len(result["findings"]) == 1
    assert result["findings"][0]["type"] == "LATERAL_MOVEMENT_SMB"

@pytest.mark.asyncio
async def test_beaconing_agent(mock_client, empty_state):
    mock_client.get_flows.return_value = [
        {
            "src_ip": "1.1.1.1", 
            "dest_ip": "8.8.8.8", 
            "enriched": {"beacon": True, "beacon_score": 0.95}
        }
    ]
    agent = BeaconingAgent(mock_client)
    result = await agent.run(empty_state)
    
    assert len(result["findings"]) == 1
    assert result["findings"][0]["type"] == "C2_BEACONING"
    assert result["findings"][0]["confidence"] == 0.95
