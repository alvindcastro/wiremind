import pytest
import httpx
from wiremind.client import WiremindClient

@pytest.fixture
async def client():
    client = WiremindClient(base_url="http://mock-api")
    yield client
    await client.close()

@pytest.mark.asyncio
async def test_get_flows(client, respx_mock):
    respx_mock.get("http://mock-api/api/v1/flows").mock(return_value=httpx.Response(200, json=[{"id": "flow1"}]))
    flows = await client.get_flows()
    assert len(flows) == 1
    assert flows[0]["id"] == "flow1"

@pytest.mark.asyncio
async def test_get_stats(client, respx_mock):
    respx_mock.get("http://mock-api/api/v1/stats").mock(return_value=httpx.Response(200, json={"total_flows": 10}))
    stats = await client.get_stats()
    assert stats["total_flows"] == 10

@pytest.mark.asyncio
async def test_api_error(client, respx_mock):
    respx_mock.get("http://mock-api/api/v1/flows").mock(return_value=httpx.Response(500))
    with pytest.raises(httpx.HTTPStatusError):
        await client.get_flows()
