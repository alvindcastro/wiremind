import httpx
from typing import List, Dict, Any, Optional

class WiremindClient:
    def __init__(self, base_url: str = "http://localhost:8765"):
        self.base_url = f"{base_url.rstrip('/')}/api/v1"
        self.client = httpx.AsyncClient(timeout=30.0)

    async def close(self):
        await self.client.aclose()

    async def get_flows(self) -> List[Dict[str, Any]]:
        response = await self.client.get(f"{self.base_url}/flows")
        response.raise_for_status()
        return response.json()

    async def get_dns(self) -> List[Dict[str, Any]]:
        response = await self.client.get(f"{self.base_url}/dns")
        response.raise_for_status()
        return response.json()

    async def get_http(self) -> List[Dict[str, Any]]:
        response = await self.client.get(f"{self.base_url}/http")
        response.raise_for_status()
        return response.json()

    async def get_tls(self) -> List[Dict[str, Any]]:
        response = await self.client.get(f"{self.base_url}/tls")
        response.raise_for_status()
        return response.json()

    async def get_icmp(self) -> List[Dict[str, Any]]:
        response = await self.client.get(f"{self.base_url}/icmp")
        response.raise_for_status()
        return response.json()

    async def get_stats(self) -> Dict[str, Any]:
        response = await self.client.get(f"{self.base_url}/stats")
        response.raise_for_status()
        return response.json()
