from typing import Any, List, Optional
from pydantic import BaseModel, Field
from wiremind.client import WiremindClient
from wiremind.tools.base import WiremindTool

class SearchQuery(BaseModel):
    ip: Optional[str] = Field(None, description="Filter by IP address (Source or Destination)")
    port: Optional[int] = Field(None, description="Filter by Port number")
    protocol: Optional[str] = Field(None, description="Filter by Protocol (tcp, udp, icmp)")
    sni: Optional[str] = Field(None, description="Filter by TLS SNI")

class CoreTools:
    """
    Collection of core tools for agents to interact with the Wiremind API.
    """
    def __init__(self, client: WiremindClient):
        self.client = client

    @WiremindTool(
        name="search_flows",
        description="Search and filter network flows based on IP, port, protocol, or SNI.",
        args_schema=SearchQuery
    )
    async def search_flows(self, query: SearchQuery) -> List[dict]:
        flows = await self.client.get_flows()
        
        filtered = []
        for flow in flows:
            if query.ip and (flow.get("src_ip") == query.ip or flow.get("dest_ip") == query.ip):
                filtered.append(flow)
                continue
            if query.port and (flow.get("src_port") == query.port or flow.get("dest_port") == query.port):
                filtered.append(flow)
                continue
            if query.protocol and flow.get("protocol") == query.protocol:
                filtered.append(flow)
                continue
            
            # For SNI we need to check if it's enriched or check TLS logs (simplified here)
            if query.sni:
                # In a real implementation we'd join with TLS logs
                pass

        return filtered[:50] # Limit to 50 results

    @WiremindTool(
        name="get_stats",
        description="Get high-level statistics of the captured traffic (flow counts, protocol breakdown).",
    )
    async def get_stats(self) -> dict:
        return await self.client.get_stats()

    @WiremindTool(
        name="deep_dive_ip",
        description="Aggregate all evidence (DNS, TLS, HTTP, ICMP) for a specific IP address.",
        args_schema=SearchQuery # Reusing SearchQuery for the IP field
    )
    async def deep_dive_ip(self, query: SearchQuery) -> dict:
        if not query.ip:
            return {"error": "IP address is required for deep dive"}
        
        ip = query.ip
        evidence = {
            "flows": [],
            "dns": [],
            "tls": [],
            "http": []
        }
        
        # This is a bit heavy-weight, but standard for a forensics 'deep dive'
        all_flows = await self.client.get_flows()
        evidence["flows"] = [f for f in all_flows if f.get("src_ip") == ip or f.get("dest_ip") == ip]
        
        all_dns = await self.client.get_dns()
        evidence["dns"] = [d for d in all_dns if ip in (d.get("client_ip", ""), d.get("server_ip", ""))]
        
        all_tls = await self.client.get_tls()
        evidence["tls"] = [t for t in all_tls if ip in (t.get("src_ip", ""), t.get("dest_ip", ""))]
        
        all_http = await self.client.get_http()
        evidence["http"] = [h for h in all_http if ip in (h.get("src_ip", ""), h.get("dest_ip", ""))]
        
        return evidence
