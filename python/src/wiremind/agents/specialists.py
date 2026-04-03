from typing import Dict, Any, List, Optional
from wiremind.client import WiremindClient
from wiremind.state import ForensicsState
from wiremind.knowledge.consultant import SecurityConsultant

class DNSAgent:
    def __init__(self, client: WiremindClient, consultant: Optional[SecurityConsultant] = None):
        self.client = client
        self.consultant = consultant

    async def run(self, state: ForensicsState) -> Dict[str, Any]:
        """
        Analyzes DNS logs for potential threats.
        """
        dns_logs = await self.client.get_dns()
        findings = []

        # Analyze DNS queries
        for log in dns_logs:
            query = log.get("query", "")
            # Basic DGA detection (placeholder for real logic)
            if len(query) > 30 and "." in query:
                finding = {
                    "agent": "DNSAgent",
                    "type": "DNS_DGA_SUSPICION",
                    "query": query,
                    "confidence": 0.7,
                    "severity": "HIGH",
                    "description": f"Long query string detected: {query}",
                    "details": "Long query string detected"
                }
                
                # Enrich with MITRE context if consultant is available
                if self.consultant:
                    finding["mitre_context"] = self.consultant.search_mitre("DNS tunneling " + query, k=1)
                
                findings.append(finding)

            # Check for NXDOMAIN spikes (if status is available)
            if log.get("status") == "NXDOMAIN":
                 findings.append({
                    "agent": "DNSAgent",
                    "type": "DNS_NXDOMAIN",
                    "query": query,
                    "confidence": 0.5,
                    "severity": "MEDIUM",
                    "description": f"Query resulted in NXDOMAIN: {query}",
                    "details": "Query resulted in NXDOMAIN"
                })

        return {"findings": findings}

class TLSAgent:
    def __init__(self, client: WiremindClient, consultant: Optional[SecurityConsultant] = None):
        self.client = client
        self.consultant = consultant

    async def run(self, state: ForensicsState) -> Dict[str, Any]:
        """
        Analyzes TLS handshakes for anomalies.
        """
        tls_logs = await self.client.get_tls()
        findings = []

        for log in tls_logs:
            sni = log.get("sni", "")
            # Placeholder for SNI mismatch check
            if sni and "google" in sni and log.get("dest_ip") != "8.8.8.8":
                # Real check would involve IP reputation or ownership
                pass

            # Cipher suite analysis (check for weak/deprecated)
            cipher = log.get("cipher_suite", "")
            if cipher and "RC4" in cipher:
                 findings.append({
                    "agent": "TLSAgent",
                    "type": "TLS_WEAK_CIPHER",
                    "sni": sni,
                    "cipher": cipher,
                    "confidence": 0.9,
                    "severity": "HIGH",
                    "description": f"Weak cipher detected: {cipher} for {sni}",
                    "details": "Weak/deprecated cipher suite detected"
                })

        return {"findings": findings}

class HTTPAgent:
    def __init__(self, client: WiremindClient, consultant: Optional[SecurityConsultant] = None):
        self.client = client
        self.consultant = consultant

    async def run(self, state: ForensicsState) -> Dict[str, Any]:
        """
        Analyzes HTTP requests for suspicious patterns.
        """
        http_logs = await self.client.get_http()
        findings = []

        for log in http_logs:
            ua = log.get("user_agent", "")
            # Unusual User-Agent strings
            if ua and ("python-requests" in ua.lower() or "curl" in ua.lower()):
                 findings.append({
                    "agent": "HTTPAgent",
                    "type": "HTTP_CLI_AGENT",
                    "user_agent": ua,
                    "confidence": 0.4,
                    "severity": "LOW",
                    "description": f"CLI agent detected: {ua}",
                    "details": f"Command-line client detected: {ua}"
                })

        return {"findings": findings}

class LateralMovementAgent:
    def __init__(self, client: WiremindClient, consultant: Optional[SecurityConsultant] = None):
        self.client = client
        self.consultant = consultant

    async def run(self, state: ForensicsState) -> Dict[str, Any]:
        """
        Analyzes internal flows for lateral movement signatures.
        """
        flows = await self.client.get_flows()
        findings = []

        for flow in flows:
            # Check for internal-to-internal flows (assuming private RFC1918)
            src_ip = flow.get("src_ip", "")
            dest_ip = flow.get("dest_ip", "")
            
            # Simple private IP check (placeholder)
            if src_ip.startswith(("10.", "192.168.", "172.")):
                if dest_ip.startswith(("10.", "192.168.", "172.")):
                    # Potential lateral movement if port is sensitive
                    port = flow.get("dest_port")
                    if port in [445, 135, 139]: # SMB/RPC
                         findings.append({
                            "agent": "LateralMovementAgent",
                            "type": "LATERAL_MOVEMENT_SMB",
                            "src_ip": src_ip,
                            "dest_ip": dest_ip,
                            "confidence": 0.6,
                            "severity": "MEDIUM",
                            "description": f"Internal SMB flow: {src_ip} -> {dest_ip}",
                            "details": f"Internal SMB flow: {src_ip} -> {dest_ip}"
                        })

        return {"findings": findings}

class BeaconingAgent:
    def __init__(self, client: WiremindClient, consultant: Optional[SecurityConsultant] = None):
        self.client = client
        self.consultant = consultant

    async def run(self, state: ForensicsState) -> Dict[str, Any]:
        """
        Validates beaconing scores from the Go engine.
        """
        flows = await self.client.get_flows()
        findings = []

        for flow in flows:
            enriched = flow.get("enriched", {})
            if enriched.get("beacon"):
                findings.append({
                    "agent": "BeaconingAgent",
                    "type": "C2_BEACONING",
                    "src_ip": flow.get("src_ip"),
                    "dest_ip": flow.get("dest_ip"),
                    "confidence": enriched.get("beacon_score", 0.8),
                    "severity": "HIGH",
                    "description": f"C2 Beaconing detected: {flow.get('src_ip')} -> {flow.get('dest_ip')}",
                    "details": "Consistent jitter detected in flow"
                })

        return {"findings": findings}
