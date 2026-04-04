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

        # API returns EnrichedDNSEvent: {"event": {"questions": [{"name": ...}], "rcode": ..., ...}, ...}
        for log in dns_logs:
            event = log.get("event", {})
            rcode = event.get("rcode", "")
            questions = event.get("questions") or []

            for q in questions:
                query = q.get("name", "")

                # Basic DGA detection
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
                    if self.consultant:
                        finding["mitre_context"] = self.consultant.search_mitre("DNS tunneling " + query, k=1)
                    findings.append(finding)

            # Check for NXDOMAIN
            if rcode == "NXDOMAIN":
                first_query = questions[0].get("name", "") if questions else ""
                findings.append({
                    "agent": "DNSAgent",
                    "type": "DNS_NXDOMAIN",
                    "query": first_query,
                    "confidence": 0.5,
                    "severity": "MEDIUM",
                    "description": f"Query resulted in NXDOMAIN: {first_query}",
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

        # API returns EnrichedTLSEvent: {"event": {"sni": ..., "cipher_suites": [...], ...}, ...}
        for log in tls_logs:
            event = log.get("event", {})
            sni = event.get("sni", "")
            cipher_suites = event.get("cipher_suites") or []

            for cipher in cipher_suites:
                if "RC4" in cipher:
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

            # Check IOC threat hit on SNI
            sni_threat = log.get("sni_threat") or {}
            if sni_threat.get("is_malicious"):
                findings.append({
                    "agent": "TLSAgent",
                    "type": "TLS_MALICIOUS_SNI",
                    "sni": sni,
                    "confidence": 0.95,
                    "severity": "CRITICAL",
                    "description": f"SNI matched threat intel: {sni}",
                    "details": f"Threat score: {sni_threat.get('threat_score', 0)}"
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

        # API returns EnrichedHTTPEvent: {"event": {"user_agent": ..., "host": ..., "method": ..., "url": ...}, ...}
        for log in http_logs:
            event = log.get("event", {})
            ua = event.get("user_agent", "")
            host = event.get("host", "")

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

            # Check IOC threat hit on host
            host_threat = log.get("host_threat") or {}
            if host_threat.get("is_malicious"):
                findings.append({
                    "agent": "HTTPAgent",
                    "type": "HTTP_MALICIOUS_HOST",
                    "host": host,
                    "confidence": 0.95,
                    "severity": "CRITICAL",
                    "description": f"HTTP host matched threat intel: {host}",
                    "details": f"Threat score: {host_threat.get('threat_score', 0)}"
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

        # API returns EnrichedFlow: {"flow": {"src_ip": ..., "dst_ip": ..., "dst_port": ..., ...}, ...}
        for enriched in flows:
            flow = enriched.get("flow", {})
            src_ip = flow.get("src_ip", "")
            dst_ip = flow.get("dst_ip", "")
            dst_port = flow.get("dst_port")

            # Check for internal-to-internal flows (RFC1918)
            if src_ip.startswith(("10.", "192.168.", "172.")):
                if dst_ip.startswith(("10.", "192.168.", "172.")):
                    if dst_port in [445, 135, 139]:  # SMB/RPC
                        findings.append({
                            "agent": "LateralMovementAgent",
                            "type": "LATERAL_MOVEMENT_SMB",
                            "src_ip": src_ip,
                            "dest_ip": dst_ip,
                            "confidence": 0.6,
                            "severity": "MEDIUM",
                            "description": f"Internal SMB flow: {src_ip} -> {dst_ip}",
                            "details": f"Internal SMB flow: {src_ip} -> {dst_ip}"
                        })

            # Check IOC threat hit on dst
            dst_threat = enriched.get("dst_threat") or {}
            if dst_threat.get("is_malicious"):
                findings.append({
                    "agent": "LateralMovementAgent",
                    "type": "FLOW_MALICIOUS_DESTINATION",
                    "src_ip": src_ip,
                    "dest_ip": dst_ip,
                    "confidence": 0.9,
                    "severity": "HIGH",
                    "description": f"Flow to malicious IP: {src_ip} -> {dst_ip}",
                    "details": f"Threat score: {dst_threat.get('threat_score', 0)}"
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

        # API returns EnrichedFlow: top-level "is_beacon", "beacon_interval_s", "beacon_jitter"
        # nested flow data under "flow" key
        for enriched in flows:
            if enriched.get("is_beacon"):
                flow = enriched.get("flow", {})
                src_ip = flow.get("src_ip", "")
                dst_ip = flow.get("dst_ip", "")
                interval = enriched.get("beacon_interval_s", 0)
                jitter = enriched.get("beacon_jitter", 0)
                # Lower jitter = more regular = higher confidence
                confidence = max(0.5, 1.0 - jitter) if jitter else 0.8
                findings.append({
                    "agent": "BeaconingAgent",
                    "type": "C2_BEACONING",
                    "src_ip": src_ip,
                    "dest_ip": dst_ip,
                    "confidence": round(confidence, 2),
                    "severity": "HIGH",
                    "description": f"C2 Beaconing detected: {src_ip} -> {dst_ip} (interval={interval:.1f}s, jitter={jitter:.2f})",
                    "details": f"Mean interval: {interval:.1f}s, jitter coefficient: {jitter:.2f}"
                })

        return {"findings": findings}
