from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field

class AttackChainNode(BaseModel):
    id: str
    type: str  # e.g., "DNS_LOOKUP", "TLS_CONNECTION", "DATA_EXFILTRATION"
    timestamp: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    description: str
    mitre_attack_id: Optional[str] = None
    severity: str = "low"
    finding_ref: Optional[int] = None # index in findings list

class AttackChain(BaseModel):
    nodes: List[AttackChainNode] = Field(default_factory=list)
    edges: List[Dict[str, str]] = Field(default_factory=list) # List of {"from": "node_id", "to": "node_id"}
    mitre_mapping: List[str] = Field(default_factory=list)

class AttackChainConstructor:
    """
    Synthesizes multiple specialist findings into a coherent attack chain.
    """
    
    def construct(self, findings: List[Dict[str, Any]]) -> AttackChain:
        chain = AttackChain()
        
        # Sort findings by timestamp if available
        sorted_findings = sorted(
            findings, 
            key=lambda x: x.get("timestamp", "") or ""
        )
        
        # Create nodes
        for i, finding in enumerate(sorted_findings):
            node_id = f"node_{i}"
            node_type = self._map_agent_to_type(finding.get("agent", "unknown"))
            
            node = AttackChainNode(
                id=node_id,
                type=node_type,
                timestamp=finding.get("timestamp"),
                source_ip=finding.get("source_ip"),
                dest_ip=finding.get("dest_ip"),
                description=finding.get("description", ""),
                mitre_attack_id=finding.get("mitre_attack_id"),
                severity=finding.get("severity", "low"),
                finding_ref=i
            )
            chain.nodes.append(node)
            
            if node.mitre_attack_id and node.mitre_attack_id not in chain.mitre_mapping:
                chain.mitre_mapping.append(node.mitre_attack_id)
        
        # Simple temporal linkage for now
        # In a more advanced version, we'd link by IP/port/host correlations
        for i in range(len(chain.nodes) - 1):
            source_node = chain.nodes[i]
            target_node = chain.nodes[i+1]
            
            # Link if they share IPs or if they are sequential in time
            if self._should_link(source_node, target_node):
                chain.edges.append({"from": source_node.id, "to": target_node.id})
                
        return chain

    def _map_agent_to_type(self, agent: str) -> str:
        mapping = {
            "DNSAgent": "RECONNAISSANCE_DNS",
            "TLSAgent": "ENCRYPTED_CHANNEL",
            "HTTPAgent": "WEB_PROTOCOL_EXPLOIT",
            "LateralMovementAgent": "LATERAL_MOVEMENT",
            "BeaconingAgent": "COMMAND_AND_CONTROL"
        }
        return mapping.get(agent, "UNKNOWN_ACTIVITY")

    def _should_link(self, n1: AttackChainNode, n2: AttackChainNode) -> bool:
        # Link if they share an IP (source or dest)
        ips1 = {n1.source_ip, n1.dest_ip} - {None}
        ips2 = {n2.source_ip, n2.dest_ip} - {None}
        
        if ips1.intersection(ips2):
            return True
            
        # Or if they are very close in time (temporal proximity)
        # For simplicity, if they are sequential and no other strong reason, link them
        return True
