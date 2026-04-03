from typing import List, Dict, Any
from .correlation import AttackChain

class SummaryGenerator:
    """
    Generates human-readable executive summaries from forensics data and attack chains.
    """
    
    def generate_summary(self, chain: AttackChain) -> str:
        if not chain.nodes:
            return "No suspicious activity detected in the analyzed forensics data."
            
        summary = [
            "# Wiremind AI Forensics Report",
            "## Executive Summary",
            f"Analysis of network traffic identified **{len(chain.nodes)}** suspicious events correlated into an attack chain."
        ]
        
        # Max severity
        severities = [n.severity for n in chain.nodes]
        max_severity = "low"
        if "critical" in severities:
            max_severity = "CRITICAL"
        elif "high" in severities:
            max_severity = "HIGH"
        elif "medium" in severities:
            max_severity = "MEDIUM"
        
        summary.append(f"**Overall Risk Level:** {max_severity.upper()}")
        
        # MITRE Mapping
        if chain.mitre_mapping:
            summary.append(f"**MITRE ATT&CK Techniques Identified:** {', '.join(chain.mitre_mapping)}")
            
        summary.append("\n## Correlation Timeline")
        for node in chain.nodes:
            ts = node.timestamp[:19] if node.timestamp else "Unknown Time"
            summary.append(f"- **[{ts}] {node.type}**: {node.description} (Severity: {node.severity})")
            
        if chain.edges:
            summary.append("\n## Attack Path Correlation")
            summary.append(f"Detected {len(chain.edges)} logical links between observed events, indicating a potential multi-stage threat.")
            
        summary.append("\n## Recommended Actions")
        if max_severity in ["CRITICAL", "HIGH"]:
            summary.append("1. **Isolate Affected Hosts**: Review connections from involved source IPs immediately.")
            summary.append("2. **Block External C2**: Monitor and block traffic to identified malicious destination domains/IPs.")
        else:
            summary.append("1. **Continued Monitoring**: Observe involved endpoints for further anomalous activity.")
            summary.append("2. **Baseline Review**: Verify if the detected behavior matches expected operational patterns.")
            
        return "\n".join(summary)

    def generate_json_report(self, chain: AttackChain) -> Dict[str, Any]:
        return chain.model_dump()
