import pytest
from wiremind.agents.correlation import AttackChainConstructor
from wiremind.agents.reporting import SummaryGenerator

def test_summary_generation():
    findings = [
        {
            "agent": "DNSAgent",
            "type": "DNS_ANOMALY",
            "description": "Suspicious DNS query",
            "mitre_attack_id": "T1071.004",
            "severity": "medium"
        },
        {
            "agent": "BeaconingAgent",
            "type": "C2_BEACONING",
            "description": "Heartbeat detected to 45.33.22.11",
            "mitre_attack_id": "T1071.001",
            "severity": "high"
        }
    ]
    
    constructor = AttackChainConstructor()
    chain = constructor.construct(findings)
    
    generator = SummaryGenerator()
    summary = generator.generate_summary(chain)
    
    assert "# Wiremind AI Forensics Report" in summary
    assert "Overall Risk Level:** HIGH" in summary
    assert "T1071.004" in summary
    assert "T1071.001" in summary
    assert "Heartbeat detected" in summary

def test_summary_no_findings():
    constructor = AttackChainConstructor()
    chain = constructor.construct([])
    generator = SummaryGenerator()
    summary = generator.generate_summary(chain)
    assert "No suspicious activity detected" in summary
