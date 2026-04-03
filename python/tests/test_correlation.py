import pytest
from wiremind.agents.correlation import AttackChainConstructor

def test_attack_chain_construction():
    findings = [
        {
            "agent": "DNSAgent",
            "type": "DNS_ANOMALY",
            "description": "Suspicious DNS query to malwaredomain.com",
            "source_ip": "10.0.0.5",
            "dest_ip": "8.8.8.8",
            "mitre_attack_id": "T1071.004",
            "timestamp": "2026-04-03T10:00:00Z"
        },
        {
            "agent": "TLSAgent",
            "type": "TLS_ANOMALY",
            "description": "Encrypted connection to known C2 IP",
            "source_ip": "10.0.0.5",
            "dest_ip": "45.33.22.11",
            "mitre_attack_id": "T1573.001",
            "timestamp": "2026-04-03T10:05:00Z"
        }
    ]
    
    constructor = AttackChainConstructor()
    chain = constructor.construct(findings)
    
    assert len(chain.nodes) == 2
    assert len(chain.edges) == 1
    assert "T1071.004" in chain.mitre_mapping
    assert "T1573.001" in chain.mitre_mapping
    assert chain.nodes[0].type == "RECONNAISSANCE_DNS"
    assert chain.nodes[1].type == "ENCRYPTED_CHANNEL"

def test_attack_chain_no_findings():
    constructor = AttackChainConstructor()
    chain = constructor.construct([])
    assert len(chain.nodes) == 0
    assert len(chain.edges) == 0
