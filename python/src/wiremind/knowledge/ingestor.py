import os
import json
from typing import List, Dict, Any
from wiremind.knowledge.vectorstore import VectorStoreManager

class KnowledgeIngestor:
    """Ingests security knowledge into the Wiremind vector store."""

    def __init__(self, manager: VectorStoreManager):
        self.manager = manager
        self.mitre_collection = "mitre_attack"
        self.playbook_collection = "security_playbooks"

    def ingest_mitre_subset(self, mitre_data: List[Dict[str, str]]):
        """
        Ingests a subset of MITRE ATT&CK techniques.
        Expected format: [{"id": "T1071", "name": "Application Layer Protocol", "description": "..."}]
        """
        texts = []
        metadatas = []
        for tech in mitre_data:
            content = f"Technique: {tech['name']} ({tech['id']})\nDescription: {tech['description']}"
            texts.append(content)
            metadatas.append({"id": tech['id'], "name": tech['name'], "source": "mitre_attack"})
        
        self.manager.add_documents(self.mitre_collection, texts, metadatas)

    def ingest_playbooks(self, playbooks: List[Dict[str, str]]):
        """
        Ingests internal security playbooks.
        Expected format: [{"title": "DNS Tunneling Response", "steps": "..."}]
        """
        texts = []
        metadatas = []
        for pb in playbooks:
            content = f"Playbook: {pb['title']}\nResponse Steps: {pb['steps']}"
            texts.append(content)
            metadatas.append({"title": pb['title'], "source": "internal_playbook"})
            
        self.manager.add_documents(self.playbook_collection, texts, metadatas)

def seed_knowledge(manager: VectorStoreManager):
    """Seed the vector store with initial data for testing and initial use."""
    ingestor = KnowledgeIngestor(manager)
    
    # Sample MITRE ATT&CK Subset
    mitre_samples = [
        {
            "id": "T1071.001",
            "name": "Application Layer Protocol: Web Protocols",
            "description": "Adversaries may communicate using application layer protocols associated with web traffic (HTTP, HTTPS) to avoid detection."
        },
        {
            "id": "T1071.004",
            "name": "Application Layer Protocol: DNS",
            "description": "Adversaries may communicate using DNS to avoid detection. DNS tunneling is a common method for C2."
        },
        {
            "id": "T1571",
            "name": "Non-Standard Port",
            "description": "Adversaries may use a non-standard port to communicate across the network to bypass filtering."
        },
        {
            "id": "T1048",
            "name": "Exfiltration Over Alternative Protocol",
            "description": "Adversaries may steal data by exfiltrating it over a different protocol than the one used for C2."
        }
    ]
    
    # Sample Internal Playbooks
    playbook_samples = [
        {
            "title": "DNS Tunneling Detection & Response",
            "steps": "1. Analyze DNS traffic for high volume of subdomains. 2. Check for unusual TXT or NULL records. 3. Correlate with destination IPs for potential C2."
        },
        {
            "title": "Beaconing Analysis",
            "steps": "1. Review jitter and periodicity of connections. 2. Cross-reference destination IP with Threat Intel. 3. Monitor for outbound connections to suspicious TLDs."
        }
    ]
    
    # Reset and seed
    manager.reset_collection(ingestor.mitre_collection)
    manager.reset_collection(ingestor.playbook_collection)
    
    ingestor.ingest_mitre_subset(mitre_samples)
    ingestor.ingest_playbooks(playbook_samples)
    print(f"Knowledge seeded in {manager.persist_directory}")

if __name__ == "__main__":
    manager = VectorStoreManager()
    seed_knowledge(manager)
