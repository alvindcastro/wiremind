from typing import List, Optional
from langchain_core.documents import Document
from wiremind.knowledge.vectorstore import VectorStoreManager

class SecurityConsultant:
    """A tool for agents to query security knowledge and playbooks."""

    def __init__(self, manager: VectorStoreManager):
        self.manager = manager

    def search_mitre(self, query: str, k: int = 2) -> str:
        """Search for MITRE ATT&CK techniques relevant to a query."""
        docs = self.manager.query("mitre_attack", query, k=k)
        if not docs:
            return "No relevant MITRE ATT&CK techniques found."
        
        results = []
        for doc in docs:
            results.append(doc.page_content)
        return "\n---\n".join(results)

    def get_playbook(self, query: str) -> str:
        """Retrieve relevant security playbooks for a threat."""
        docs = self.manager.query("security_playbooks", query, k=1)
        if not docs:
            return "No matching security playbooks found for this threat."
        
        return docs[0].page_content

    def analyze_findings(self, findings: str) -> str:
        """Correlate findings with knowledge base to provide context and recommendations."""
        mitre_context = self.search_mitre(findings)
        playbook_context = self.get_playbook(findings)
        
        analysis = "### Security Consultant Analysis\n\n"
        analysis += "#### Relevant MITRE ATT&CK Techniques:\n"
        analysis += mitre_context + "\n\n"
        analysis += "#### Recommended Response Playbook:\n"
        analysis += playbook_context
        
        return analysis
