import pytest
import os
import sys
from unittest.mock import MagicMock
from langchain_core.documents import Document

# Setup path
sys.path.append(os.path.join(os.getcwd(), 'python', 'src'))

from wiremind.knowledge.vectorstore import VectorStoreManager
from wiremind.knowledge.ingestor import KnowledgeIngestor
from wiremind.knowledge.consultant import SecurityConsultant

def test_vector_store_manager():
    """Test the vector store manager (mocked/simple version)."""
    manager = VectorStoreManager(persist_directory="python/data/test_chroma")
    manager.reset_collection("test_col")
    
    manager.add_documents("test_col", ["This is a test document about DNS tunneling."], [{"id": "1"}])
    
    results = manager.query("test_col", "DNS")
    assert len(results) > 0
    assert "DNS" in results[0].page_content

def test_knowledge_ingestor():
    """Test the knowledge ingestor."""
    manager = VectorStoreManager(persist_directory="python/data/test_chroma")
    ingestor = KnowledgeIngestor(manager)
    
    mitre_data = [{"id": "T1071.004", "name": "DNS", "description": "DNS tunneling description"}]
    ingestor.ingest_mitre_subset(mitre_data)
    
    results = manager.query("mitre_attack", "DNS")
    assert any("T1071.004" in doc.page_content for doc in results)

def test_security_consultant():
    """Test the security consultant tool."""
    manager = VectorStoreManager(persist_directory="python/data/test_chroma")
    manager.reset_collection("mitre_attack")
    manager.add_documents("mitre_attack", ["Technique: DNS Tunneling (T1071.004)"], [{"id": "T1071.004"}])
    
    consultant = SecurityConsultant(manager)
    mitre_info = consultant.search_mitre("DNS")
    assert "T1071.004" in mitre_info
    
    playbook_info = consultant.get_playbook("DNS")
    assert "No matching security playbooks found" in playbook_info # We didn't seed playbooks in this test
