import os
from typing import List, Dict, Any, Optional
from langchain_core.documents import Document

class VectorStoreManager:
    """Manages the knowledge base for RAG capabilities in Wiremind."""

    def __init__(self, persist_directory: str = "python/data/knowledge"):
        self.persist_directory = persist_directory
        self._collections = {}
        os.makedirs(persist_directory, exist_ok=True)
        
    def add_documents(self, collection_name: str, texts: List[str], metadatas: Optional[List[Dict]] = None):
        """Adds text documents to the specified collection."""
        if collection_name not in self._collections:
            self._collections[collection_name] = []
        
        for i, text in enumerate(texts):
            metadata = metadatas[i] if metadatas and i < len(metadatas) else {}
            self._collections[collection_name].append(Document(page_content=text, metadata=metadata))

    def query(self, collection_name: str, query_text: str, k: int = 3) -> List[Document]:
        """Queries the store for the most relevant documents using simple keyword matching."""
        if collection_name not in self._collections:
            return []
        
        docs = self._collections[collection_name]
        # Simple keyword-based ranking for RAG demonstration without heavy dependencies
        query_words = set(query_text.lower().split())
        
        ranked_docs = []
        for doc in docs:
            score = sum(1 for word in query_words if word in doc.page_content.lower())
            if score > 0:
                ranked_docs.append((score, doc))
        
        ranked_docs.sort(key=lambda x: x[0], reverse=True)
        return [doc for score, doc in ranked_docs[:k]]

    def reset_collection(self, collection_name: str):
        """Resets a collection."""
        self._collections[collection_name] = []
