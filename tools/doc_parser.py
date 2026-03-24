"""
Document Parser — LlamaIndex + ChromaDB + HuggingFace Embeddings (all free)

Builds and loads vector indices for:
  1. MedBridge corpus documents (for ingestion agent)
  2. NIST CSF 2.0 framework data (for assessment agent)
  3. MITRE ATT&CK framework data (for threat modeling agent)

Free stack:
  - Embeddings: sentence-transformers/all-MiniLM-L6-v2 (local, no API)
  - Vector store: ChromaDB (local, persisted to disk)
  - NO paid LLM needed for indexing/retrieval — agents use their own Groq/Gemini LLMs
"""

import os
import json
import logging
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

# Project root for path validation
_PROJECT_ROOT = Path(__file__).parent.parent.resolve()


def validate_corpus_path(corpus_path: str) -> str:
    """
    Validate and sanitize corpus_path to prevent path traversal attacks.
    Accepts paths within the project root or system temp directories.
    Raises ValueError if the path is outside allowed directories.
    """
    resolved = Path(corpus_path).resolve()

    # Allow paths within project root
    try:
        resolved.relative_to(_PROJECT_ROOT)
        return str(resolved)
    except ValueError:
        pass

    # Allow paths within system temp directory
    try:
        resolved.relative_to(Path(tempfile.gettempdir()).resolve())
        return str(resolved)
    except ValueError:
        pass

    raise ValueError(
        f"Path traversal blocked: '{corpus_path}' resolves to '{resolved}' "
        f"which is outside the project root and temp directories."
    )


class SimpleRetrieverEngine:
    """
    Lightweight wrapper around LlamaIndex retriever that returns concatenated
    source texts without requiring an LLM for synthesis.

    The agents pass the retrieved text to their own Groq/Gemini LLMs for analysis,
    so we don't need LlamaIndex to do any LLM-based response synthesis.
    """

    def __init__(self, retriever):
        self._retriever = retriever

    def query(self, query_str: str) -> str:
        """Retrieve relevant document chunks and concatenate their text."""
        nodes = self._retriever.retrieve(query_str)
        if not nodes:
            return "No relevant information found."
        texts = []
        for node in nodes:
            text = node.get_content() if hasattr(node, 'get_content') else str(node)
            if text.strip():
                texts.append(text.strip())
        return "\n\n---\n\n".join(texts) if texts else "No relevant information found."


def get_embed_model():
    """Returns free local embedding model. No API calls, no cost."""
    from llama_index.embeddings.huggingface import HuggingFaceEmbedding
    return HuggingFaceEmbedding(model_name="sentence-transformers/all-MiniLM-L6-v2")


def build_corpus_index(corpus_path: str, chroma_db_path: str, collection_name: str = "corpus"):
    """
    Indexes MedBridge corpus documents into ChromaDB.
    Returns the query engine for semantic search.
    """
    import chromadb
    from llama_index.core import SimpleDirectoryReader, VectorStoreIndex, StorageContext
    from llama_index.vector_stores.chroma import ChromaVectorStore

    embed_model = get_embed_model()

    # Set up ChromaDB
    chroma_client = chromadb.PersistentClient(path=chroma_db_path)
    chroma_collection = chroma_client.get_or_create_collection(collection_name)
    vector_store = ChromaVectorStore(chroma_collection=chroma_collection)
    storage_context = StorageContext.from_defaults(vector_store=vector_store)

    # Validate corpus path to prevent path traversal
    corpus_path = validate_corpus_path(corpus_path)

    # Check if index already built
    if chroma_collection.count() > 0:
        logger.info(f"Loading existing {collection_name} index from ChromaDB ({chroma_collection.count()} chunks)")
        index = VectorStoreIndex.from_vector_store(
            vector_store,
            embed_model=embed_model,
        )
    else:
        logger.info(f"Building {collection_name} index from {corpus_path}")
        documents = SimpleDirectoryReader(corpus_path, recursive=True).load_data()
        logger.info(f"Loaded {len(documents)} documents")
        index = VectorStoreIndex.from_documents(
            documents,
            storage_context=storage_context,
            embed_model=embed_model,
            show_progress=True,
        )
        logger.info(f"Index built: {chroma_collection.count()} chunks stored")

    retriever = index.as_retriever(similarity_top_k=5)
    return SimpleRetrieverEngine(retriever)


def build_nist_index(nist_json_path: str, chroma_db_path: str):
    """
    Indexes NIST CSF 2.0 JSON into ChromaDB for framework-grounded querying.
    """
    import chromadb
    from llama_index.core import VectorStoreIndex, StorageContext
    from llama_index.vector_stores.chroma import ChromaVectorStore

    embed_model = get_embed_model()
    chroma_client = chromadb.PersistentClient(path=chroma_db_path)
    chroma_collection = chroma_client.get_or_create_collection("nist_csf")
    vector_store = ChromaVectorStore(chroma_collection=chroma_collection)
    storage_context = StorageContext.from_defaults(vector_store=vector_store)

    if chroma_collection.count() > 0:
        logger.info(f"Loading existing NIST CSF index ({chroma_collection.count()} chunks)")
        index = VectorStoreIndex.from_vector_store(vector_store, embed_model=embed_model)
        retriever = index.as_retriever(similarity_top_k=8)
        return SimpleRetrieverEngine(retriever)

    logger.info(f"Building NIST CSF index from {nist_json_path}")
    if not os.path.exists(nist_json_path):
        logger.warning(f"NIST CSF JSON not found at {nist_json_path}. Run scripts/download_frameworks.py first.")
        return None

    with open(nist_json_path, "r") as f:
        nist_data = json.load(f)

    # Convert NIST CSF structure to LlamaIndex documents
    documents = _nist_to_documents(nist_data)
    logger.info(f"Created {len(documents)} NIST CSF document chunks")

    index = VectorStoreIndex.from_documents(
        documents,
        storage_context=storage_context,
        embed_model=embed_model,
        show_progress=True,
    )
    retriever = index.as_retriever(similarity_top_k=8)
    return SimpleRetrieverEngine(retriever)


def build_mitre_index(mitre_json_path: str, chroma_db_path: str):
    """
    Indexes MITRE ATT&CK STIX data into ChromaDB.
    Only indexes techniques (not all STIX objects) to keep index manageable.
    """
    import chromadb
    from llama_index.core import VectorStoreIndex, StorageContext
    from llama_index.vector_stores.chroma import ChromaVectorStore

    embed_model = get_embed_model()
    chroma_client = chromadb.PersistentClient(path=chroma_db_path)
    chroma_collection = chroma_client.get_or_create_collection("mitre_attack")
    vector_store = ChromaVectorStore(chroma_collection=chroma_collection)
    storage_context = StorageContext.from_defaults(vector_store=vector_store)

    if chroma_collection.count() > 0:
        logger.info(f"Loading existing MITRE ATT&CK index ({chroma_collection.count()} chunks)")
        index = VectorStoreIndex.from_vector_store(vector_store, embed_model=embed_model)
        retriever = index.as_retriever(similarity_top_k=10)
        return SimpleRetrieverEngine(retriever)

    logger.info(f"Building MITRE ATT&CK index from {mitre_json_path}")
    if not os.path.exists(mitre_json_path):
        logger.warning(f"MITRE ATT&CK JSON not found at {mitre_json_path}. Run scripts/download_frameworks.py first.")
        return None

    with open(mitre_json_path, "r") as f:
        stix_bundle = json.load(f)

    documents = _mitre_to_documents(stix_bundle)
    logger.info(f"Created {len(documents)} MITRE ATT&CK technique chunks")

    index = VectorStoreIndex.from_documents(
        documents,
        storage_context=storage_context,
        embed_model=embed_model,
        show_progress=True,
    )
    retriever = index.as_retriever(similarity_top_k=10)
    return SimpleRetrieverEngine(retriever)


def _nist_to_documents(nist_data: dict) -> list:
    """Convert NIST CSF 2.0 JSON structure to LlamaIndex Documents."""
    from llama_index.core import Document
    documents = []

    # Handle different NIST CSF JSON formats
    functions = nist_data.get("functions", nist_data.get("Function", []))
    for func in functions:
        func_id = func.get("id", func.get("Function.Identifier", ""))
        func_name = func.get("name", func.get("Function.Title", ""))

        for cat in func.get("categories", func.get("Category", [])):
            cat_id = cat.get("id", cat.get("Category.Identifier", ""))
            cat_name = cat.get("name", cat.get("Category.Title", ""))

            for sub in cat.get("subcategories", cat.get("Subcategory", [])):
                sub_id = sub.get("id", sub.get("Subcategory.Identifier", ""))
                sub_desc = sub.get("description", sub.get("Subcategory.Statement", ""))

                text = (
                    f"NIST CSF 2.0 | Function: {func_name} ({func_id}) | "
                    f"Category: {cat_name} ({cat_id}) | "
                    f"Subcategory {sub_id}: {sub_desc}"
                )
                documents.append(Document(
                    text=text,
                    metadata={"function": func_id, "category": cat_id, "subcategory": sub_id}
                ))

    if not documents:
        # Fallback: treat entire JSON as text
        documents.append(Document(text=json.dumps(nist_data, indent=2)))

    return documents


def _mitre_to_documents(stix_bundle: dict) -> list:
    """Extract ATT&CK techniques from STIX bundle into LlamaIndex Documents."""
    from llama_index.core import Document
    documents = []

    objects = stix_bundle.get("objects", [])
    techniques = [o for o in objects if o.get("type") == "attack-pattern"]

    for tech in techniques:
        tech_id = ""
        for ref in tech.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id", "")
                break

        name = tech.get("name", "")
        desc = tech.get("description", "")[:800]  # Cap at 800 chars
        tactics = [p.get("phase_name", "") for p in tech.get("kill_chain_phases", [])]
        platforms = tech.get("x_mitre_platforms", [])
        is_subtechnique = tech.get("x_mitre_is_subtechnique", False)

        text = (
            f"MITRE ATT&CK Technique: {tech_id} — {name}\n"
            f"Tactics: {', '.join(tactics)}\n"
            f"Platforms: {', '.join(platforms)}\n"
            f"Is Sub-technique: {is_subtechnique}\n"
            f"Description: {desc}"
        )
        documents.append(Document(
            text=text,
            metadata={
                "technique_id": tech_id,
                "name": name,
                "tactics": ",".join(tactics),
                "platforms": ",".join(platforms),
            }
        ))

    return documents
