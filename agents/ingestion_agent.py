"""
Agent 1: Ingestion Agent
Parses MedBridge corpus documents and extracts structured security-relevant information:
  - Asset inventory
  - Policy references and status
  - Technology stack references
  - Vendor risk notes
  - Executive summary of organizational context
"""

import json
import logging
from typing import Optional

from langchain_core.messages import HumanMessage

from config.settings import get_llm, get_embed_model, CORPUS_PATH, CHROMA_DB_PATH
from agents.state import AgentState

logger = logging.getLogger(__name__)

# ── Extraction Prompts ────────────────────────────────────────────────────────

ASSET_EXTRACTION_PROMPT = """You are a cybersecurity analyst reviewing organizational documents for MedBridge Health Systems.

Based on the following document excerpts, extract a comprehensive asset inventory.

For each asset, provide:
- name: Asset name or hostname
- type: "Server" | "Workstation" | "Network Device" | "Application" | "Cloud Resource" | "Medical Device" | "Integration"
- environment: "On-Premises" | "Cloud (Azure)" | "Hybrid" | "SaaS"
- criticality: "Critical" | "High" | "Medium" | "Low"
- os_or_platform: Operating system or platform (if mentioned)
- phi_data: true/false — whether this asset handles Protected Health Information
- notes: Any security-relevant notes (patch status, EOL, vulnerabilities, etc.)

Document excerpts:
{context}

Return a JSON array of assets. Be thorough — include servers, endpoints, applications, network devices, medical devices, and cloud resources.

JSON array:"""

POLICY_EXTRACTION_PROMPT = """You are a cybersecurity compliance analyst.

Based on the following document excerpts about MedBridge Health Systems, extract all security policy information.

For each policy, provide:
- name: Policy name
- status: "Active" | "Outdated" | "Draft" | "Missing"
- last_review: Last review date or "Unknown"
- owner: Policy owner
- nist_function: Related NIST CSF 2.0 function ("Govern" | "Identify" | "Protect" | "Detect" | "Respond" | "Recover")
- gap_notes: Key gaps or compliance issues identified

Document excerpts:
{context}

Return a JSON array of policies. Include ALL policies mentioned, including missing ones.

JSON array:"""

VENDOR_EXTRACTION_PROMPT = """You are a third-party risk analyst.

Based on the following document excerpts about MedBridge Health Systems, extract all vendor/third-party relationship information.

For each vendor, provide:
- vendor_name: Name of the vendor
- service: What service they provide
- connection_type: How they connect to MedBridge systems
- data_access: What data they can access (include if PHI)
- phi_access: true/false
- mfa_required: true/false
- last_assessment: Date of last security assessment or "None"
- risk_rating: "High" | "Medium" | "Low"
- key_risks: List of key risk findings

Document excerpts:
{context}

Return a JSON array of vendor risk entries.

JSON array:"""

SUMMARY_PROMPT = """You are a senior cybersecurity consultant preparing an executive brief.

Based on the following documents about MedBridge Health Systems, write a concise organizational security context summary (2-3 paragraphs) covering:
1. Organization type, size, and regulatory environment
2. Current IT/security posture (high-level strengths and critical weaknesses)
3. Primary business objectives at risk from a cybersecurity perspective

Documents:
{context}

Write the summary in professional consulting language suitable for a board-level executive audience:"""


def run_ingestion_node(state: AgentState) -> AgentState:
    """
    LangGraph node function for the Ingestion Agent.
    Reads corpus documents, extracts structured data, returns updated state.
    """
    logger.info("Ingestion Agent: Starting document analysis")
    state["current_step"] = "ingestion"
    state["progress_messages"] = state.get("progress_messages", [])
    state["progress_messages"].append("Ingestion Agent: Loading and indexing documents...")

    try:
        llm = get_llm()
        query_engine = _build_query_engine(state["docs_path"])

        # Extract assets
        logger.info("Extracting asset inventory...")
        state["progress_messages"].append("Ingestion Agent: Extracting asset inventory...")
        asset_context = str(query_engine.query(
            "List all servers, workstations, network devices, applications, medical devices, and cloud resources"
        ))
        state["asset_inventory"] = _extract_json(llm, ASSET_EXTRACTION_PROMPT.format(context=asset_context))

        # Extract policies
        logger.info("Extracting policy inventory...")
        state["progress_messages"].append("Ingestion Agent: Extracting policy inventory...")
        policy_context = str(query_engine.query(
            "List all security policies, their status, last review dates, and any compliance gaps"
        ))
        state["policy_refs"] = _extract_json(llm, POLICY_EXTRACTION_PROMPT.format(context=policy_context))

        # Extract tech refs
        logger.info("Extracting technology references...")
        tech_context = str(query_engine.query(
            "What technologies, software, and security tools does MedBridge use?"
        ))
        state["tech_refs"] = _extract_tech_list(llm, tech_context)

        # Extract vendor risks
        logger.info("Extracting vendor risk information...")
        state["progress_messages"].append("Ingestion Agent: Extracting vendor relationships...")
        vendor_context = str(query_engine.query(
            "Describe all third-party vendor connections, their data access, security assessments, and risks"
        ))
        state["vendor_risks"] = _extract_json(llm, VENDOR_EXTRACTION_PROMPT.format(context=vendor_context))

        # Generate executive summary
        logger.info("Generating organizational summary...")
        state["progress_messages"].append("Ingestion Agent: Generating organizational summary...")
        all_context = str(query_engine.query(
            "Provide a comprehensive overview of MedBridge Health Systems' organization, IT environment, and security posture"
        ))
        summary_response = llm.invoke([HumanMessage(content=SUMMARY_PROMPT.format(context=all_context))])
        state["ingestion_summary"] = summary_response.content

        # Track data provenance
        fallback_flags = state.get("fallback_flags") or {}
        fallback_flags["ingestion"] = "llm_generated"
        state["fallback_flags"] = fallback_flags

        state["progress_messages"].append("Ingestion Agent: Complete ✓")
        logger.info(f"Ingestion complete: {len(state.get('asset_inventory', []))} assets, "
                    f"{len(state.get('policy_refs', []))} policies, "
                    f"{len(state.get('vendor_risks', []))} vendors")

    except Exception as e:
        logger.error(f"Ingestion Agent error: {e}")
        state["errors"] = state.get("errors", []) + [f"Ingestion Agent: {str(e)}"]
        # Provide fallback minimal data so pipeline can continue
        state["asset_inventory"] = state.get("asset_inventory") or []
        state["policy_refs"] = state.get("policy_refs") or []
        state["tech_refs"] = state.get("tech_refs") or []
        state["vendor_risks"] = state.get("vendor_risks") or []
        state["ingestion_summary"] = state.get("ingestion_summary") or "Summary unavailable due to error."
        # Track fallback usage
        fallback_flags = state.get("fallback_flags") or {}
        fallback_flags["ingestion"] = "fallback_static"
        state["fallback_flags"] = fallback_flags

    return state


def _build_query_engine(docs_path: str):
    """Builds or loads the corpus vector index."""
    from tools.doc_parser import build_corpus_index
    return build_corpus_index(
        corpus_path=docs_path,
        chroma_db_path=CHROMA_DB_PATH,
        collection_name="corpus",
    )


def _extract_json(llm, prompt: str) -> list[dict]:
    """Invoke LLM with a prompt and parse JSON array from response."""
    try:
        response = llm.invoke([HumanMessage(content=prompt)])
        content = response.content.strip()

        # Extract JSON array from response (handle markdown code blocks)
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()

        # Find JSON array
        start = content.find("[")
        end = content.rfind("]") + 1
        if start >= 0 and end > start:
            return json.loads(content[start:end])
    except Exception as e:
        logger.warning(f"JSON extraction failed: {e}")
    return []


def _extract_tech_list(llm, context: str) -> list[str]:
    """Extract a flat list of technology names from the context."""
    prompt = f"""From this text about MedBridge Health Systems, extract a list of all technology product names, software, and tools mentioned.

Text:
{context}

Return a JSON array of strings (technology names only, no descriptions):
["Azure Active Directory", "Epic EHR", ...]"""

    try:
        response = llm.invoke([HumanMessage(content=prompt)])
        content = response.content.strip()
        if "```" in content:
            content = content.split("```")[1].split("```")[0].strip()
        start = content.find("[")
        end = content.rfind("]") + 1
        if start >= 0 and end > start:
            return json.loads(content[start:end])
    except Exception as e:
        logger.warning(f"Tech list extraction failed: {e}")
    return []
