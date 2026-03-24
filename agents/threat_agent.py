"""
Agent 2: Threat Modeling Agent
Performs STRIDE threat analysis and MITRE ATT&CK technique mapping for the target organization.

Outputs:
  - STRIDE threats per asset/category
  - MITRE ATT&CK technique mappings with healthcare relevance
  - Cyber kill chain stages for ransomware attack scenario
  - Top threat actors relevant to healthcare sector
"""

import json
import logging
from langchain_core.messages import HumanMessage

from config.settings import get_llm, CHROMA_DB_PATH, MITRE_ATTACK_PATH, ORG_NAME
from agents.state import AgentState

logger = logging.getLogger(__name__)

# ── Kill Chain Definition (Pre-defined for MedBridge ransomware scenario) ─────

# Fallback data specific to MedBridge demo corpus
MEDBRIDGE_KILL_CHAIN = [
    {
        "stage": "1. Reconnaissance",
        "description": "Threat actor gathers intelligence on MedBridge's public-facing assets, employee information (LinkedIn, clinical staff directories), vendor relationships (LabConnect, RadCloud), and technology stack.",
        "mapped_techniques": ["T1591 - Gather Victim Org Information", "T1589 - Gather Victim Identity Information", "T1590 - Gather Victim Network Information"],
        "mitre_ids": ["T1591", "T1589", "T1590"],
        "medbridge_relevance": "Clinical staff directories publicly listed on MedBridge website; Epic EHR system identifiable via job postings; Azure AD tenant discoverable via OSINT"
    },
    {
        "stage": "2. Initial Access",
        "description": "Spearphishing email targeting clinical nursing staff — highest-risk group based on 34% click rate in 2023 phishing simulation and minimal security training. Email impersonates Epic Systems IT support or Microsoft, requesting credential re-verification.",
        "mapped_techniques": ["T1566.001 - Spearphishing Attachment", "T1566.002 - Spearphishing Link (AiTM)"],
        "mitre_ids": ["T1566.001", "T1566.002"],
        "medbridge_relevance": "Clinical staff have 34% phishing click rate; MFA only 12% enrolled for clinical staff; prior incident INC-2023-001 shows successful phishing via AiTM"
    },
    {
        "stage": "3. Execution",
        "description": "Malicious payload executed on compromised clinical workstation using PowerShell (not blocked; no application allowlisting). Script downloads second-stage beacon.",
        "mapped_techniques": ["T1059.001 - PowerShell", "T1059.003 - Windows Command Shell", "T1204.002 - Malicious File"],
        "mitre_ids": ["T1059.001", "T1059.003", "T1204.002"],
        "medbridge_relevance": "PowerShell not restricted on Windows 10/11 clinical workstations; no application allowlisting; Windows Defender in basic AV mode only"
    },
    {
        "stage": "4. Persistence",
        "description": "Attacker establishes persistence via registry Run key and creates a scheduled task for C2 beacon re-establishment after reboot.",
        "mapped_techniques": ["T1547.001 - Registry Run Keys / Startup Folder", "T1053.005 - Scheduled Task"],
        "mitre_ids": ["T1547.001", "T1053.005"],
        "medbridge_relevance": "No behavioral EDR to detect registry modifications; no SIEM to correlate persistence artifacts across endpoints"
    },
    {
        "stage": "5. Credential Access",
        "description": "Attacker dumps credentials from LSASS memory on compromised workstation using Mimikatz. Obtains clinical staff AD credentials. Pivots to IT workstation via phishing or password spray to obtain IT admin credentials.",
        "mapped_techniques": ["T1003.001 - LSASS Memory", "T1110.003 - Password Spraying", "T1558 - Steal or Forge Kerberos Tickets"],
        "mitre_ids": ["T1003.001", "T1110.003", "T1558"],
        "medbridge_relevance": "No Credential Guard enforced; 14 domain admin accounts without MFA; no PAM tool; password policy outdated (8-char minimum); AD tiering not implemented"
    },
    {
        "stage": "6. Lateral Movement",
        "description": "Using domain admin credentials, attacker moves from clinical workstation to Epic EHR application servers via RDP (enabled for IT admin access). Access to Epic DB server obtained. Attacker conducts internal reconnaissance for 24–72 hours.",
        "mapped_techniques": ["T1021.001 - Remote Desktop Protocol", "T1018 - Remote System Discovery", "T1049 - System Network Connections Discovery"],
        "mitre_ids": ["T1021.001", "T1018", "T1049"],
        "medbridge_relevance": "RDP enabled on all servers; VLAN ACLs not enforced (clinical VLAN 10 has direct access to server VLAN 30); no SIEM to detect lateral movement; dwell time of 72 hours in INC-2024-001"
    },
    {
        "stage": "7. Collection",
        "description": "Attacker exfiltrates patient data sample (PHI) from Epic database as proof-of-data for double-extortion ransomware demand.",
        "mapped_techniques": ["T1560 - Archive Collected Data", "T1041 - Exfiltration Over C2 Channel", "T1005 - Data from Local System"],
        "mitre_ids": ["T1560", "T1041", "T1005"],
        "medbridge_relevance": "Epic DB contains 340,000 patient records; no DLP tool; Azure Blob Storage (AZ-005) accessible; no data exfiltration monitoring"
    },
    {
        "stage": "8. Impact",
        "description": "Ransomware payload deployed across Epic application servers, file servers, and clinical workstations. Epic EHR encrypted — patient care halted at all 6 facilities. Ransom note demands $2.5M in cryptocurrency.",
        "mapped_techniques": ["T1486 - Data Encrypted for Impact", "T1490 - Inhibit System Recovery", "T1489 - Service Stop"],
        "mitre_ids": ["T1486", "T1490", "T1489"],
        "medbridge_relevance": "Epic EHR downtime at $1.2M/day; BCP/DRP untested; backup recovery for Epic not validated; estimated 3.5-day recovery time = $4.2M direct impact"
    },
]


# ── STRIDE Prompt ──────────────────────────────────────────────────────────────

STRIDE_PROMPT = """You are a senior cybersecurity architect performing a STRIDE threat model for {org_name}.

Organization context:
{org_context}

Asset context:
{asset_context}

Perform a STRIDE threat analysis. For each of the following HIGH-PRIORITY assets, generate STRIDE threats:
1. Epic EHR Application Servers (EPIC-APP-01, EPIC-APP-02)
2. Active Directory Domain Controllers (AD-DC-01, AD-DC-02)
3. LabConnect HL7 Integration (RHAPSODY-01 + VPN connection)
4. Clinical Workstations (280 Windows 10/11 endpoints)
5. Azure Active Directory / Entra ID (hybrid-joined)
6. RadCloud DICOM Router (DICOM-01)

STRIDE categories:
- Spoofing: Impersonating users, systems, or processes
- Tampering: Modifying data in transit or at rest
- Repudiation: Performing actions without accountability
- Information Disclosure: Exposing data to unauthorized parties
- Denial of Service: Making systems unavailable
- Elevation of Privilege: Gaining unauthorized access levels

For each threat, provide:
- asset: Asset name
- stride_category: STRIDE category
- threat_description: Specific threat scenario
- likelihood: 1-5 (5=almost certain)
- impact: 1-5 (5=catastrophic — patient safety/major HIPAA breach/significant revenue loss)
- mitre_technique_ids: List of relevant MITRE ATT&CK technique IDs (e.g., ["T1566.001", "T1003"])
- control_gaps: What missing controls enable this threat

Generate at least 20 diverse STRIDE threats covering multiple assets and categories.

Return a JSON array:"""


MITRE_MAPPING_PROMPT = """You are a threat intelligence analyst specializing in healthcare cybersecurity.

Based on {org_name}'s environment and known healthcare threat actors (FIN12, Conti affiliates, healthcare-targeted ransomware groups), identify the most relevant MITRE ATT&CK techniques.

{org_name} environment summary:
{context}

Known healthcare threat context:
- Healthcare is the #1 ransomware target sector (HC3 2024 report)
- FIN12 specifically targets healthcare with Ryuk/PYSA/BlackCat ransomware
- Common TTPs: spearphishing → Mimikatz → lateral movement → ransomware
- Epic EHR is a high-value target (contains 340K patient records)
- Legacy systems (Windows 10, EOL firewalls) increase attack surface

For each technique, provide:
- technique_id: MITRE ATT&CK ID (e.g., "T1566.001")
- technique_name: Technique name
- tactic: MITRE tactic (e.g., "Initial Access", "Credential Access")
- healthcare_relevance: Why this technique is particularly relevant to {org_name}/healthcare
- org_specific_risk: Specific vulnerability or condition at {org_name} that enables this technique
- priority: "Critical" | "High" | "Medium"

Identify 15–20 techniques most relevant to healthcare ransomware scenarios.

Return a JSON array:"""


def run_threat_node(state: AgentState) -> AgentState:
    """LangGraph node for Threat Modeling Agent."""
    logger.info("Threat Modeling Agent: Starting threat analysis")
    state["current_step"] = "threat_modeling"
    state["progress_messages"] = state.get("progress_messages", [])
    state["progress_messages"].append("Threat Modeling Agent: Running STRIDE analysis...")

    try:
        llm = get_llm()

        # Build context from ingestion output
        org_context = state.get("ingestion_summary", f"{ORG_NAME} — healthcare org, hybrid Azure + on-prem, Epic EHR")
        asset_list = state.get("asset_inventory", [])
        asset_context = json.dumps(asset_list[:20], indent=2) if asset_list else "See asset inventory"

        # Run STRIDE analysis
        logger.info("Running STRIDE threat analysis...")
        stride_response = llm.invoke([HumanMessage(content=STRIDE_PROMPT.format(
            org_name=ORG_NAME,
            org_context=org_context,
            asset_context=asset_context
        ))])
        state["stride_threats"] = _parse_json(stride_response.content, "STRIDE threats")

        state["progress_messages"].append("Threat Modeling Agent: Mapping MITRE ATT&CK techniques...")

        # Run MITRE ATT&CK mapping (augmented with vector search if index available)
        mitre_context = _get_mitre_context(state)
        logger.info("Mapping MITRE ATT&CK techniques...")
        mitre_response = llm.invoke([HumanMessage(content=MITRE_MAPPING_PROMPT.format(
            org_name=ORG_NAME,
            context=org_context + "\n\n" + mitre_context
        ))])
        state["mitre_techniques"] = _parse_json(mitre_response.content, "MITRE techniques")

        # Set pre-defined kill chain
        state["kill_chain"] = MEDBRIDGE_KILL_CHAIN
        state["top_threat_actors"] = [
            "FIN12 (ransomware affiliate — healthcare specialization, Ryuk/BlackCat)",
            "Conti/ALPHV affiliates (healthcare ransomware with data exfiltration)",
            "Malicious Insider (clinical or IT staff with EHR access)",
            "Nation-State Actor (APT40/APT41 — healthcare intellectual property)",
            "Opportunistic Cybercriminal (unpatched vulnerability exploitation)",
        ]

        # Track data provenance
        fallback_flags = state.get("fallback_flags") or {}
        fallback_flags["threat_modeling"] = "llm_generated"
        state["fallback_flags"] = fallback_flags

        state["progress_messages"].append("Threat Modeling Agent: Complete ✓")
        logger.info(f"Threat modeling complete: {len(state.get('stride_threats', []))} STRIDE threats, "
                    f"{len(state.get('mitre_techniques', []))} MITRE techniques, "
                    f"{len(state.get('kill_chain', []))} kill chain stages")

    except Exception as e:
        logger.error(f"Threat Modeling Agent error: {e}")
        state["errors"] = state.get("errors", []) + [f"Threat Agent: {str(e)}"]
        state["stride_threats"] = state.get("stride_threats") or []
        state["mitre_techniques"] = state.get("mitre_techniques") or []
        state["kill_chain"] = state.get("kill_chain") or MEDBRIDGE_KILL_CHAIN
        state["top_threat_actors"] = state.get("top_threat_actors") or ["FIN12 (ransomware)"]
        # Track fallback usage
        fallback_flags = state.get("fallback_flags") or {}
        fallback_flags["threat_modeling"] = "fallback_static"
        state["fallback_flags"] = fallback_flags

    return state


def _get_mitre_context(state: AgentState) -> str:
    """Query MITRE ATT&CK index for healthcare-relevant techniques."""
    try:
        from tools.doc_parser import build_mitre_index
        query_engine = build_mitre_index(MITRE_ATTACK_PATH, CHROMA_DB_PATH)
        if query_engine:
            result = query_engine.query(
                "Healthcare ransomware techniques: phishing, credential dumping, lateral movement, data encryption"
            )
            return str(result)
    except Exception as e:
        logger.warning(f"MITRE index query failed (framework data may not be downloaded): {e}")
    return "MITRE ATT&CK framework data not available — using LLM knowledge"


def _parse_json(content: str, label: str) -> list[dict]:
    """Parse JSON array from LLM response."""
    try:
        content = content.strip()
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()
        start = content.find("[")
        end = content.rfind("]") + 1
        if start >= 0 and end > start:
            return json.loads(content[start:end])
    except Exception as e:
        logger.warning(f"Failed to parse {label}: {e}")
    return []
