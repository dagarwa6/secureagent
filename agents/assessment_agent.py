"""
Agent 3: Assessment Agent
Evaluates MedBridge's current security posture against NIST CSF 2.0 across all 6 functions.
Produces maturity scores (1–5), justifications, and industry benchmark comparison.

NIST CSF 2.0 Functions:
  GV - Govern
  ID - Identify
  PR - Protect
  DE - Detect
  RS - Respond
  RC - Recover
"""

import json
import logging
from langchain_core.messages import HumanMessage

from config.settings import get_llm, CHROMA_DB_PATH, NIST_CSF_PATH
from agents.state import AgentState

logger = logging.getLogger(__name__)

# ── NIST CSF 2.0 Maturity Level Definitions ───────────────────────────────────

MATURITY_LEVELS = {
    1: "Initial — Security is reactive, ad-hoc; no formal processes; significant gaps",
    2: "Developing — Some processes exist but inconsistently applied; limited documentation",
    3: "Defined — Documented processes in place; consistently applied across most areas",
    4: "Managed — Processes measured and controlled; metrics tracked; regular review",
    5: "Optimizing — Continuous improvement; proactive risk management; industry-leading practices",
}

# Healthcare sector benchmark (CISA 2024 Healthcare Cybersecurity Performance Goals)
HEALTHCARE_BENCHMARK = 2.1

# ── Per-Function Assessment Prompts ───────────────────────────────────────────

FUNCTION_ASSESSMENT_PROMPT = """You are a senior cybersecurity consultant performing a NIST CSF 2.0 maturity assessment for MedBridge Health Systems.

Function being assessed: {function_name} ({function_id})
Function description: {function_desc}

Organization context:
{org_context}

Relevant evidence from MedBridge documents:
{evidence_context}

NIST CSF 2.0 Maturity Scale:
1.0 = Initial: Ad-hoc, reactive, no formal processes
2.0 = Developing: Some processes, inconsistently applied
3.0 = Defined: Documented processes, consistently applied
4.0 = Managed: Measured, controlled, metrics-driven
5.0 = Optimizing: Continuous improvement, proactive

Healthcare industry benchmark: 2.1/5.0 (CISA 2024)

IMPORTANT SCORING GUIDANCE:
- Be CONSERVATIVE. Score based strictly on documented evidence, not assumptions.
- If a capability is ABSENT (no SIEM, no EDR, no CISO), the score for that function should be 1.0-1.5.
- A score of 2.0+ requires evidence of at least partially implemented, documented processes.
- Do NOT inflate scores. A healthcare org with no detection capability (no SIEM, no EDR) should score Detect at 1.0, not 1.8.
- Reference specific corpus evidence for every score.

Based on the evidence, assign a maturity score and provide:
- score: Float between 1.0 and 5.0 (can be decimal like 1.5, 2.3)
- maturity_level: One of "Initial" | "Developing" | "Defined" | "Managed" | "Optimizing"
- score_justification: 2-3 sentences citing specific evidence from MedBridge documents
- key_strengths: List of 1-3 specific strengths observed
- key_gaps: List of 3-5 specific control gaps that drive the score down
- critical_finding: The single most important finding for this function (1 sentence)
- nist_subcategories_assessed: List of 3-5 NIST CSF 2.0 subcategory IDs most relevant

Return a JSON object (not an array):"""

# Function definitions for prompting
NIST_FUNCTIONS = [
    {
        "id": "GV",
        "name": "Govern",
        "desc": "Establishes cybersecurity strategy, policies, roles, responsibilities, and accountability. Includes organizational context, risk management strategy, and supply chain risk management."
    },
    {
        "id": "ID",
        "name": "Identify",
        "desc": "Develops understanding of cybersecurity risk to systems, people, assets, data, and capabilities. Includes asset management, risk assessment, and improvement activities."
    },
    {
        "id": "PR",
        "name": "Protect",
        "desc": "Implements safeguards to ensure delivery of services. Covers identity management, awareness training, data security, platform security, and technology infrastructure resilience."
    },
    {
        "id": "DE",
        "name": "Detect",
        "desc": "Enables timely discovery of cybersecurity incidents. Includes continuous monitoring and adverse event analysis."
    },
    {
        "id": "RS",
        "name": "Respond",
        "desc": "Takes action regarding detected incidents. Covers incident management, incident analysis, incident response reporting, mitigation, and improvements."
    },
    {
        "id": "RC",
        "name": "Recover",
        "desc": "Maintains resilience and restores capabilities after incidents. Includes recovery plan execution and communication during recovery."
    },
]


def run_assessment_node(state: AgentState) -> AgentState:
    """LangGraph node for Assessment Agent."""
    logger.info("Assessment Agent: Starting NIST CSF 2.0 maturity scoring")
    state["current_step"] = "assessment"
    state["progress_messages"] = state.get("progress_messages", [])
    state["progress_messages"].append("Assessment Agent: Scoring NIST CSF 2.0 maturity...")

    try:
        llm = get_llm()
        nist_query_engine = _get_nist_query_engine()
        org_context = _build_org_context(state)

        function_scores = []

        for func in NIST_FUNCTIONS:
            logger.info(f"Assessing {func['name']} ({func['id']})...")
            state["progress_messages"].append(f"Assessment Agent: Scoring {func['name']} function...")

            # Get relevant evidence from corpus
            evidence_context = _get_evidence(state, func["name"], nist_query_engine)

            # Score the function
            prompt = FUNCTION_ASSESSMENT_PROMPT.format(
                function_name=func["name"],
                function_id=func["id"],
                function_desc=func["desc"],
                org_context=org_context,
                evidence_context=evidence_context,
            )
            response = llm.invoke([HumanMessage(content=prompt)])
            score_data = _parse_score(response.content, func["id"])
            score_data["function"] = func["name"]
            score_data["function_id"] = func["id"]
            function_scores.append(score_data)

        state["nist_scores"] = function_scores

        # Calculate overall score (weighted average)
        scores = [s.get("score", 2.0) for s in function_scores]
        state["overall_maturity_score"] = round(sum(scores) / len(scores), 2)
        state["industry_benchmark"] = HEALTHCARE_BENCHMARK

        # Generate CIS Controls mapping
        state["cis_controls_mapped"] = _generate_cis_mapping(state)

        # Track data provenance
        fallback_flags = state.get("fallback_flags") or {}
        fallback_flags["assessment"] = "llm_generated"
        state["fallback_flags"] = fallback_flags

        state["progress_messages"].append("Assessment Agent: Complete ✓")
        logger.info(f"Assessment complete: overall score {state['overall_maturity_score']:.1f}/5.0 "
                    f"(healthcare benchmark: {HEALTHCARE_BENCHMARK})")

    except Exception as e:
        logger.error(f"Assessment Agent error: {e}")
        state["errors"] = state.get("errors", []) + [f"Assessment Agent: {str(e)}"]
        # Fallback scores based on known MedBridge issues
        state["nist_scores"] = state.get("nist_scores") or _get_fallback_scores()
        state["overall_maturity_score"] = state.get("overall_maturity_score") or 1.33
        state["industry_benchmark"] = HEALTHCARE_BENCHMARK
        # Track fallback usage
        fallback_flags = state.get("fallback_flags") or {}
        fallback_flags["assessment"] = "fallback_static"
        state["fallback_flags"] = fallback_flags

    return state


def _get_nist_query_engine():
    """Try to get NIST CSF vector index; return None if not available."""
    try:
        from tools.doc_parser import build_nist_index
        return build_nist_index(NIST_CSF_PATH, CHROMA_DB_PATH)
    except Exception as e:
        logger.warning(f"NIST index not available: {e}")
        return None


def _build_org_context(state: AgentState) -> str:
    """Build concise org context string from ingestion outputs."""
    summary = state.get("ingestion_summary", "")
    policy_count = len(state.get("policy_refs", []))
    asset_count = len(state.get("asset_inventory", []))
    vendor_count = len(state.get("vendor_risks", []))
    return (
        f"{summary}\n\n"
        f"Assets inventoried: {asset_count} | Policies: {policy_count} ({policy_count} total, "
        f"only 3 active per inventory) | Vendors: {vendor_count}\n"
        "Known issues: No CISO, no SIEM, no EDR, no PAM, MFA only 35%, EOL firewall, "
        "no vulnerability management program, deferred patching, outdated IRP/BCP, "
        "shared accounts, no formal risk assessment since 2022"
    )


def _get_evidence(state: AgentState, function_name: str, nist_query_engine) -> str:
    """Get relevant evidence from corpus for the given function."""
    # Evidence map: function → relevant search terms for corpus
    evidence_queries = {
        "Govern": "security governance CISO security policy organizational structure security strategy budget",
        "Identify": "asset inventory risk assessment vulnerability management third-party vendor risk",
        "Protect": "access control MFA authentication patch management endpoint protection encryption training",
        "Detect": "SIEM monitoring logging incident detection security events alerts",
        "Respond": "incident response plan IRP incident handling breach notification playbook",
        "Recover": "business continuity plan BCP disaster recovery backup restore testing RTO RPO",
    }

    query = evidence_queries.get(function_name, function_name)

    # Use corpus ingestion data already in state as primary evidence
    relevant_evidence = []

    # Policy evidence
    for policy in (state.get("policy_refs") or []):
        pf = policy.get("nist_function", "")
        if function_name.lower() in str(pf).lower() or not pf:
            relevant_evidence.append(f"Policy: {policy.get('name', 'Unknown')} — Status: {policy.get('status', 'Unknown')}")

    # Asset evidence (for Identify function)
    if function_name == "Identify":
        for asset in (state.get("asset_inventory") or [])[:10]:
            relevant_evidence.append(f"Asset: {asset.get('name', 'Unknown')} ({asset.get('type', 'Unknown')})")

    # Vendor evidence (for Govern/Identify functions)
    if function_name in ("Govern", "Identify"):
        for vendor in (state.get("vendor_risks") or []):
            relevant_evidence.append(f"Vendor: {vendor.get('vendor_name', 'Unknown')} — Risk: {vendor.get('risk_rating', 'Unknown')}")

    evidence_str = "\n".join(relevant_evidence) if relevant_evidence else "Evidence extracted from corpus documents"

    # Augment with known MedBridge specific findings per function
    specific_findings = {
        "Govern": "No CISO or dedicated security leadership role. Security budget not separately tracked. No security steering committee. No documented security strategy. HIPAA Security Officer role held by CCO (dual role). No board-level security reporting.",
        "Identify": "No formal asset management tool. Tech stack inventory maintained as spreadsheet (informal). No vulnerability scanner until 2024. Third-party risk assessment not conducted since contract initiation. No formal risk assessment process (last HIPAA risk analysis 2022).",
        "Protect": "MFA coverage 35% overall; clinical staff only 12% enrolled. No PAM tool. 14 domain admin accounts used for daily work (no tiering). 127 unmanaged service accounts. Password policy outdated (8-char minimum). EDR not deployed (Windows Defender AV only). VLAN ACLs not enforced between clinical and server segments. 8 of 22 policies missing.",
        "Detect": "No SIEM deployed. Windows Event Logs not centrally aggregated. No UEBA. No EDR with behavioral analytics. Epic EHR access logs not monitored. DNS query logging disabled. No 24/7 SOC. Mean time to detect: 6+ hours to 11 days (prior incidents).",
        "Respond": "Incident Response Plan outdated (Dec 2021). No ransomware or insider threat playbooks. No formal Incident Response Team defined. No executive escalation path documented. Forensic capability: none. INC-2024-001 had 72-hour dwell time before detection.",
        "Recover": "BCP outdated (Jun 2020). Epic backup recovery never tested. No defined RTO/RPO. DRP does not exist as standalone document. Azure Backup vault exists but recovery untested. No DR tabletop exercises conducted.",
    }

    return evidence_str + "\n\n" + specific_findings.get(function_name, "")


def _parse_score(content: str, func_id: str) -> dict:
    """Parse JSON score object from LLM response."""
    try:
        content = content.strip()
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()
        start = content.find("{")
        end = content.rfind("}") + 1
        if start >= 0 and end > start:
            data = json.loads(content[start:end])
            # Ensure score is a valid float
            data["score"] = float(data.get("score", 2.0))
            data["score"] = max(1.0, min(5.0, data["score"]))
            return data
    except Exception as e:
        logger.warning(f"Failed to parse score for {func_id}: {e}")
    return {"score": 2.0, "maturity_level": "Developing", "score_justification": "Score estimated from known gaps", "key_gaps": [], "key_strengths": []}


def _get_fallback_scores() -> list[dict]:
    """Fallback scores based on known MedBridge issues if LLM fails.

    Recalibrated to be evidence-based and conservative:
    - No CISO, no SIEM, no EDR, 35% MFA, untested BCP = ~1.3 overall
    - Detect at 1.0: zero detection capability (no SIEM, no EDR, no NDR)
    - Scores reference specific corpus evidence for defensibility
    """
    return [
        {"function": "Govern", "function_id": "GV", "score": 1.0, "maturity_level": "Initial", "score_justification": "No CISO or dedicated security leadership exists. Security budget is not separately tracked. No security steering committee or board-level reporting. HIPAA Security Officer role is held by the CCO as a secondary duty with no security expertise. This represents essentially non-existent cybersecurity governance.", "key_gaps": ["No CISO role — security decisions are ad-hoc", "No security strategy or multi-year roadmap", "No security steering committee", "No dedicated security budget line item", "No board-level security reporting"], "key_strengths": ["HIPAA compliance team exists (CCO-led)", "Some governance awareness at COO level"]},
        {"function": "Identify", "function_id": "ID", "score": 1.5, "maturity_level": "Initial", "score_justification": "Asset inventory maintained informally via spreadsheet with no automated discovery. HIPAA risk analysis overdue since 2022. No formal vulnerability management program until Tenable acquired in 2024 (coverage still incomplete). No third-party risk assessment process.", "key_gaps": ["No formal asset management tool — spreadsheet-only", "HIPAA risk analysis overdue (last: 2022)", "No vendor/third-party risk program", "Tenable scanner acquired 2024 but coverage incomplete", "No formal risk assessment process"], "key_strengths": ["Technology inventory partially documented", "Tenable scanner recently acquired"]},
        {"function": "Protect", "function_id": "PR", "score": 2.0, "maturity_level": "Developing", "score_justification": "Basic protective controls exist (SCCM, Windows Defender AV, Azure AD) but with critical gaps: MFA at only 35% (clinical staff 12%), no EDR, no PAM tool, 14 domain admins use DA accounts for daily work, 127 unmanaged service accounts, VLAN ACLs unenforced between clinical and server segments, and 8 of 22 policies missing.", "key_gaps": ["MFA at 35% coverage (clinical staff only 12%)", "No EDR — Windows Defender AV only", "No PAM tool; 14 DA accounts used daily", "127 unmanaged service accounts", "VLAN ACLs unenforced; flat network access"], "key_strengths": ["SCCM endpoint management deployed", "Windows Defender AV on endpoints", "Azure AD / Entra ID exists"]},
        {"function": "Detect", "function_id": "DE", "score": 1.0, "maturity_level": "Initial", "score_justification": "MedBridge has effectively zero detection capability. No SIEM is deployed. No behavioral EDR or NDR exists. Windows Event Logs are not centrally aggregated. Epic EHR access logs are not monitored. DNS query logging is disabled. No 24/7 SOC or monitoring exists. Mean time to detect in prior incidents ranged from 6+ hours (INC-2023-001) to 11 days (INC-2024-001).", "key_gaps": ["No SIEM deployed", "No behavioral EDR or NDR", "No centralized log aggregation", "No UEBA for insider threat detection", "No 24/7 security monitoring; MTTD: 6hrs–11 days"], "key_strengths": ["Firewall logs collected (30-day retention only)", "Azure Monitor exists but unused for security"]},
        {"function": "Respond", "function_id": "RS", "score": 1.5, "maturity_level": "Initial", "score_justification": "An Incident Response Plan exists but was last updated in December 2021. No ransomware, insider threat, or cloud security playbooks exist. No formal Incident Response Team is defined. No forensic capability exists in-house. INC-2024-001 had a 72-hour attacker dwell time before detection. No executive escalation path is documented.", "key_gaps": ["IRP outdated (December 2021)", "No ransomware or insider threat playbooks", "No formal IRT defined", "No forensic investigation capability", "No executive escalation path documented"], "key_strengths": ["IRP exists as a foundational document", "IT Director provides ad-hoc incident response"]},
        {"function": "Recover", "function_id": "RC", "score": 1.0, "maturity_level": "Initial", "score_justification": "BCP was last updated in June 2020 and has never been tested. Epic EHR backup recovery has never been validated. No RTO or RPO targets are defined. No standalone Disaster Recovery Plan exists. No DR tabletop exercises have been conducted. Azure Backup vault is configured but recovery procedures are untested.", "key_gaps": ["BCP untested since June 2020", "Epic backup recovery never validated", "No defined RTO/RPO targets", "No standalone DRP document", "No DR tabletop exercises conducted"], "key_strengths": ["Veeam backup tool deployed for on-premises", "Azure Backup vault configured for cloud"]},
    ]


def _generate_cis_mapping(state: AgentState) -> list[dict]:
    """Generate CIS Controls v8 cross-reference from NIST assessment data."""
    # Key CIS Controls v8 mapped to MedBridge findings
    return [
        {"control_id": "CIS-1", "title": "Inventory and Control of Enterprise Assets", "status": "Partial", "nist_function": "ID", "notes": "Spreadsheet-based; no automated discovery tool"},
        {"control_id": "CIS-2", "title": "Inventory and Control of Software Assets", "status": "Partial", "nist_function": "ID", "notes": "SCCM covers Windows; Linux unmanaged"},
        {"control_id": "CIS-3", "title": "Data Protection", "status": "Weak", "nist_function": "PR", "notes": "No data classification; no DLP; encryption policy missing"},
        {"control_id": "CIS-4", "title": "Secure Configuration of Enterprise Assets and Software", "status": "Weak", "nist_function": "PR", "notes": "No hardening baseline; default credentials on IoT devices"},
        {"control_id": "CIS-5", "title": "Account Management", "status": "Weak", "nist_function": "PR", "notes": "127 unmanaged service accounts; shared accounts at 2 facilities"},
        {"control_id": "CIS-6", "title": "Access Control Management", "status": "Weak", "nist_function": "PR", "notes": "No PAM; domain admins use DA accounts daily; no quarterly review"},
        {"control_id": "CIS-7", "title": "Continuous Vulnerability Management", "status": "Developing", "nist_function": "ID", "notes": "Tenable acquired 2024; coverage incomplete; 90-day patch cycle"},
        {"control_id": "CIS-8", "title": "Audit Log Management", "status": "Weak", "nist_function": "DE", "notes": "No centralized SIEM; 30-day firewall log retention only"},
        {"control_id": "CIS-9", "title": "Email and Web Browser Protections", "status": "Developing", "nist_function": "PR", "notes": "Defender for O365 Plan 1 added post-INC-2023-001"},
        {"control_id": "CIS-10", "title": "Malware Defenses", "status": "Partial", "nist_function": "PR", "notes": "Windows Defender AV only; no behavioral EDR"},
        {"control_id": "CIS-11", "title": "Data Recovery", "status": "Weak", "nist_function": "RC", "notes": "Backups not tested; no defined RTO/RPO"},
        {"control_id": "CIS-12", "title": "Network Infrastructure Management", "status": "Weak", "nist_function": "PR", "notes": "EOL firewalls; VLAN ACLs unenforced; no network segmentation enforcement"},
        {"control_id": "CIS-13", "title": "Network Monitoring and Defense", "status": "Weak", "nist_function": "DE", "notes": "No IDS/IPS; no NDR; minimal firewall alerting"},
        {"control_id": "CIS-14", "title": "Security Awareness and Skills Training", "status": "Weak", "nist_function": "PR", "notes": "61% completion rate; no phishing simulation since 2023; no role-based training"},
        {"control_id": "CIS-15", "title": "Service Provider Management", "status": "Weak", "nist_function": "GV", "notes": "No formal TPRM program; vendor assessments ad-hoc or non-existent"},
        {"control_id": "CIS-16", "title": "Application Software Security", "status": "Partial", "nist_function": "PR", "notes": "Epic patching deferred; no SAST/DAST; no application allowlisting"},
        {"control_id": "CIS-17", "title": "Incident Response Management", "status": "Weak", "nist_function": "RS", "notes": "IRP outdated 2021; no playbooks; no formal IRT defined"},
        {"control_id": "CIS-18", "title": "Penetration Testing", "status": "Missing", "nist_function": "ID", "notes": "No penetration testing program; last test: never conducted"},
    ]
