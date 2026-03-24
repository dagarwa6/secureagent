"""
Agent 4: Gap Analysis & Risk Agent
Identifies control gaps, produces a prioritized risk register (15+ findings),
classifies findings as systemic vs isolated, and runs FAIR-lite quantification.

Risk finding classification:
  - Systemic Structural Weakness: Cross-domain, governance-level gap affecting multiple systems
  - Isolated Control Failure: Single system or tactical gap
"""

import json
import logging
from langchain_core.messages import HumanMessage

from config.settings import get_llm, ORG_NAME
from agents.state import AgentState
from tools.fair_calculator import get_medbridge_fair_results, fair_results_to_dict

logger = logging.getLogger(__name__)

# ── Healthcare Industry Benchmark ─────────────────────────────────────────────
HEALTHCARE_BENCHMARK = 2.1  # CISA 2024 healthcare sector average

RISK_REGISTER_PROMPT = """You are a senior cybersecurity risk analyst completing a risk register for {org_name}.

Organization summary:
{org_context}

NIST CSF 2.0 assessment results:
{nist_scores}

Threat model findings:
{threats_context}

Known critical gaps:
- No CISO or dedicated security leadership
- No SIEM or centralized monitoring
- No EDR (Windows Defender AV only)
- MFA at only 35% (clinical staff 12%)
- No PAM tool; 14 domain admins use DA accounts daily
- EOL Cisco ASA firewall
- VLAN ACLs not enforced between clinical and server segments
- 8 of 22 security policies missing; 9 outdated
- LabConnect VPN: no MFA, 4-year-old PSK
- RadCloud: static API key, SOC 2 Type I only
- Medical devices (120 infusion pumps) with default credentials
- Incident Response Plan outdated since 2021
- BCP untested since 2020; Epic backup never validated

Generate a comprehensive risk register with AT LEAST 15 findings.

For each finding, provide:
- id: "RISK-001" through "RISK-NNN"
- asset: Specific asset(s) affected
- threat_scenario: Specific threat scenario (what could happen)
- likelihood: Integer 1-5 (5=almost certain)
- impact: Integer 1-5 (5=catastrophic — patient safety risk, major regulatory breach, or >$1M impact)
- risk_score: likelihood * impact (integer 1-25)
- control_gap: The specific control that is missing or inadequate
- gap_type: "Systemic Structural Weakness" (cross-domain, governance-level) OR "Isolated Control Failure" (single system, tactical)
- owner: Who should own this risk (e.g., "CISO (to be hired)", "IT Director", "COO")
- recommended_control: Specific recommended control or remediation
- nist_function: Primary NIST CSF 2.0 function ("Govern"|"Identify"|"Protect"|"Detect"|"Respond"|"Recover")
- business_objective_at_risk: Business objective threatened ("Revenue Continuity"|"HIPAA Compliance"|"Patient Safety"|"Operational Efficiency"|"Reputational Integrity")
- priority: "Critical" (score 20-25) | "High" (score 15-19) | "Medium" (score 9-14) | "Low" (score 1-8)

Ensure findings cover:
- At least 3 findings per NIST function
- Both Systemic (governance/cross-domain) and Isolated (tactical) gaps
- Findings linked to specific {org_name} assets and incidents

Return a JSON array of risk findings, sorted by risk_score descending:"""


def run_gap_node(state: AgentState) -> AgentState:
    """LangGraph node for Gap Analysis & Risk Agent."""
    logger.info("Gap Analysis Agent: Starting risk register generation")
    state["current_step"] = "gap_analysis"
    state["progress_messages"] = state.get("progress_messages", [])
    state["progress_messages"].append("Gap Analysis Agent: Building risk register...")

    try:
        llm = get_llm()

        # Build context
        org_context = state.get("ingestion_summary", f"{ORG_NAME} healthcare org")
        nist_scores = _format_nist_scores(state.get("nist_scores", []))
        threats_context = _format_threats(state)

        # Generate risk register
        logger.info("Generating risk register with LLM...")
        response = llm.invoke([HumanMessage(content=RISK_REGISTER_PROMPT.format(
            org_name=ORG_NAME,
            org_context=org_context,
            nist_scores=nist_scores,
            threats_context=threats_context,
        ))])

        findings = _parse_findings(response.content)

        # Ensure minimum 15 findings
        if len(findings) < 15:
            logger.warning(f"Only {len(findings)} findings generated; adding fallback findings")
            findings = _merge_with_fallback(findings)

        # Sort by risk score descending
        findings = sorted(findings, key=lambda x: x.get("risk_score", 0), reverse=True)

        # Re-assign IDs after sorting
        for i, finding in enumerate(findings, 1):
            finding["id"] = f"RISK-{i:03d}"

        state["risk_findings"] = findings
        state["top_10_gaps"] = findings[:10]

        # Count systemic vs isolated
        state["systemic_count"] = sum(1 for f in findings if "Systemic" in str(f.get("gap_type", "")))
        state["isolated_count"] = len(findings) - state["systemic_count"]

        state["progress_messages"].append("Gap Analysis Agent: Running FAIR-lite quantification...")

        # Run FAIR-lite
        logger.info("Running FAIR-lite analysis...")
        fair_results = get_medbridge_fair_results()
        state["fair_results"] = fair_results_to_dict(fair_results)

        # Attach ALE estimates to matching risk findings
        _attach_ale_estimates(state)

        # Track data provenance
        fallback_flags = state.get("fallback_flags") or {}
        fallback_flags["gap_analysis"] = "llm_generated"
        state["fallback_flags"] = fallback_flags

        state["progress_messages"].append("Gap Analysis Agent: Complete ✓")
        logger.info(f"Gap analysis complete: {len(findings)} findings "
                    f"({state['systemic_count']} systemic, {state['isolated_count']} isolated)")

    except Exception as e:
        logger.error(f"Gap Analysis Agent error: {e}")
        state["errors"] = state.get("errors", []) + [f"Gap Agent: {str(e)}"]
        state["risk_findings"] = state.get("risk_findings") or _get_fallback_findings()
        state["top_10_gaps"] = (state.get("risk_findings") or [])[:10]
        state["systemic_count"] = state.get("systemic_count") or 7
        state["isolated_count"] = state.get("isolated_count") or 8
        state["fair_results"] = state.get("fair_results") or fair_results_to_dict(get_medbridge_fair_results())
        # Track fallback usage
        fallback_flags = state.get("fallback_flags") or {}
        fallback_flags["gap_analysis"] = "fallback_static"
        state["fallback_flags"] = fallback_flags

    return state


def _format_nist_scores(nist_scores: list) -> str:
    if not nist_scores:
        return "NIST CSF scores unavailable"
    lines = []
    for s in nist_scores:
        lines.append(f"{s.get('function', 'Unknown')} ({s.get('function_id', '')}): "
                     f"Score {s.get('score', '?')}/5.0 | "
                     f"Key gaps: {', '.join(s.get('key_gaps', [])[:3])}")
    return "\n".join(lines)


def _format_threats(state: AgentState) -> str:
    stride = state.get("stride_threats", [])
    mitre = state.get("mitre_techniques", [])
    parts = []
    if stride:
        top_stride = sorted(stride, key=lambda x: x.get("likelihood", 0) * x.get("impact", 0), reverse=True)[:5]
        parts.append("Top STRIDE threats: " + "; ".join(
            f"{t.get('asset', 'Asset')} - {t.get('stride_category', 'STRIDE')} - {t.get('threat_description', '')[:80]}"
            for t in top_stride
        ))
    if mitre:
        critical = [m for m in mitre if m.get("priority") == "Critical"][:5]
        parts.append("Critical MITRE techniques: " + "; ".join(
            f"{m.get('technique_id', 'T?')} {m.get('technique_name', '')}"
            for m in critical
        ))
    return "\n".join(parts) if parts else "Threat data from STRIDE and MITRE ATT&CK analysis"


def _parse_findings(content: str) -> list[dict]:
    try:
        content = content.strip()
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()
        start = content.find("[")
        end = content.rfind("]") + 1
        if start >= 0 and end > start:
            data = json.loads(content[start:end])
            # Validate and fix each finding
            validated = []
            for d in data:
                d["likelihood"] = int(d.get("likelihood", 3))
                d["impact"] = int(d.get("impact", 3))
                d["risk_score"] = d["likelihood"] * d["impact"]
                validated.append(d)
            return validated
    except Exception as e:
        logger.warning(f"Failed to parse risk findings: {e}")
    return []


def _attach_ale_estimates(state: AgentState) -> None:
    """Attach ALE estimates from FAIR results to matching risk findings."""
    fair = state.get("fair_results", [])
    findings = state.get("risk_findings", [])

    # Map FAIR results to findings by keyword matching
    keyword_map = {
        "Ransomware": ("Ransomware Attack on Epic EHR", fair),
        "PHI": ("PHI Data Breach via Insider Threat", fair),
        "LabConnect": ("Third-Party Supply Chain Compromise (LabConnect)", fair),
        "Medical Device": ("Medical Device Exploit (Infusion Pump Compromise)", fair),
        "Identity": ("Identity Governance Failure (Privilege Escalation)", fair),
    }

    for finding in findings:
        threat = finding.get("threat_scenario", "") + " " + finding.get("asset", "")
        for keyword, (fair_name, _) in keyword_map.items():
            if keyword.lower() in threat.lower():
                for fair_result in fair:
                    if fair_result.get("risk_name") == fair_name:
                        finding["ale_usd"] = fair_result.get("ale_usd")
                        finding["ale_formatted"] = fair_result.get("ale_formatted")
                        break
                break


def _merge_with_fallback(existing: list) -> list:
    """Merge existing findings with fallback to reach 15+ findings."""
    fallback = _get_fallback_findings()
    existing_ids = {f.get("control_gap", "") for f in existing}
    for fb in fallback:
        if fb.get("control_gap", "") not in existing_ids and len(existing) < 15:
            existing.append(fb)
    return existing


# Fallback data specific to MedBridge demo corpus
def _get_fallback_findings() -> list[dict]:
    """Pre-defined risk findings for MedBridge based on known gaps."""
    return [
        {"id": "RISK-001", "asset": "All MedBridge Systems", "threat_scenario": "Ransomware attack encrypts Epic EHR and clinical systems via phishing → credential theft → lateral movement", "likelihood": 4, "impact": 5, "risk_score": 20, "control_gap": "No EDR, no SIEM, MFA only 35%, VLAN ACLs unenforced", "gap_type": "Systemic Structural Weakness", "owner": "CISO (to be hired)", "recommended_control": "Deploy EDR (Microsoft Defender for Endpoint), enforce MFA universally, implement SIEM (Azure Sentinel)", "nist_function": "Protect", "business_objective_at_risk": "Revenue Continuity", "priority": "Critical", "ale_usd": 1070000, "ale_formatted": "$1,070,000"},
        {"id": "RISK-002", "asset": "Active Directory + All 1,200 User Accounts", "threat_scenario": "MFA bypass via credential phishing (AiTM) targeting clinical staff with 34% phishing click rate", "likelihood": 4, "impact": 5, "risk_score": 20, "control_gap": "MFA enrollment at 12% for clinical staff; no phishing-resistant MFA (FIDO2)", "gap_type": "Systemic Structural Weakness", "owner": "IT Director", "recommended_control": "Enforce MFA for all users via Conditional Access; deploy FIDO2/hardware tokens for privileged users", "nist_function": "Protect", "business_objective_at_risk": "HIPAA Compliance", "priority": "Critical"},
        {"id": "RISK-003", "asset": "Cisco ASA 5555-X (NET-001) — Perimeter Firewall", "threat_scenario": "Exploitation of unpatched perimeter firewall (EOL 2024, no support contract) via known CVEs", "likelihood": 3, "impact": 5, "risk_score": 15, "control_gap": "EOL firewall with no replacement planned; no active support contract", "gap_type": "Isolated Control Failure", "owner": "IT Director", "recommended_control": "Replace EOL Cisco ASA with supported next-gen firewall (Palo Alto, Fortinet, or Meraki MX)", "nist_function": "Protect", "business_objective_at_risk": "Revenue Continuity", "priority": "High"},
        {"id": "RISK-004", "asset": "Epic EHR (340,000 patient records)", "threat_scenario": "PHI data breach via malicious insider using shared accounts or break-the-glass access with inadequate logging", "likelihood": 3, "impact": 5, "risk_score": 15, "control_gap": "Shared accounts at 2 facilities; break-the-glass access reviewed quarterly only; no UEBA", "gap_type": "Systemic Structural Weakness", "owner": "IT Director / CCO", "recommended_control": "Eliminate shared accounts; implement UEBA for Epic access; daily automated break-the-glass review", "nist_function": "Protect", "business_objective_at_risk": "HIPAA Compliance", "priority": "High", "ale_usd": 720000, "ale_formatted": "$720,000"},
        {"id": "RISK-005", "asset": "Security Governance (Organization-Wide)", "threat_scenario": "Security incidents escalate without strategic response due to no CISO and no security budget authority", "likelihood": 5, "impact": 4, "risk_score": 20, "control_gap": "No CISO; no dedicated security budget; security decisions reactive", "gap_type": "Systemic Structural Weakness", "owner": "CEO / COO", "recommended_control": "Hire CISO or appoint vCISO; establish Security Steering Committee; create dedicated security budget", "nist_function": "Govern", "business_objective_at_risk": "Operational Efficiency", "priority": "Critical"},
        {"id": "RISK-006", "asset": "RHAPSODY-01 + Epic EHR (via LabConnect VPN)", "threat_scenario": "Supply chain attack via LabConnect VPN compromise — attacker pivots to Epic EHR via Rhapsody integration account", "likelihood": 2, "impact": 5, "risk_score": 10, "control_gap": "VPN PSK not rotated 4 years; no MFA for LabConnect; Rhapsody account has bidirectional Epic access", "gap_type": "Isolated Control Failure", "owner": "IT Director", "recommended_control": "Require MFA for LabConnect VPN; rotate PSK immediately; restrict Rhapsody account to minimum required access", "nist_function": "Protect", "business_objective_at_risk": "HIPAA Compliance", "priority": "Medium", "ale_usd": 210000, "ale_formatted": "$210,000"},
        {"id": "RISK-007", "asset": "120 Baxter Sigma Infusion Pumps (VLAN 40)", "threat_scenario": "Medical device compromise via default credentials — attacker manipulates infusion rates creating patient safety risk", "likelihood": 2, "impact": 5, "risk_score": 10, "control_gap": "Default credentials not changed; no patch management; minimal VLAN isolation enforcement", "gap_type": "Isolated Control Failure", "owner": "IT Director / CMO", "recommended_control": "Change default credentials; coordinate with Baxter for firmware patches; enforce outbound firewall rules on VLAN 40", "nist_function": "Protect", "business_objective_at_risk": "Patient Safety", "priority": "Medium", "ale_usd": 160000, "ale_formatted": "$160,000"},
        {"id": "RISK-008", "asset": "All Systems (Organization-Wide)", "threat_scenario": "Delayed incident detection enables extended attacker dwell time — data exfiltration or ransomware staging undetected for days", "likelihood": 5, "impact": 4, "risk_score": 20, "control_gap": "No SIEM; no behavioral EDR; MTTD 6+ hours to 11 days in prior incidents", "gap_type": "Systemic Structural Weakness", "owner": "CISO (to be hired)", "recommended_control": "Deploy Azure Sentinel SIEM; implement behavioral EDR (Microsoft Defender for Endpoint); establish 24/7 alerting", "nist_function": "Detect", "business_objective_at_risk": "Revenue Continuity", "priority": "Critical"},
        {"id": "RISK-009", "asset": "Active Directory (14 Domain Admin Accounts)", "threat_scenario": "Privilege escalation via domain admin credential theft — admins use DA accounts for daily work without MFA", "likelihood": 4, "impact": 5, "risk_score": 20, "control_gap": "No AD tiering; domain admins use DA accounts daily; no PAM tool; no MFA on DA accounts", "gap_type": "Systemic Structural Weakness", "owner": "IT Director", "recommended_control": "Implement AD tiering; require privileged access workstations (PAWs); enforce MFA on all admin accounts; evaluate PAM tool (CyberArk, BeyondTrust)", "nist_function": "Protect", "business_objective_at_risk": "Revenue Continuity", "priority": "Critical", "ale_usd": 300000, "ale_formatted": "$300,000"},
        {"id": "RISK-010", "asset": "All Systems — Incident Response Capability", "threat_scenario": "Major incident (ransomware or breach) escalates due to outdated IRP, no playbooks, and no defined IRT", "likelihood": 3, "impact": 5, "risk_score": 15, "control_gap": "IRP outdated (2021); no ransomware playbook; no formal IRT; no forensic capability", "gap_type": "Systemic Structural Weakness", "owner": "IT Director / COO", "recommended_control": "Update IRP with ransomware, insider, and cloud playbooks; define and train IRT; conduct annual tabletop exercise; retain external IR firm on retainer", "nist_function": "Respond", "business_objective_at_risk": "HIPAA Compliance", "priority": "High"},
        {"id": "RISK-011", "asset": "Epic EHR + All Clinical Systems — BCP/DR", "threat_scenario": "Extended Epic EHR downtime after ransomware due to untested backups and undefined RTO/RPO", "likelihood": 3, "impact": 5, "risk_score": 15, "control_gap": "BCP untested (2020); Epic backup recovery never validated; no defined RTO/RPO", "gap_type": "Systemic Structural Weakness", "owner": "COO / IT Director", "recommended_control": "Conduct Epic backup recovery test; define RTO (<4 hours) / RPO (<1 hour); develop standalone DRP; conduct annual BCP tabletop", "nist_function": "Recover", "business_objective_at_risk": "Revenue Continuity", "priority": "High"},
        {"id": "RISK-012", "asset": "Azure Blob Storage (AZ-005) — Radiology Archive", "threat_scenario": "Recurrence of misconfigured storage container exposes PHI (repeat of INC-2024-002)", "likelihood": 3, "impact": 4, "risk_score": 12, "control_gap": "No Azure Policy enforcement; no CSPM tool; cloud changes require no security review", "gap_type": "Isolated Control Failure", "owner": "IT Director", "recommended_control": "Enable Microsoft Defender for Cloud; deploy Azure Policy (deny public storage containers); require security peer review for all cloud configuration changes", "nist_function": "Protect", "business_objective_at_risk": "HIPAA Compliance", "priority": "Medium"},
        {"id": "RISK-013", "asset": "All 1,200 Staff — Security Awareness", "threat_scenario": "Social engineering attacks succeed due to 34% phishing click rate and no active awareness program", "likelihood": 5, "impact": 3, "risk_score": 15, "control_gap": "61% training completion; no phishing simulation since 2023; no role-based training for clinical staff", "gap_type": "Systemic Structural Weakness", "owner": "HR Director / IT Director", "recommended_control": "Launch monthly phishing simulations; role-based training for clinical staff; mandatory completion tracking; security champions program", "nist_function": "Protect", "business_objective_at_risk": "HIPAA Compliance", "priority": "High"},
        {"id": "RISK-014", "asset": "DICOM-01 + RadCloud (340,000+ patient images)", "threat_scenario": "Static API key for RadCloud DICOM transfer is stolen, enabling unauthorized access to 5+ years of radiology imaging", "likelihood": 2, "impact": 4, "risk_score": 8, "control_gap": "Static API key not rotated 2+ years; RadCloud has SOC 2 Type I only (2022)", "gap_type": "Isolated Control Failure", "owner": "IT Director", "recommended_control": "Rotate RadCloud API key immediately; require SOC 2 Type II as 2026 contract renewal condition; implement API key rotation policy", "nist_function": "Protect", "business_objective_at_risk": "HIPAA Compliance", "priority": "Low"},
        {"id": "RISK-015", "asset": "All Systems — Vulnerability Management", "threat_scenario": "Exploitation of known critical vulnerabilities due to 90-day patching cycle (repeat of INC-2024-001)", "likelihood": 3, "impact": 4, "risk_score": 12, "control_gap": "Patch policy says 30 days; actual cycle 90+ days for servers; no automated critical patch SLA", "gap_type": "Systemic Structural Weakness", "owner": "IT Director", "recommended_control": "Enforce 14-day SLA for critical patches (CVSS 9+); 30-day SLA for high (CVSS 7+); automate patching via WSUS/SCCM; weekly Tenable scan review", "nist_function": "Identify", "business_objective_at_risk": "Revenue Continuity", "priority": "Medium"},
        {"id": "RISK-016", "asset": "HIPAA Risk Management Program", "threat_scenario": "OCR audit or enforcement action due to overdue risk analysis and non-compliant security posture", "likelihood": 3, "impact": 4, "risk_score": 12, "control_gap": "HIPAA risk analysis overdue since 2022; HIPAA Security Officer in dual role; multiple §164.312 gaps", "gap_type": "Systemic Structural Weakness", "owner": "CCO / IT Director", "recommended_control": "Commission HIPAA risk analysis immediately; dedicate HIPAA Security Officer role; remediate §164.308 and §164.312 gaps identified in assessment", "nist_function": "Govern", "business_objective_at_risk": "HIPAA Compliance", "priority": "Medium"},
    ]
