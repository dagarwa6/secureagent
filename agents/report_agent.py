"""
Agent 5: Report Generation Agent
Synthesizes all prior agent outputs into:
  1. Architecture & governance recommendations
  2. 18-month implementation roadmap
  3. Change management plan
  4. Executive summary
  5. Board-ready DOCX report (via report/generator.py)
"""

import json
import logging
from langchain_core.messages import HumanMessage

from config.settings import get_llm
from agents.state import AgentState

logger = logging.getLogger(__name__)

# ── Pre-defined Architecture Recommendations ───────────────────────────────────

TARGET_ARCHITECTURE = """
## Recommended Target-State Security Architecture for MedBridge Health Systems

### 1. Zero Trust Network Architecture
**Current State:** Flat network with unenforced VLAN ACLs; clinical workstations have direct access to Epic servers.
**Recommended State:**
- Enforce microsegmentation between all VLANs (clinical, server, medical device, vendor DMZ)
- Replace legacy VPN (Cisco AnyConnect) with a Zero Trust Network Access (ZTNA) solution (e.g., Azure AD Application Proxy, Zscaler Private Access)
- Implement explicit "never trust, always verify" access model: no implicit trust from network location
- Epic EHR server VLAN accessible only via authenticated, MFA-verified sessions through ZTNA gateway
- Medical device VLAN (VLAN 40) fully isolated: outbound only to approved vendor IPs via application-layer firewall

### 2. Identity & Access Management Overhaul
**Current State:** 35% MFA, 14 untiered domain admin accounts, 127 unmanaged service accounts, no PAM.
**Recommended State:**
- **Universal MFA:** Enforce MFA for all 1,200 users via Azure AD Conditional Access policies (not legacy per-user MFA)
- **MFA Phishing Resistance:** Deploy FIDO2 security keys for all privileged users (domain admins, IT staff, executives)
- **Azure AD Privileged Identity Management (PIM):** Just-in-time privileged access; no standing domain admin permissions
- **AD Tiering:** Implement 3-tier AD model (Tier 0: Domain Controllers, Tier 1: Servers, Tier 2: Workstations)
- **Service Account Management:** Audit and remediate 127 service accounts; implement Group Managed Service Accounts (gMSA)
- **Quarterly Access Reviews:** Automated access certification via Azure AD Access Reviews
- **Automated Deprovisioning:** HR-to-IT workflow for account deactivation within 24 hours of termination

### 3. Endpoint Detection & Response
**Current State:** Windows Defender AV only; no behavioral analytics; no centralized EDR telemetry.
**Recommended State:**
- Deploy Microsoft Defender for Endpoint (MDE) on all 492 managed endpoints (280 clinical WS + 120 admin + 80 laptops + 12 IT)
- Deploy MDE on Epic EHR application and database servers
- Enable: Attack Surface Reduction (ASR) rules, network protection, tamper protection, PowerShell script block logging
- Configure MDE to alert on: LSASS access, suspicious PowerShell, lateral movement indicators, ransomware behaviors
- Centralize MDE telemetry into Azure Sentinel SIEM

### 4. SIEM & Security Operations
**Current State:** No SIEM; manual log review; no 24/7 monitoring; MTTD 6+ hours to 11 days.
**Recommended State:**
- Deploy Azure Sentinel as primary SIEM (native Azure integration reduces cost vs. third-party SIEM)
- Connect log sources: Azure AD sign-in logs, MDE endpoint telemetry, Cisco ASA/replacement firewall logs, Epic EHR access logs, DNS query logs, Azure Monitor
- Deploy custom analytics rules for: Epic EHR after-hours access, credential stuffing detection, lateral movement (RDP from clinical VLANs), ransomware indicators
- Options for 24/7 SOC: (a) Hire 2 additional security analysts + night/weekend coverage, OR (b) Engage MSSP with healthcare specialization (recommended for budget-constrained orgs)
- Target MTTD: < 1 hour for critical events

### 5. Third-Party Risk Management Program
**Current State:** No formal TPRM; LabConnect PSK not rotated 4 years; RadCloud SOC 2 Type I only.
**Recommended State:**
- Establish annual SIG Lite vendor security questionnaire process for all PHI-handling vendors
- Require MFA for all vendor VPN/API access (LabConnect, RadCloud) — add to contracts
- Require SOC 2 Type II from RadCloud at 2026 contract renewal
- Rotate LabConnect VPN PSK and RadCloud API key immediately
- Implement vendor network monitoring on VLAN 60 (Vendor DMZ)
- Add security requirements to all new vendor contracts: MFA, encryption standards, 72-hour breach notification SLA
"""

# ── Pre-defined Roadmap ───────────────────────────────────────────────────────

IMPLEMENTATION_ROADMAP = [
    {
        "phase": "Phase 1: Quick Wins & Foundations",
        "timeframe": "0–6 months",
        "budget_estimate_usd": 285000,
        "theme": "Establish security leadership, address critical MFA gap, deploy EDR",
        "initiatives": [
            {"name": "Hire CISO or engage vCISO", "timeline": "Month 1–2", "cost_usd": 180000, "priority": "Critical", "description": "Hire full-time CISO ($170–200K/yr) or engage interim vCISO ($15–25K/month). Establish security budget and steering committee."},
            {"name": "Universal MFA rollout via Conditional Access", "timeline": "Month 1–3", "cost_usd": 15000, "priority": "Critical", "description": "Enable Azure AD Conditional Access for all users; target 100% MFA enrollment (up from 35%); FIDO2 keys for privileged users."},
            {"name": "Deploy Microsoft Defender for Endpoint", "timeline": "Month 2–4", "cost_usd": 45000, "priority": "Critical", "description": "Deploy MDE on all 492 managed endpoints and Epic servers. Enable behavioral analytics, ASR rules, and script logging."},
            {"name": "Update Incident Response Plan + Playbooks", "timeline": "Month 2–3", "cost_usd": 25000, "priority": "High", "description": "Engage IR firm to update IRP with ransomware, insider, and cloud playbooks. Define and train IRT. Establish IR retainer."},
            {"name": "Annual Tabletop Exercise", "timeline": "Month 4", "cost_usd": 20000, "priority": "High", "description": "Conduct ransomware tabletop exercise with IT, COO, CCO, Legal. Validate IRP and communication plan."},
        ],
        "success_criteria": ["100% MFA enrollment", "EDR deployed on all managed endpoints", "IRP updated with playbooks", "CISO or vCISO onboarded"],
        "risk_reduction": "Addresses RISK-001, RISK-002, RISK-005, RISK-009 — eliminates ~$1.8M ALE exposure"
    },
    {
        "phase": "Phase 2: Detection, Governance & Architecture",
        "timeframe": "6–12 months",
        "budget_estimate_usd": 320000,
        "theme": "Deploy SIEM, implement Zero Trust segmentation, formalize vendor risk",
        "initiatives": [
            {"name": "Azure Sentinel SIEM Deployment", "timeline": "Month 6–9", "cost_usd": 120000, "priority": "Critical", "description": "Deploy Azure Sentinel; connect all log sources (Azure AD, MDE, firewall, Epic EHR, DNS); configure custom analytics rules. Evaluate 24/7 MSSP vs. in-house SOC."},
            {"name": "Zero Trust / Network Microsegmentation", "timeline": "Month 7–11", "cost_usd": 80000, "priority": "High", "description": "Enforce VLAN ACLs between clinical and server segments; deploy ZTNA (Azure AD App Proxy); replace EOL Cisco ASA with NGFW."},
            {"name": "Third-Party Risk Management Program", "timeline": "Month 7–8", "cost_usd": 30000, "priority": "High", "description": "Conduct SIG Lite assessments for LabConnect and RadCloud; rotate VPN PSK and API key; add MFA requirements to vendor contracts."},
            {"name": "Security Awareness Program", "timeline": "Month 6–12", "cost_usd": 90000, "priority": "High", "description": "Launch monthly phishing simulations; role-based training (clinical staff, IT, executives); security champions program; track completion to 95%."},
        ],
        "success_criteria": ["SIEM live with 24/7 alerting", "MTTD < 1 hour for critical alerts", "VLAN ACLs enforced", "Vendor MFA requirements in contracts", "Phishing click rate < 10%"],
        "risk_reduction": "Addresses RISK-008, RISK-006, RISK-013 — improves MTTD and reduces lateral movement risk"
    },
    {
        "phase": "Phase 3: Maturity & Continuous Improvement",
        "timeframe": "12–18 months",
        "budget_estimate_usd": 150000,
        "theme": "Validate recovery capability, mature governance, close remaining gaps",
        "initiatives": [
            {"name": "BCP/DR Testing & Epic Recovery Validation", "timeline": "Month 13–15", "cost_usd": 50000, "priority": "High", "description": "Conduct full Epic backup recovery test (RTO target: <4 hours, RPO: <1 hour); tabletop BCP exercise; develop standalone DRP."},
            {"name": "Continuous Vulnerability Management Maturity", "timeline": "Month 12–18", "cost_usd": 60000, "priority": "Medium", "description": "Enforce 14-day critical patch SLA; automate patching via SCCM/Intune; expand Tenable coverage to Linux servers and cloud; monthly vulnerability review cadence."},
            {"name": "Governance & Policy Maturity", "timeline": "Month 12–18", "cost_usd": 40000, "priority": "Medium", "description": "Complete all 8 missing policies; update 9 outdated policies; establish annual policy review cycle; complete overdue HIPAA risk analysis; implement security KPI dashboard for board reporting."},
        ],
        "success_criteria": ["Epic recovery tested and validated", "All policies current", "HIPAA risk analysis complete", "Board security KPI dashboard live", "NIST CSF overall score >3.0"],
        "risk_reduction": "Addresses RISK-011, RISK-015, RISK-016 — improves resilience and regulatory compliance"
    },
]

# ── RACI Matrix ───────────────────────────────────────────────────────────────

RACI_MATRIX = [
    {"security_function": "Cybersecurity Strategy & Budget", "responsible": "CISO", "accountable": "COO", "consulted": "CFO, CCO", "informed": "Board, CEO"},
    {"security_function": "Risk Management Program", "responsible": "CISO", "accountable": "COO", "consulted": "CCO, IT Director", "informed": "Board"},
    {"security_function": "Incident Response Execution", "responsible": "Security Analyst / IR Lead", "accountable": "IT Director", "consulted": "CISO, Legal", "informed": "COO, CCO, CEO"},
    {"security_function": "Patch Management", "responsible": "IT Sysadmin", "accountable": "IT Director", "consulted": "Security Analyst", "informed": "CISO"},
    {"security_function": "Identity & Access Management", "responsible": "IT Sysadmin", "accountable": "IT Director", "consulted": "CISO, HR", "informed": "CCO"},
    {"security_function": "Vendor / Third-Party Risk", "responsible": "CISO", "accountable": "COO", "consulted": "Legal, Procurement", "informed": "IT Director"},
    {"security_function": "Security Awareness Training", "responsible": "HR Director + Security Analyst", "accountable": "CISO", "consulted": "Clinical Department Heads", "informed": "COO"},
    {"security_function": "HIPAA Security Compliance", "responsible": "CCO (HIPAA Security Officer)", "accountable": "CCO", "consulted": "CISO, Legal", "informed": "CEO, Board"},
    {"security_function": "Cloud Security (Azure)", "responsible": "IT Sysadmin (Kevin Park)", "accountable": "IT Director", "consulted": "CISO", "informed": "COO"},
    {"security_function": "Board Security Reporting", "responsible": "CISO", "accountable": "CEO", "consulted": "COO, CCO", "informed": "Board"},
]


# ── Prompts ───────────────────────────────────────────────────────────────────

EXEC_SUMMARY_PROMPT = """You are a senior cybersecurity consultant writing an executive summary for MedBridge Health Systems' board of directors.

Assessment findings:
- Overall NIST CSF 2.0 maturity score: {overall_score}/5.0 (healthcare industry benchmark: 2.1)
- NIST function scores: {function_scores}
- Risk register: {risk_count} findings; top risks: {top_risks}
- Key gaps: No CISO, no SIEM, no EDR, MFA at 35%, EOL firewall, outdated IRP
- Financial exposure (FAIR-lite): {top_fair}
- 18-month investment required: ~$755,000

Write a 3-paragraph executive summary that:
1. Opens with a clear risk statement framed in business terms (patient safety, revenue, compliance)
2. Summarizes the 3 most critical findings with their financial/regulatory impact
3. Presents the strategic recommendation and investment ROI ($755K investment vs. $2.26M ALE reduction)

Tone: Board-level; no technical jargon; focus on business risk and strategic opportunity. Be direct and specific."""


def run_report_node(state: AgentState) -> AgentState:
    """LangGraph node for Report Generation Agent."""
    logger.info("Report Generation Agent: Building report")
    state["current_step"] = "report_generation"
    state["progress_messages"] = state.get("progress_messages", [])
    state["progress_messages"].append("Report Generation Agent: Generating architecture recommendations...")

    try:
        llm = get_llm()

        # Set architecture recommendations
        state["architecture_recommendations"] = TARGET_ARCHITECTURE

        # Set governance output
        state["governance_output"] = {
            "raci_matrix": RACI_MATRIX,
            "policy_updates": _get_policy_priorities(state),
            "training_plan": _get_training_plan(),
            "kpis": _get_executive_kpis(),
            "governance_structure": "Establish a Security Steering Committee chaired by the CISO reporting to COO, with monthly meetings and quarterly board reporting. Hire or contract a full-time CISO as the single accountable executive for cybersecurity risk. Create a dedicated security budget (recommended: 8-12% of IT budget, ~$170-250K annually for operations post-Phase 1).",
        }

        # Set roadmap
        state["roadmap"] = IMPLEMENTATION_ROADMAP

        # Set change management
        state["change_management"] = _get_change_management()

        state["progress_messages"].append("Report Generation Agent: Generating executive summary...")

        # Generate executive summary
        overall_score = state.get("overall_maturity_score", 1.88)
        nist_scores = state.get("nist_scores", [])
        function_scores_str = "; ".join([
            f"{s.get('function', 'Unknown')}: {s.get('score', '?')}/5.0"
            for s in nist_scores
        ]) if nist_scores else "Govern: 1.5, Identify: 2.0, Protect: 2.5, Detect: 1.8, Respond: 2.0, Recover: 1.5"

        risk_findings = state.get("risk_findings", [])
        top_risks_str = "; ".join([
            f"{r.get('id', '?')}: {r.get('threat_scenario', '')[:80]}"
            for r in (risk_findings[:3] if risk_findings else [])
        ]) or "Ransomware, PHI breach, No CISO"

        fair_results = state.get("fair_results", [])
        top_fair_str = "; ".join([
            f"{f.get('risk_name', '?')}: {f.get('ale_formatted', '?')}/yr"
            for f in (fair_results[:3] if fair_results else [])
        ]) or "Ransomware: $1.07M/yr ALE"

        exec_summary_response = llm.invoke([HumanMessage(content=EXEC_SUMMARY_PROMPT.format(
            overall_score=f"{overall_score:.1f}",
            function_scores=function_scores_str,
            risk_count=len(risk_findings),
            top_risks=top_risks_str,
            top_fair=top_fair_str,
        ))])
        state["executive_summary"] = exec_summary_response.content

        # Generate DOCX report
        state["progress_messages"].append("Report Generation Agent: Generating DOCX report...")
        state["report_path"] = _generate_docx(state)

        # Track data provenance
        fallback_flags = state.get("fallback_flags") or {}
        fallback_flags["report_generation"] = "llm_generated"
        state["fallback_flags"] = fallback_flags

        state["progress_messages"].append("Report Generation Agent: Complete ✓")
        logger.info(f"Report generation complete: {state['report_path']}")

    except Exception as e:
        logger.error(f"Report Generation Agent error: {e}")
        state["errors"] = state.get("errors", []) + [f"Report Agent: {str(e)}"]
        state["architecture_recommendations"] = state.get("architecture_recommendations") or TARGET_ARCHITECTURE
        state["roadmap"] = state.get("roadmap") or IMPLEMENTATION_ROADMAP
        # Track fallback usage
        fallback_flags = state.get("fallback_flags") or {}
        fallback_flags["report_generation"] = "fallback_static"
        state["fallback_flags"] = fallback_flags

    return state


def _generate_docx(state: AgentState) -> str:
    """Generate the DOCX report using the report generator."""
    try:
        from report.generator import ReportGenerator
        generator = ReportGenerator()
        return generator.build_report(state)
    except Exception as e:
        logger.error(f"DOCX generation failed: {e}")
        return ""


def _get_policy_priorities(state: AgentState) -> list[dict]:
    """Return prioritized policy updates based on gap analysis."""
    return [
        {"policy": "Privileged Access Management Policy", "status": "Missing", "priority": "Critical", "timeline": "Month 1", "owner": "CISO / IT Director"},
        {"policy": "Incident Response Plan (Update)", "status": "Outdated (2021)", "priority": "Critical", "timeline": "Month 2", "owner": "IT Director / IR Firm"},
        {"policy": "Password Policy (Update)", "status": "Outdated (2021)", "priority": "Critical", "timeline": "Month 1", "owner": "IT Director"},
        {"policy": "Cloud Security Policy", "status": "Missing", "priority": "High", "timeline": "Month 3", "owner": "CISO"},
        {"policy": "Vendor / Third-Party Risk Policy", "status": "Missing", "priority": "High", "timeline": "Month 3", "owner": "CISO"},
        {"policy": "Data Classification Policy", "status": "Missing", "priority": "High", "timeline": "Month 4", "owner": "CISO / CCO"},
        {"policy": "Business Continuity Plan (Update)", "status": "Outdated (2020)", "priority": "High", "timeline": "Month 4", "owner": "COO"},
        {"policy": "Security Awareness Training Policy", "status": "Draft", "priority": "High", "timeline": "Month 2", "owner": "HR / CISO"},
    ]


def _get_training_plan() -> list[dict]:
    return [
        {"audience": "All Staff (1,200)", "training": "Annual Security Awareness + HIPAA Refresher", "frequency": "Annual + quarterly micro-trainings", "format": "LMS (online)"},
        {"audience": "Clinical Staff (680)", "training": "Phishing Recognition + Epic Access Hygiene", "frequency": "Monthly phishing simulations; bi-annual classroom", "format": "Simulation + classroom"},
        {"audience": "IT Staff (7)", "training": "Security certifications (CompTIA Security+, CISSP)", "frequency": "FY2026 target: all staff certified", "format": "Self-paced + exam vouchers"},
        {"audience": "Executive Leadership (6)", "training": "Cyber Risk for Board Leaders", "frequency": "Annual; tabletop exercise participation", "format": "Workshop (external facilitator)"},
        {"audience": "New Hires", "training": "Security Onboarding (before system access)", "frequency": "Every new hire before day 1 access", "format": "LMS (online), 2 hours"},
    ]


def _get_executive_kpis() -> list[dict]:
    return [
        {"metric": "MFA Enrollment Rate", "current": "35%", "target": "100%", "timeline": "Month 3", "reporting_freq": "Monthly"},
        {"metric": "Mean Time to Detect (MTTD)", "current": "6+ hours", "target": "< 1 hour", "timeline": "Month 9", "reporting_freq": "Monthly"},
        {"metric": "Patch Compliance (Critical CVEs)", "current": "~70% (90-day cycle)", "target": "95% within 14 days", "timeline": "Month 6", "reporting_freq": "Monthly"},
        {"metric": "Phishing Click Rate", "current": "34%", "target": "< 10%", "timeline": "Month 12", "reporting_freq": "Per simulation"},
        {"metric": "NIST CSF Overall Score", "current": "~1.3/5.0", "target": "3.0/5.0", "timeline": "Month 18", "reporting_freq": "Quarterly"},
        {"metric": "Security Training Completion", "current": "61%", "target": "95%", "timeline": "Month 6", "reporting_freq": "Monthly"},
        {"metric": "Open Critical Risk Findings", "current": str(sum(1 for _ in range(5))), "target": "0 open Critical findings", "timeline": "Month 6", "reporting_freq": "Monthly"},
    ]


def _get_change_management() -> dict:
    return {
        "stakeholder_communications": [
            {"audience": "Board of Directors", "message": "MedBridge is below the healthcare industry security benchmark. A $755K 18-month investment reduces $2.26M in annual financial exposure.", "frequency": "Quarterly board meeting", "owner": "CEO + CISO"},
            {"audience": "COO / C-Suite", "message": "Security improvements protect operational continuity — an Epic ransomware event costs $1.2M/day. Phase 1 costs $285K and eliminates the highest-risk exposure.", "frequency": "Monthly steering committee", "owner": "CISO"},
            {"audience": "IT Staff (7 FTEs)", "message": "New tools (MDE, Sentinel, PAM) reduce manual workload. Training and certifications supported. New Security Analyst hire incoming.", "frequency": "Bi-weekly IT team meetings", "owner": "IT Director"},
            {"audience": "Clinical Staff (680)", "message": "MFA and security training protect patient data — HIPAA violations create personal liability. Simple, user-friendly MFA app (Microsoft Authenticator) provided.", "frequency": "Facility town halls + email", "owner": "Clinical IT Leads"},
        ],
        "quick_wins_90_days": [
            "Force MFA enrollment for all IT staff and administrative users (weeks 1–2, zero cost)",
            "Rotate LabConnect VPN PSK and RadCloud API key (1 day, zero cost)",
            "Enable Azure Policy to prevent public storage containers (1 hour, zero cost)",
            "Enable PowerShell ScriptBlock logging on all endpoints via GPO (1 day, zero cost)",
            "Identify and eliminate shared accounts at 2 facilities (1 week, zero cost)",
            "Notify LabConnect and RadCloud of upcoming MFA requirement (letter, zero cost)",
        ],
        "resistance_mitigation": [
            {"resistance": "Clinical staff: 'MFA slows me down during emergencies'", "mitigation": "Offer SMS/phone-call MFA as alternative; implement session persistence for same device (8-hour sessions); deploy shared workstation MFA via badge tap"},
            {"resistance": "IT Director: 'We don't have bandwidth for this'", "mitigation": "Hire CISO to own security roadmap; use managed services (MSSP, Sentinel automation) to reduce manual workload"},
            {"resistance": "CFO: 'Security ROI is hard to measure'", "mitigation": "Present FAIR ALE analysis: $755K investment reduces $2.26M/yr ALE exposure — 3:1 ROI in year one alone"},
            {"resistance": "Vendors: 'Adding MFA is too complex/costly'", "mitigation": "Phase in requirement over 90 days; offer to assist with Azure AD B2B federation (minimal vendor effort); make it a contract renewal condition"},
        ],
    }
