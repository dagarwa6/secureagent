# Project Charter
## SecureAgent — AI-Powered Security Posture Assessment
### Engagement: MedBridge Health Systems
**CIS 8397 Cybersecurity Capstone | Georgia State University | Spring 2026**
**Prepared by:** [Student Name]
**Date:** March 2026
**Version:** 1.0

---

## 1. Executive Overview

MedBridge Health Systems has engaged SecureAgent to conduct a comprehensive cybersecurity posture assessment using an AI-powered autonomous consulting pipeline. This charter establishes the scope, objectives, stakeholders, milestones, and success criteria for the engagement.

**Business Context:** MedBridge operates 6 healthcare facilities serving 340,000 patients in the Atlanta metropolitan area. As a HIPAA-regulated entity with hybrid cloud infrastructure (Azure + on-premises Epic EHR), MedBridge faces significant cybersecurity risk — particularly ransomware, which is the #1 threat to the healthcare sector. The organization has identified the need for an objective, systematic assessment of its security posture to inform a multi-year security investment roadmap.

**Assessment Driver:** A combination of regulatory pressure (HIPAA risk analysis requirements, overdue since 2022), recent security incidents (INC-2023-001, INC-2024-001, INC-2024-002), and executive awareness of the cyber threat landscape has created urgency for this engagement.

---

## 2. Engagement Objectives

| # | Objective | Success Criterion |
|---|---|---|
| 1 | Deliver a current-state security posture assessment using NIST CSF 2.0 | Maturity scores (1–5) for all 6 NIST functions with justifications |
| 2 | Identify and prioritize cybersecurity risks specific to MedBridge | Risk register with 15+ findings, ranked by risk score |
| 3 | Map the threat landscape to MedBridge's specific attack surface | STRIDE threat model + MITRE ATT&CK technique mapping |
| 4 | Design a target-state security architecture | Recommendation covering Zero Trust, IAM, EDR, SIEM |
| 5 | Develop an executable 18-month implementation roadmap | Phased plan with budget estimates and resource requirements |
| 6 | Provide board-ready deliverables | 15–20 page report + 15–20 slide executive presentation |
| 7 | Quantify top risks in financial terms | FAIR-lite ALE estimates for top 5 risk scenarios |

---

## 3. Scope Definition

### 3.1 In-Scope Assets & Systems

**Network & Infrastructure:**
- Perimeter network: Cisco ASA 5555-X firewall, dual ISP, VPN infrastructure
- Internal network: All 7 VLANs (10, 20, 30, 40, 50, 60, 99)
- Azure infrastructure: Azure AD/Entra ID, Azure VNet, Azure Blob Storage, Azure Backup

**Servers (On-Premises):**
- Epic EHR infrastructure: EPIC-APP-01, EPIC-APP-02, EPIC-DB-01, EPIC-DB-02, EPIC-REPORT (SRV-001 through SRV-006)
- Directory services: AD-DC-01, AD-DC-02 (SRV-007, SRV-008)
- File servers: FILE-01, FILE-02 (SRV-009, SRV-010)
- Integration servers: RHAPSODY-01, DICOM-01 (SRV-013, SRV-014)
- Supporting infrastructure: 12 total Linux servers; 40 total Windows servers

**Endpoints:**
- 280 clinical workstations
- 120 administrative desktops
- 80 clinical laptops
- 12 IT admin laptops

**Applications:**
- Epic EHR (Cogito 2023) — primary clinical system
- Microsoft 365 (Exchange Online, Teams, SharePoint)
- RadCloud PACS SaaS
- LabConnect HL7 integration

**Identity & Access:**
- Active Directory (domain: medbridge.local)
- Azure AD / Entra ID (hybrid-joined)
- 1,480 user accounts, 127 service accounts, 14 domain admin accounts

**Third-Party Vendors:**
- LabConnect LLC (lab results integration)
- Radiant Medical Imaging / RadCloud (PACS)
- PaySync Inc. (payroll)

**Governance & Policy:**
- All 22 documented (or missing) security policies
- HIPAA compliance posture
- Security organizational structure and roles

### 3.2 Out-of-Scope

| Item | Reason |
|---|---|
| Medical devices (infusion pumps, imaging) | Requires specialized OT/IoT security expertise; separate engagement recommended |
| Patient-facing applications (MyChart portal) | Epic-managed SaaS; vendor responsibility |
| Physical security controls | Facilities team scope; not IT-managed |
| Financial systems (billing, ERP) | Not identified as primary risk vectors for this engagement |
| Non-IT administrative systems | Out of IT security scope |

**Note:** Medical device security gaps will be documented in the risk register as a recommended follow-on engagement but detailed OT/IoT assessment is excluded from the current scope.

---

## 4. Stakeholders

| Name | Title | Role in Engagement | Communication |
|---|---|---|---|
| Dr. Patricia Chen | CEO | Executive Sponsor; approves security investment | Monthly briefings; final report presentation |
| Marcus Williams | COO | Primary executive contact; operational risk owner | Bi-weekly updates; co-recipient of final report |
| Sandra Klein | CFO | Budget authority; reviews ROI analysis | Budget section review; cost-benefit presentation |
| Lisa Torres | CCO / HIPAA Security Officer | Compliance liaison; co-owner of gap analysis | Weekly check-ins during assessment |
| James Thornton | IT Director | Primary technical contact; subject matter expert | Daily collaboration during data collection |
| [Vacant] | Security Analyst | Would be primary operational contact; role unfilled | Gap noted in charter |
| MedBridge Board | Board of Directors | Audience for final executive presentation | Board meeting presentation (Week 8) |

---

## 5. Methodology

SecureAgent uses a five-phase AI-assisted assessment methodology:

| Phase | Agent | Activities | Output |
|---|---|---|---|
| 1. Document Ingestion | Ingestion Agent | Parse organizational documents; extract assets, policies, vendor refs | Structured asset/policy/vendor inventory |
| 2. Threat Modeling | Threat Modeling Agent | STRIDE analysis; MITRE ATT&CK mapping; kill chain modeling | Threat model; 20+ STRIDE entries; kill chain diagram |
| 3. Current-State Assessment | Assessment Agent | NIST CSF 2.0 maturity scoring; CIS Controls cross-reference | Maturity scores (1–5) for 6 functions; benchmark comparison |
| 4. Gap Analysis | Gap & Risk Agent | Control gap identification; risk register; FAIR-lite quantification | 15+ prioritized findings; ALE for top 5 risks |
| 5. Report Generation | Report Generation Agent | Architecture recommendations; roadmap; board report assembly | DOCX report; board deck |

**Framework Alignment:**
- **NIST CSF 2.0**: Primary maturity framework (Govern, Identify, Protect, Detect, Respond, Recover)
- **MITRE ATT&CK**: Adversary simulation and technique mapping
- **CIS Controls v8**: Secondary benchmarking and control validation
- **FAIR**: Quantitative risk modeling for financial impact estimates
- **STRIDE**: Systematic threat modeling methodology

---

## 6. Milestones & Timeline

| Sprint | Weeks | Gate | Deliverable | Points |
|---|---|---|---|---|
| Sprint 1 | 1–2 | End Week 2 | Project Charter + environment setup + corpus + Ingestion Agent v1 | 10 |
| Sprint 2 | 3–4 | End Week 4 | Threat Model + Assessment + Gap Analysis (15+ findings) | 20 |
| Sprint 3 | 5–6 | End Week 6 | Target architecture + roadmap + working Streamlit demo + DOCX report | 22 |
| Sprint 4 | 7–8 | Week 8 | Final written report (15–20 pg) + board deck (15–20 slides) + oral defense | 43 |

### Detailed Week-by-Week Schedule

| Week | Focus | Key Deliverables |
|---|---|---|
| Week 1 | Foundation | GitHub setup, environment configuration, corpus documents, framework data download |
| Week 2 | Ingestion Agent | Ingestion Agent v1 working, Project Charter document complete |
| Week 3 | Threat Agents | Threat Modeling Agent + kill chain; Assessment Agent NIST scoring |
| Week 4 | Gap Analysis | Gap Analysis Agent + risk register (15+ findings); LangGraph pipeline wired |
| Week 5 | Architecture | Target-state architecture design; governance module; roadmap; FAIR ALE |
| Week 6 | Demo | Report Generation Agent; DOCX template; Streamlit demo UI; end-to-end test |
| Week 7 | Polish | Final report polish; board slide deck; agent hardening; validators |
| Week 8 | Defense | QA review; 2+ mock defenses; oral defense presentation |

---

## 7. Success Metrics

| Metric | Target | Measurement |
|---|---|---|
| Pipeline runtime | < 10 minutes end-to-end | Measured from document upload to DOCX download |
| NIST CSF accuracy | Scores within ±0.5 of expert benchmarks | Compare to CISA healthcare sector benchmarks (~2.1 avg) |
| Risk register coverage | 15+ prioritized findings | Count of unique risk findings with all fields populated |
| Report quality | 15–20 pages, professional grade | Word count + completeness review against rubric |
| Demo reliability | Runs successfully 3/3 test cases | Test on different subsets of corpus documents |
| Oral defense score | A-range (90+) | Rubric: framework integration, defensibility, depth |

---

## 8. Assumptions & Constraints

### Assumptions
1. MedBridge documents accurately represent the organization's current state
2. NIST CSF 2.0 is the primary framework; CIS Controls used for secondary validation
3. Groq API free tier is sufficient for full pipeline runs (14,400 requests/day)
4. All team work completed on personal hardware; no lab or cloud VM resources required

### Constraints
| Constraint | Impact | Mitigation |
|---|---|---|
| Free resources only | Cannot use GPT-4o or paid APIs | Use Groq (free) + Gemini (free) as fallbacks |
| Solo development | Full pipeline built by one person | Strict sprint gates; use AI assistance for boilerplate |
| 8-week timeline | Limited polish time | Prioritize working pipeline over perfect code |
| Simulated corpus | Not real client data | Corpus is detailed and realistic; limitations noted in report |

---

## 9. Risk Register (Project Risks)

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Groq rate limiting during demo | Medium | High | Cache all intermediate outputs as JSON; re-run expensive calls only when needed |
| LLM output inconsistency | Medium | High | Structured JSON output with Pydantic validation; retry logic |
| Scope creep | High | Medium | Freeze features after Week 6; Sprint 4 = polish only |
| Demo failure during defense | Low | High | Pre-record backup demo video; test on 3+ document sets before Week 8 |
| LLM hallucination in report | Medium | High | Human-in-the-loop review step; validators check claims against corpus |

---

## 10. Sign-off

| Role | Name | Date |
|---|---|---|
| Student (Project Lead) | [Student Name] | March 2026 |
| Faculty Advisor | Dr. William Dicker | [Date] |
