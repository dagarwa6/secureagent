# MedBridge Health Systems — Security Policy Inventory
**Document Type:** Policy Registry
**Classification:** Internal
**Last Updated:** November 2025
**Owner:** IT Director, James Thornton

---

## Policy Status Legend
- **Active:** Policy is current, reviewed within 24 months, distributed to staff
- **Outdated:** Policy exists but has not been reviewed/updated in 24+ months
- **Draft:** Policy exists in draft form; not formally approved or distributed
- **Missing:** No policy exists for this domain; identified as gap

---

## Information Security Policies

| # | Policy Name | Status | Last Review | Owner | Notes |
|---|---|---|---|---|---|
| POL-001 | Acceptable Use Policy (AUP) | Active | Jan 2025 | IT Director | Covers personal device use, internet access |
| POL-002 | Information Security Policy (Master) | Outdated | Mar 2022 | IT Director | Predates NIST CSF 2.0; no governance section |
| POL-003 | Password Policy | Outdated | Jun 2021 | IT Director | Min 8 chars; no MFA requirement; no complexity requirements for service accounts |
| POL-004 | Remote Access Policy | Outdated | Aug 2022 | IT Director | Does not address cloud access patterns |
| POL-005 | Data Classification Policy | Missing | N/A | — | No formal data classification scheme in place |
| POL-006 | Asset Management Policy | Draft | — | IT Director | Draft created 2024; not approved |
| POL-007 | Patch Management Policy | Outdated | Sep 2021 | IT Sysadmin | 30-day patch SLA in policy; actual cycle is 90+ days for servers |
| POL-008 | Incident Response Plan (IRP) | Outdated | Dec 2021 | IT Director | No playbooks for ransomware, insider threat; contact list outdated |
| POL-009 | Business Continuity Plan (BCP) | Outdated | Jun 2020 | COO | Never tested; RTOs undefined; EPIC backup recovery untested |
| POL-010 | Disaster Recovery Plan (DRP) | Missing | N/A | — | BCP references DR but no standalone DRP exists |
| POL-011 | Vendor / Third-Party Risk Policy | Missing | N/A | — | No formal vendor risk assessment process |
| POL-012 | Access Control Policy | Outdated | Oct 2021 | IT Director | Does not cover privileged access management or role-based access controls |
| POL-013 | Encryption Policy | Missing | N/A | — | No defined encryption standards for data at rest or in transit |
| POL-014 | Physical Security Policy | Active | Mar 2024 | Facilities Mgr | Covers data center access, badge requirements |
| POL-015 | HIPAA Privacy Policy | Active | Jan 2025 | Compliance Officer | Maintained by compliance team |
| POL-016 | HIPAA Security Rule Policy | Outdated | Jan 2023 | Compliance Officer | Missing risk analysis update as required by HIPAA §164.308(a)(1) |
| POL-017 | Social Engineering / Phishing Policy | Missing | N/A | — | No policy or guidance for phishing awareness |
| POL-018 | Security Awareness Training Policy | Draft | — | HR Director | Annual training is informal; no formal policy |
| POL-019 | Change Management Policy | Active | Jun 2024 | IT Director | Covers infrastructure changes; no security review gate |
| POL-020 | Privileged Access Management Policy | Missing | N/A | — | No policy on admin account management, PAM tools |
| POL-021 | Medical Device Security Policy | Missing | N/A | — | No policy for IoT/OT device security or patching |
| POL-022 | Cloud Security Policy | Missing | N/A | — | Azure usage has grown organically; no formal cloud governance |

---

## Policy Gap Summary

| Category | Total Policies | Active | Outdated | Draft | Missing |
|---|---|---|---|---|---|
| Governance | 3 | 1 | 2 | 0 | 0 |
| Risk Management | 3 | 0 | 1 | 0 | 2 |
| Access Control | 3 | 0 | 2 | 0 | 1 |
| Incident Response | 2 | 0 | 1 | 0 | 1 |
| Asset & Vendor Mgmt | 3 | 0 | 1 | 1 | 1 |
| Data Protection | 3 | 1 | 1 | 0 | 1 |
| Awareness & Training | 2 | 0 | 0 | 1 | 1 |
| Cloud & Technology | 3 | 1 | 1 | 0 | 1 |
| **TOTAL** | **22** | **3 (14%)** | **9 (41%)** | **2 (9%)** | **8 (36%)** |

**Key Finding:** Only 14% of policies are current. 36% of required policy domains have no policy at all. This represents a significant governance gap against HIPAA Security Rule requirements and NIST CSF 2.0 Govern function expectations.

---

## Compliance Observations

### HIPAA Security Rule Gaps
- **§164.308(a)(1)(ii)(A)** — Risk Analysis: Current risk assessment is from 2022; HIPAA requires regular re-evaluation. **Non-compliant.**
- **§164.308(a)(5)** — Security Awareness Training: No formal training program documented. Annual phishing simulation last conducted 2023. **Non-compliant.**
- **§164.308(a)(3)** — Workforce Clearances: No formal background check process documented for clinical IT staff. **Gap identified.**
- **§164.312(a)(1)** — Access Control: Shared accounts and break-the-glass access not consistently logged. **Non-compliant.**

### NIST CSF 2.0 Govern Function Gaps
- No organizational cybersecurity strategy documented
- No security roles and responsibilities formally assigned (no CISO)
- No supply chain risk management policy
- Security not integrated into organizational risk management processes
