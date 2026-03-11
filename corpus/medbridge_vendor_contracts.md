# MedBridge Health Systems — Vendor & Third-Party Risk Summary
**Document Type:** Vendor Register
**Classification:** Confidential
**Last Updated:** November 2025
**Owner:** IT Director, James Thornton

---

## Overview

MedBridge relies on three primary third-party vendors with direct network or data access to clinical systems. No formal third-party risk management program exists. Vendor security is assessed informally and inconsistently.

---

## Vendor 1: LabConnect LLC — Lab Results Integration

**Contract ID:** VENDOR-001
**Contract Start:** March 2021
**Contract Renewal:** March 2027
**Annual Value:** $180,000

### Services Provided
LabConnect provides clinical laboratory testing services and electronically delivers lab results directly into Epic EHR via an HL7 integration running on MedBridge's Rhapsody integration engine (SRV-013).

### Data Access
| Data Type | Direction | Volume |
|---|---|---|
| Lab orders (PHI) | MedBridge → LabConnect | ~2,400 orders/day |
| Lab results (PHI) | LabConnect → MedBridge | ~2,400 results/day |
| Patient demographics | Bi-directional | Per order |

### Technical Integration
- **Connection:** Site-to-site IPSec VPN to MedBridge VLAN 60 (Vendor DMZ)
- **Protocol:** HL7 v2.x over TCP/IP via Rhapsody interface engine
- **Authentication:** VPN pre-shared key (PSK); no certificate-based auth
- **LabConnect system access:** Read/write to Rhapsody; Rhapsody has bidirectional Epic connection

### Security Assessment Status
| Assessment | Status | Date |
|---|---|---|
| Last vendor security questionnaire | None conducted | N/A |
| SOC 2 report requested | Yes — SOC 2 Type II (2023) received | Nov 2023 |
| Business Associate Agreement (BAA) | Signed | 2021 |
| Penetration test results requested | Not requested | — |
| Security requirements in contract | Basic HIPAA language only | — |

### Risk Notes
- LabConnect's Rhapsody connection uses a shared service account with elevated privileges (domain user + Rhapsody admin)
- No MFA required by contract for LabConnect engineers accessing the VPN
- VPN PSK has not been rotated since contract initiation (4 years)
- Rhapsody has bidirectional Epic access — a LabConnect compromise could allow access to Epic data
- Last security assessment was a self-reported SOC 2 from 2023; no independent review since

**Risk Rating (Informal):** HIGH — PHI access, elevated privileges, no MFA, 4-year-old PSK

---

## Vendor 2: Radiant Medical Imaging — RadCloud PACS SaaS

**Contract ID:** VENDOR-002
**Contract Start:** September 2020
**Contract Renewal:** September 2026
**Annual Value:** $240,000

### Services Provided
Radiant provides cloud-based Picture Archiving and Communication System (PACS) for storage, management, and retrieval of radiology studies (MRI, CT, X-Ray). Radiologists access studies via a web browser on their workstations.

### Data Access
| Data Type | Direction | Volume |
|---|---|---|
| DICOM imaging studies (PHI) | MedBridge → RadCloud | ~140 studies/day |
| Radiology reports (PHI) | RadCloud → Epic (via API) | ~140 reports/day |
| Patient demographics | Bi-directional | Per study |

**Note:** The August 2024 misconfigured Azure storage incident (INC-2024-002) involved DICOM files intended for eventual migration to RadCloud — highlighting supply chain risk in imaging data flows.

### Technical Integration
- **Connection:** HTTPS (TLS 1.2) from on-prem DICOM router (SRV-014) to RadCloud SaaS
- **Authentication:** API key (static; not rotated); DICOM integration account is a domain user account
- **Radiologist access:** HTTPS web portal with username/password; MFA optional (only ~60% of radiologists enrolled)
- **Report delivery:** HL7 messages via Epic integration API (API key authentication)

### Security Assessment Status
| Assessment | Status | Date |
|---|---|---|
| SOC 2 Type I | Obtained | 2022 |
| SOC 2 Type II | Not available | — |
| Last security questionnaire | None | — |
| BAA | Signed | 2020 |
| Penetration test | Not requested | — |

### Risk Notes
- RadCloud holds 5+ years of MedBridge DICOM imaging studies (340,000+ patient records)
- SOC 2 Type I only (point-in-time; weaker assurance than ongoing Type II)
- Static API key for DICOM transfer not rotated in 2+ years
- DICOM integration uses a domain user account (lateral movement risk if compromised)
- 40% of radiologists do not use MFA for accessing cloud PACS
- OCR inquiry from INC-2024-002 has raised questions about RadCloud data governance practices

**Risk Rating (Informal):** HIGH — Large PHI repository, no Type II SOC 2, static API keys, partial MFA

---

## Vendor 3: PaySync Inc. — Payroll Processing

**Contract ID:** VENDOR-003
**Contract Start:** January 2019
**Contract Renewal:** January 2027
**Annual Value:** $95,000

### Services Provided
PaySync processes bi-weekly payroll for all 1,200 MedBridge employees. Data is exchanged via SFTP. No direct network access to MedBridge internal systems.

### Data Access
| Data Type | Direction | Volume |
|---|---|---|
| Employee PII (SSN, salary, bank routing) | MedBridge → PaySync | Bi-weekly |
| Payroll reports | PaySync → MedBridge | Bi-weekly |
| W-2 / tax documents | PaySync → MedBridge | Annual |

### Technical Integration
- **Connection:** SFTP to MedBridge DMZ server (SRV-018)
- **Authentication:** SSH key-based authentication (keys rotated annually)
- **Data encryption:** SFTP (encrypted in transit); no PHI involved (employee PII only)

### Security Assessment Status
| Assessment | Status | Date |
|---|---|---|
| SOC 2 Type II | Obtained and reviewed | 2024 |
| Last security questionnaire | Completed | Oct 2024 |
| BAA | Not applicable (no PHI) | — |
| Data Processing Agreement | Signed | 2023 |
| Penetration test results | Requested; not received | — |

### Risk Notes
- Lowest risk profile of the three vendors
- SOC 2 Type II available and recent (2024)
- Scope limited to SFTP; no internal network access
- Primary risk: employee PII (SSN, bank data) — not PHI, but still sensitive
- SSH keys rotated annually — acceptable practice

**Risk Rating (Informal):** MEDIUM — Employee PII only; good controls in place; limited access scope

---

## Vendor Risk Summary

| Vendor | PHI Access | Network Access | SOC 2 | MFA Required | Risk Rating |
|---|---|---|---|---|---|
| LabConnect LLC | Yes (orders/results) | Direct VPN to DMZ | Type II (2023) | No | HIGH |
| Radiant (RadCloud) | Yes (DICOM/imaging) | HTTPS (SaaS) | Type I only | Partial | HIGH |
| PaySync Inc. | No (employee PII) | SFTP only | Type II (2024) | SFTP keys | MEDIUM |

---

## Recommended Actions (Not Yet Implemented)

1. Establish formal Third-Party Risk Management (TPRM) program
2. Require MFA for all vendor connections with PHI access (LabConnect, RadCloud)
3. Rotate LabConnect VPN PSK and RadCloud API key immediately
4. Require SOC 2 Type II from RadCloud as contract condition at 2026 renewal
5. Conduct annual vendor security questionnaire using SIG Lite framework
6. Add security requirements (MFA, encryption standards, breach notification SLAs) to vendor contracts
7. Implement network monitoring for Vendor VLAN 60 traffic
