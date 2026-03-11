# MedBridge Health Systems — Network Architecture Overview
**Document Type:** Internal IT Infrastructure Document
**Classification:** Confidential
**Last Updated:** January 2026
**Owner:** IT Director, James Thornton

---

## 1. Organization Overview

MedBridge Health Systems operates across 6 facilities in the Atlanta metropolitan area:
- Main Campus (Midtown): Administrative HQ + Primary Care
- North Campus: Emergency + Surgical Center
- East Campus: Outpatient Clinic
- West Campus: Imaging & Radiology Center
- South Campus: Behavioral Health Unit
- Alpharetta Facility: Specialty Care Clinic

**Total Employees:** 1,200 (680 clinical, 420 administrative, 100 IT/support)
**Patient Records:** ~340,000 active patient records in Epic EHR

---

## 2. Network Topology

### 2.1 Hybrid Architecture
MedBridge operates a hybrid model with on-premises infrastructure at the Main Campus data center and cloud workloads hosted in Microsoft Azure (East US 2 region).

**On-Premises Data Center (Main Campus):**
- Primary data center: 2,400 sq ft, Tier 2 design
- Secondary data center (North Campus): DR/failover
- Managed by 3 sysadmins; no dedicated network engineer

**Cloud Infrastructure (Azure):**
- Azure subscription: Pay-as-you-go (no Enterprise Agreement)
- Azure Active Directory (Azure AD / Entra ID): hybrid-joined
- Azure Virtual Network (VNet): 10.0.0.0/16 address space
- No Azure Security Center / Defender for Cloud currently enabled

### 2.2 Network Segments
| Segment | VLAN | Range | Purpose |
|---|---|---|---|
| Clinical Workstations | VLAN 10 | 192.168.10.0/24 | Nurse stations, exam room PCs |
| Administrative | VLAN 20 | 192.168.20.0/24 | HR, Finance, Admin desktops |
| Servers (On-Prem) | VLAN 30 | 192.168.30.0/24 | Epic EHR app + DB servers |
| Medical Devices | VLAN 40 | 192.168.40.0/24 | Infusion pumps, imaging, monitors |
| Guest/Patient WiFi | VLAN 50 | 192.168.50.0/24 | Patient-accessible network |
| Vendor Access | VLAN 60 | 192.168.60.0/24 | Third-party vendor connections |
| Management | VLAN 99 | 192.168.99.0/24 | IT management, OOB access |

**Note:** VLAN segmentation exists in theory but ACL rules between segments are minimally enforced. Clinical workstations have unrestricted access to the server VLAN (VLAN 10 → VLAN 30) due to Epic EHR client-server architecture requirements that were never re-evaluated after a 2021 firewall upgrade.

### 2.3 Perimeter & Connectivity
- **Internet Edge:** Cisco ASA 5555-X firewall (EOL 2024, no active support contract)
- **ISP:** Dual ISP (AT&T Business + Comcast), BGP failover
- **Site-to-Site VPN:** Cisco ASA VPN tunnels connecting all 6 facilities to Main Campus
- **Remote Access VPN:** Cisco AnyConnect (2,000 concurrent user licenses) — all 1,200 staff have VPN access regardless of role
- **Azure Connectivity:** Azure VPN Gateway (Basic SKU, no redundancy) connecting on-prem to Azure VNet

### 2.4 DNS & Directory
- **Internal DNS:** Windows Server 2016 DNS (on-prem)
- **Active Directory:** Windows Server 2019 AD DS, single domain: medbridge.local
- **Azure AD:** Hybrid-joined via Azure AD Connect; password hash sync enabled (no PHS health monitoring)
- **MFA:** Not universally enforced. Enabled for ~35% of users (primarily IT staff and some admin roles). Clinical staff MFA enrollment: ~12%.

---

## 3. Epic EHR Infrastructure

Epic is MedBridge's core clinical application for Electronic Health Records.

### 3.1 Epic Server Environment
| Server | Role | OS | Location | Specs |
|---|---|---|---|---|
| EPIC-APP-01 | Epic application server (primary) | Windows Server 2019 | On-prem VLAN 30 | 32-core, 256GB RAM |
| EPIC-APP-02 | Epic application server (failover) | Windows Server 2019 | On-prem VLAN 30 | 32-core, 256GB RAM |
| EPIC-DB-01 | Epic database server (primary) | Windows Server 2016 + SQL Server 2019 | On-prem VLAN 30 | 64-core, 512GB RAM |
| EPIC-DB-02 | Epic database server (secondary/mirror) | Windows Server 2016 + SQL Server 2019 | North Campus | 64-core, 512GB RAM |
| EPIC-PRINT | Epic print server | Windows Server 2016 | On-prem VLAN 30 | 8-core, 32GB RAM |
| EPIC-REPORT | Epic reporting/Clarity server | Windows Server 2019 | On-prem VLAN 30 | 16-core, 64GB RAM |

**Patching Status:** Epic servers are on a deferred patching cycle (patches applied quarterly). Last OS patch cycle: October 2025. Epic application version: Cogito 2023 (1 major version behind latest).

### 3.2 Epic Access & Authentication
- Epic uses its own authentication layer on top of Active Directory
- No Epic-native MFA; relies on Windows session authentication
- ~320 clinical users have "break-the-glass" emergency access that bypasses normal access controls — logs reviewed manually once per quarter
- Shared accounts used in 2 of 6 facilities for shift-change workflows (flagged by previous IT audit, not yet remediated)

---

## 4. Third-Party Vendor Connections

Three external vendors have network connectivity into MedBridge systems:

### 4.1 LabConnect (Lab Results Integration)
- **Connection Type:** Site-to-site IPSec VPN to VLAN 60
- **Data Exchanged:** HL7 lab result messages, order feeds
- **Access Level:** Read/write to Epic interface engine (Rhapsody)
- **Security Assessment:** Not performed since 2021 contract initiation
- **MFA:** Not required by contract

### 4.2 RadCloud (Radiology PACS SaaS)
- **Connection Type:** HTTPS API; RadCloud servers connect to on-prem DICOM router
- **Data Exchanged:** DICOM imaging studies (PHI included)
- **Access Level:** Read/write DICOM data; integration account has domain user privileges
- **Security Assessment:** SOC 2 Type I (2022) — no Type II available
- **MFA:** Not enforced for RadCloud integration account

### 4.3 PaySync (Payroll Processor)
- **Connection Type:** SFTP to DMZ server; no direct network access
- **Data Exchanged:** Employee PII (SSN, salary, bank details)
- **Access Level:** SFTP only; limited scope
- **Security Assessment:** SOC 2 Type II available (2024)
- **MFA:** SFTP key-based authentication

---

## 5. Endpoint Inventory

### 5.1 Managed Endpoints
| Category | Count | OS | Managed By | EDR |
|---|---|---|---|---|
| Clinical Workstations (desktops) | 280 | Windows 10/11 (mixed) | Microsoft SCCM | Windows Defender (basic) |
| Administrative Desktops | 120 | Windows 11 | Microsoft SCCM | Windows Defender (basic) |
| Clinical Laptops | 80 | Windows 11 | Microsoft SCCM | Windows Defender (basic) |
| IT Admin Laptops | 12 | Windows 11 / macOS | Manual | Windows Defender / none |
| Linux Servers | 12 | Ubuntu 22.04 / RHEL 8 | Manual | None |
| Windows Servers | 40 | Windows Server 2016–2022 | WSUS | Windows Defender (basic) |

**Note:** No dedicated Endpoint Detection and Response (EDR) solution deployed. Windows Defender in basic (antivirus) mode only — no behavioral analytics, no centralized telemetry.

### 5.2 Unmanaged / IoT Devices
| Category | Count | Notes |
|---|---|---|
| Infusion Pumps | 120 | Proprietary OS, no patch management |
| Cardiac Monitors | 45 | VLAN 40 isolated but no IDS/IPS |
| Imaging Devices (MRI, CT, X-Ray) | 18 | Connected to RadCloud via DICOM |
| Environmental Sensors | 32 | Building management system; no IT oversight |

---

## 6. Security Monitoring & Logging

**Current State:**
- No SIEM (Security Information and Event Management) deployed
- Windows Event Logs collected locally; no centralized aggregation
- Cisco ASA firewall logs written to syslog server (30-day retention, no alerting)
- Azure Monitor enabled for Azure resources but not reviewed regularly
- No user behavior analytics (UEBA) capability
- No 24/7 Security Operations Center (SOC); incident response handled on-call by IT Director

**Log Coverage Gaps:**
- Epic EHR access logs not integrated with any central system
- Medical device logs not collected
- DNS query logging not enabled
- PowerShell/script execution logging (ScriptBlock, Module logging) not configured on endpoints

---

## 7. Known Issues & Technical Debt

1. **Cisco ASA EOL:** Primary perimeter firewall reached end-of-life in 2024; no replacement planned due to budget constraints
2. **Windows 10 mixed environment:** ~40% of clinical workstations still on Windows 10 (EOL October 2025)
3. **No SIEM:** All security events are siloed; no detection capability for lateral movement or anomalous access
4. **Flat network segments:** ACLs between VLANs not enforced; clinical and server segments effectively flat
5. **MFA gap:** Only 35% of users have MFA; clinical staff largely unenrolled
6. **Shared accounts:** Still in use at 2 facilities; audit trail compromised
7. **Azure Basic VPN:** No redundancy, no monitoring; single point of cloud connectivity failure
8. **Deferred patching:** Epic servers and ~30% of endpoints are 1–2 patch cycles behind
