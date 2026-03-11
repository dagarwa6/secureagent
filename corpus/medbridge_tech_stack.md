# MedBridge Health Systems — Technology Stack Inventory
**Document Type:** IT Asset Inventory
**Classification:** Confidential
**Last Updated:** December 2025
**Owner:** IT Director, James Thornton

---

## 1. Clinical Applications

| Asset ID | Application | Vendor | Version | Hosting | PHI | Criticality |
|---|---|---|---|---|---|---|
| APP-001 | Epic EHR (Cogito) | Epic Systems | 2023 (Cogito) | On-prem | Yes | Critical |
| APP-002 | Epic MyChart Patient Portal | Epic Systems | 2023 | Azure (Epic-managed) | Yes | High |
| APP-003 | RadCloud PACS | Radiant Medical Imaging | 4.2 | SaaS | Yes | High |
| APP-004 | LabConnect Integration Engine | LabConnect LLC | 3.1 | On-prem (Rhapsody) | Yes | High |
| APP-005 | Dragon Medical One (dictation) | Nuance / Microsoft | Cloud | SaaS | Yes | Medium |
| APP-006 | Pharmacy System (Omnicell) | Omnicell | 2021 | On-prem | Yes | High |
| APP-007 | Scheduling System (Qgenda) | Qgenda | SaaS | SaaS | No | Medium |

---

## 2. Infrastructure Servers (On-Premises)

| Asset ID | Hostname | Role | OS | Last Patch | Location | Criticality |
|---|---|---|---|---|---|---|
| SRV-001 | EPIC-APP-01 | Epic Application Server (Primary) | Windows Server 2019 | Oct 2025 | Main Campus DC | Critical |
| SRV-002 | EPIC-APP-02 | Epic Application Server (Failover) | Windows Server 2019 | Oct 2025 | Main Campus DC | Critical |
| SRV-003 | EPIC-DB-01 | Epic SQL Database (Primary) | Windows Server 2016 + SQL 2019 | Oct 2025 | Main Campus DC | Critical |
| SRV-004 | EPIC-DB-02 | Epic SQL Database (Mirror) | Windows Server 2016 + SQL 2019 | Oct 2025 | North Campus | Critical |
| SRV-005 | EPIC-PRINT | Epic Print Server | Windows Server 2016 | Jul 2025 | Main Campus DC | Medium |
| SRV-006 | EPIC-REPORT | Epic Reporting (Clarity) | Windows Server 2019 | Oct 2025 | Main Campus DC | Medium |
| SRV-007 | AD-DC-01 | Active Directory Domain Controller (Primary) | Windows Server 2022 | Nov 2025 | Main Campus DC | Critical |
| SRV-008 | AD-DC-02 | Active Directory Domain Controller (Secondary) | Windows Server 2022 | Nov 2025 | North Campus | Critical |
| SRV-009 | FILE-01 | File Server (Clinical Docs) | Windows Server 2019 | Oct 2025 | Main Campus DC | High |
| SRV-010 | FILE-02 | File Server (Administrative) | Windows Server 2019 | Oct 2025 | Main Campus DC | Medium |
| SRV-011 | WSUS-01 | Windows Update Services | Windows Server 2022 | Nov 2025 | Main Campus DC | Medium |
| SRV-012 | BACKUP-01 | Veeam Backup Server | Windows Server 2019 | Aug 2025 | Main Campus DC | High |
| SRV-013 | RHAPSODY-01 | HL7 Integration Engine (LabConnect) | Ubuntu 22.04 | Sep 2025 | Main Campus DC | High |
| SRV-014 | DICOM-01 | DICOM Router (RadCloud) | Ubuntu 22.04 | Sep 2025 | Main Campus DC | High |
| SRV-015 | SYSLOG-01 | Syslog Server (Firewall logs) | Ubuntu 20.04 | Jun 2025 | Main Campus DC | Low |
| SRV-016 | SMTP-01 | Email Relay (Exchange Online front-end) | Windows Server 2019 | Oct 2025 | Main Campus DC | Medium |
| SRV-017 | VPN-GW | Cisco AnyConnect VPN Gateway | Cisco ASA 5555-X (EOL) | — | Main Campus | Critical |
| SRV-018 | SFTP-01 | SFTP Server (PaySync payroll) | Ubuntu 22.04 | Sep 2025 | Main Campus DMZ | Medium |

**Note:** SRV-003 and SRV-004 (Epic DB servers) running Windows Server 2016, which reaches end of support October 2026. Upgrade not yet budgeted.

---

## 3. Cloud Infrastructure (Microsoft Azure)

| Asset ID | Resource | Type | Region | PHI | Status |
|---|---|---|---|---|---|
| AZ-001 | medbridge-vnet | Virtual Network | East US 2 | No | Active |
| AZ-002 | medbridge-vpn-gw | VPN Gateway (Basic SKU) | East US 2 | No | Active |
| AZ-003 | medbridge-ad | Azure Active Directory (Entra ID) | Global | No | Active (Hybrid) |
| AZ-004 | medbridge-m365 | Microsoft 365 (Exchange Online, Teams, SharePoint) | Global | Limited | Active |
| AZ-005 | medbridge-storage | Azure Blob Storage (imaging archive) | East US 2 | Yes | Active |
| AZ-006 | medbridge-backup | Azure Backup Vault | East US 2 | Yes | Active (not tested) |
| AZ-007 | medbridge-monitor | Azure Monitor (basic) | East US 2 | No | Active (not reviewed) |

**Security gaps (Azure):**
- No Microsoft Defender for Cloud enabled
- No Azure Sentinel (SIEM)
- Azure Blob Storage has no access logging enabled
- No Azure Policy enforcement for resource compliance
- Azure AD Conditional Access not configured (only basic MFA via legacy per-user MFA)

---

## 4. Networking Equipment

| Asset ID | Device | Model | Role | EOL Status |
|---|---|---|---|---|
| NET-001 | FW-MAIN | Cisco ASA 5555-X | Perimeter Firewall | EOL 2024 |
| NET-002 | FW-NORTH | Cisco ASA 5545-X | North Campus Firewall | EOL 2023 |
| NET-003 | SW-CORE-01 | Cisco Catalyst 9300 | Core Switch (Main Campus) | Supported |
| NET-004 | SW-CORE-02 | Cisco Catalyst 9300 | Core Switch (North Campus) | Supported |
| NET-005 | SW-ACCESS-* | Cisco Catalyst 2960-X (×12) | Access Layer Switches | EOL 2020 |
| NET-006 | WAP-* | Cisco Meraki MR36 (×48) | Wireless Access Points | Supported |
| NET-007 | VPN-CLIENT | Cisco AnyConnect | Remote Access VPN | Active |

---

## 5. Endpoint Devices

| Category | Count | OS Distribution | Management | Patch Status |
|---|---|---|---|---|
| Clinical Workstations | 280 | Win 10 (42%), Win 11 (58%) | SCCM | 78% current |
| Administrative Desktops | 120 | Win 11 (100%) | SCCM | 95% current |
| Clinical Laptops | 80 | Win 11 (100%) | SCCM | 90% current |
| IT Admin Laptops | 12 | Win 11 (9), macOS (3) | Manual | Mixed |

---

## 6. Medical Devices (IoT/OT)

| Device Category | Count | Vendor | Network | Patch Mgmt | Security |
|---|---|---|---|---|---|
| Infusion Pumps (Baxter Sigma) | 120 | Baxter | VLAN 40 (WiFi) | Vendor-managed (irregular) | No agent; default credentials not changed |
| Cardiac Monitors (Philips) | 45 | Philips | VLAN 40 (wired) | Vendor-managed | Legacy TLS 1.0 |
| MRI/CT/X-Ray (GE, Siemens) | 18 | GE / Siemens | VLAN 40 | Vendor-managed | Windows XP/7 embedded (some) |
| Environmental Sensors | 32 | Various | Building Mgmt Network | Unknown | No oversight |

**Critical gap:** Medical devices on VLAN 40 have outbound internet access for vendor updates. No firewall rules restricting communication. Default credentials not changed on infusion pumps (confirmed by IT audit 2023).

---

## 7. Identity & Access Management

| Component | Technology | Status | Notes |
|---|---|---|---|
| Directory | Active Directory (on-prem) | Active | Single domain; 1,480 user accounts (including service accounts) |
| Cloud Identity | Azure AD / Entra ID (hybrid) | Active | Password hash sync; no PHS health monitoring |
| MFA | Microsoft Authenticator (per-user MFA) | Partial | 35% coverage; no Conditional Access policy |
| PAM | None | Missing | No privileged access management tool |
| SSO | Microsoft 365 SSO only | Partial | Epic, RadCloud, Qgenda use separate credentials |
| Service Accounts | 127 service accounts | Unmanaged | Many with non-expiring passwords; no review cycle |
| Admin Accounts | 14 domain admin accounts | Unmanaged | Admins use DA accounts for daily work (no tiering) |

---

## 8. Security Tools

| Tool | Vendor | Coverage | License |
|---|---|---|---|
| Windows Defender AV | Microsoft | All Windows endpoints | Included (M365 Basic) |
| Cisco ASA IPS | Cisco | Perimeter (basic) | End of life |
| Veeam Backup | Veeam | Server backup | Active |
| SCCM | Microsoft | Windows endpoints | Active |
| WSUS | Microsoft | Windows patch | Active |
| Azure Monitor (basic) | Microsoft | Azure resources | Active (unused) |
| **MISSING: SIEM** | — | — | — |
| **MISSING: EDR** | — | — | — |
| **MISSING: PAM** | — | — | — |
| **MISSING: Vulnerability Scanner** | — | — | — |
