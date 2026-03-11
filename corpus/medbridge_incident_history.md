# MedBridge Health Systems — Incident History
**Document Type:** Security Incident Log
**Classification:** Confidential
**Last Updated:** December 2025
**Owner:** IT Director, James Thornton

---

## Overview

MedBridge has experienced 3 documented security incidents over the past 3 years. This log captures confirmed incidents only. Suspected incidents that were not formally investigated are noted in Section 4.

**Note:** Due to the lack of a SIEM and centralized logging, it is likely that additional low-level incidents occurred and went undetected.

---

## Incident 1: Phishing-Driven Credential Compromise (March 2023)

**Incident ID:** INC-2023-001
**Classification:** Confirmed Credential Compromise
**Severity:** High
**Status:** Closed (remediated)

### What Happened
A clinical nurse at the East Campus facility clicked a phishing email impersonating Microsoft IT support, requesting Authenticator app re-enrollment. The link led to an adversary-in-the-middle (AiTM) phishing page that captured both the user's Active Directory credentials and session token.

The attacker used the compromised session to:
- Access the nurse's Microsoft 365 account (email, Teams, OneDrive)
- Send 47 additional phishing emails to MedBridge staff from the compromised mailbox over a 6-hour period
- Attempt to access Epic EHR using the compromised AD credentials (blocked by Epic's own session timeout — user was not actively logged in to Epic at time of compromise)

### Detection
Detected 6 hours after initial compromise when a recipient of the internal phishing email reported it to Help Desk. IT Director manually inspected mailbox and confirmed suspicious activity.

### Impact
- 1 mailbox compromised; PHI exposure limited (nurse's email contained 12 patient appointment confirmations — names + appointment dates only; no clinical records)
- HIPAA breach notification issued to 12 patients
- Business disruption: ~4 hours for IT to respond and contain

### Root Causes
- No MFA on nurse's account (she was not enrolled in the 35% that had MFA)
- No email security product capable of detecting AiTM phishing URLs
- No automated alerts for impossible travel or anomalous sign-in
- No user security awareness training in 12+ months for clinical staff

### Remediation Actions Taken
- Forced password reset for affected user and 47 recipients of internal phish
- Enabled MFA for 120 additional administrative staff (not clinical)
- Added Microsoft Defender for Office 365 (Plan 1) — email link scanning
- Posted phishing awareness notice to staff intranet

### Gaps Not Addressed
- Clinical staff MFA enrollment (still ~12%)
- No formal phishing simulation program established
- No AiTM-resistant MFA (FIDO2/hardware tokens) deployed

---

## Incident 2: Unpatched Web Server Exploit (January 2024)

**Incident ID:** INC-2024-001
**Classification:** Confirmed System Compromise
**Severity:** Critical
**Status:** Closed (remediated)

### What Happened
An external threat actor exploited a known vulnerability (CVE-2023-44487 "HTTP/2 Rapid Reset" — CVSS 7.5) in the Apache HTTP server running on the syslog server (SRV-015 / SYSLOG-01). The vulnerability had been disclosed in October 2023 and a patch was available, but MedBridge's deferred patching cycle meant the server had not been patched 3 months after disclosure.

The attacker gained initial access, installed a web shell, and used the syslog server as a pivot point. They conducted internal reconnaissance via the syslog server (which had unfiltered outbound access due to firewall rule) for approximately 72 hours before detection.

### What Was Accessed
- Firewall logs on the syslog server (30 days of network flow data)
- Internal network scanning results (attacker mapped 12 internal servers)
- No EHR data accessed (syslog server had no direct Epic connection)
- No ransomware deployed; attacker appeared to be in reconnaissance phase

### Detection
Detected when an IT sysadmin noticed unusual CPU usage on SYSLOG-01 during routine check. Manual inspection found web shell. No automated alerts triggered.

### Impact
- 72-hour dwell time with internal network visibility
- Firewall log data exfiltrated (IP addresses, connection data — no PHI)
- No HIPAA breach (no PHI exfiltrated confirmed)
- 2 days of IT staff remediation effort

### Root Causes
- Deferred patching cycle (90+ days) vs. industry standard 30 days for critical vulnerabilities
- No vulnerability scanner to identify unpatched systems
- Syslog server had unnecessary outbound internet access (firewall misconfiguration)
- No EDR on Linux servers to detect web shell
- No SIEM to correlate unusual network behavior

### Remediation Actions Taken
- Web shell removed; server reimaged
- Emergency patch cycle for all internet-facing servers
- Removed unnecessary firewall rules for syslog server
- Purchased 1-year Tenable.io vulnerability scanner subscription (basic license)

### Gaps Not Addressed
- Patching policy not formally updated (still says 30-day SLA; actual remains 90+ days for servers)
- No EDR on Linux servers
- No SIEM deployed

---

## Incident 3: Misconfigured Azure Storage (August 2024)

**Incident ID:** INC-2024-002
**Classification:** Data Exposure (Misconfiguration)
**Severity:** High
**Status:** Closed (remediated)

### What Happened
A sysadmin was migrating legacy radiology images to Azure Blob Storage (AZ-005) as part of a storage optimization project. During configuration, the storage container was inadvertently set to "public" access rather than "private." This setting exposed the storage container and its contents to the public internet for 11 days before discovery.

### What Was Exposed
- 4,800 radiology images (DICOM format) spanning 2019–2022
- DICOM headers contain: patient name, date of birth, study date, MRN, referring physician
- Estimated 3,200 unique patients affected
- No evidence of access confirmed (no access logging was enabled on the container)

### Detection
Discovered through a routine Microsoft Azure Advisor recommendation review (not security monitoring). IT sysadmin noticed the public access flag while reviewing cost optimization recommendations.

### Impact
- HIPAA breach notification to 3,200 patients and HHS Office for Civil Rights (OCR)
- Legal fees and breach notification costs: ~$85,000
- OCR investigation initiated (ongoing as of this report)
- Reputational damage; local news coverage

### Root Causes
- No Azure Policy to prevent public storage containers
- No access logging on Azure Blob Storage
- No cloud security posture management (CSPM) tool
- Change management process did not include security review for Azure configuration changes
- Single sysadmin (no peer review required for cloud changes)

### Remediation Actions Taken
- Container set to private immediately upon discovery
- Enabled Azure Blob Storage access logging (after the fact)
- Applied Azure Policy: "Storage accounts should restrict public network access"
- Mandatory peer review added for Azure configuration changes
- OCR cooperation and remediation plan submitted

### Gaps Not Addressed
- No broader Azure security baseline / policy enforcement
- No Microsoft Defender for Cloud or CSPM tool
- No DLP (data loss prevention) to detect PHI in cloud storage

---

## 4. Suspected / Unconfirmed Incidents

The following anomalies were noted but not formally investigated due to lack of detection capability:

| Date | Anomaly | Reason Not Investigated |
|---|---|---|
| Feb 2024 | 3 user accounts locked out simultaneously at 2 AM | Attributed to "system glitch"; no forensics conducted |
| May 2024 | Unusual outbound traffic spike from EPIC-APP-01 to unknown IP | Firewall log reviewed manually; IT director concluded "false positive" |
| Oct 2024 | Clinical workstation at East Campus submitted DNS queries to known C2 domain | No DNS security tool; only discovered retroactively when domain flagged in threat intel feed shared by a peer hospital |
| Nov 2025 | Infusion pump (PUMP-087) sending unexpected UDP traffic | Medical device IT not equipped to investigate; vendor notified, no follow-up |

**Note:** The October 2024 DNS query to a C2 domain is particularly concerning. Without a SIEM or DNS security capability, it is unknown whether the workstation was compromised and whether any lateral movement occurred. Workstation was reimaged as a precaution.

---

## 5. Incident Response Capability Assessment

| Capability | Current State | Gap |
|---|---|---|
| Incident Detection | Ad-hoc; user reports + manual checks | No automated detection |
| Mean Time to Detect (MTTD) | 6+ hours (INC-2023-001) to 11 days (INC-2024-002) | Industry target: <1 hour |
| Incident Response Plan | Outdated (Dec 2021); no playbooks | No ransomware, insider, or cloud playbooks |
| Incident Response Team | IT Director (primary); no defined IRT | No legal, PR, or executive escalation documented |
| Forensic Capability | None; no forensic tools or trained staff | Cannot determine scope of compromise |
| Communication Plan | No formal plan | No public or regulatory communication templates |
| Post-Incident Review | Informal; no documented lessons-learned process | Recurring issues not systematically addressed |
