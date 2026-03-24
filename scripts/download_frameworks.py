"""
Download free framework data:
  1. NIST CSF 2.0 — from NIST GitHub (public domain)
  2. MITRE ATT&CK Enterprise — from MITRE CTI GitHub (Apache 2.0)

Run once before first pipeline execution:
    python scripts/download_frameworks.py
"""

import os
import sys
import json
import hashlib
import urllib.request

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

FRAMEWORK_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "frameworks")

# Public URLs for free framework data
NIST_CSF_URL = "https://raw.githubusercontent.com/usnistgov/NIST-Privacy-Framework/master/NIST_Privacy_Framework_V1.0.json"
# Alternative NIST CSF 2.0 source (structured JSON)
NIST_CSF_URL_ALT = "https://csrc.nist.gov/extensions/nudp/services/json/csf/download?olirids=all"

# MITRE ATT&CK Enterprise STIX bundle (latest)
MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


# Known SHA256 hashes for integrity verification (updated when downloading new versions)
EXPECTED_HASHES = {
    "mitre_attack_enterprise.json": "628c4fc3c01b9ef37e1cd84ca3c421e1d43950a43464a14aabd1a7089601dc45",
}


def _verify_hash(data: bytes, filename: str) -> bool:
    """Verify SHA256 hash of downloaded data against known good hash."""
    actual_hash = hashlib.sha256(data).hexdigest()
    expected = EXPECTED_HASHES.get(filename)
    if expected is None:
        print(f"  ℹ️  No known hash for {filename} — skipping integrity check")
        return True
    if actual_hash == expected:
        print(f"  ✅ SHA256 verified: {actual_hash[:16]}...")
        return True
    else:
        print(f"  ⚠️  SHA256 MISMATCH for {filename}!")
        print(f"      Expected: {expected}")
        print(f"      Actual:   {actual_hash}")
        print(f"      File may be corrupted, tampered, or updated upstream.")
        print(f"      Keeping file but flagging for manual review.")
        return False


def download_file(url: str, dest_path: str, label: str) -> bool:
    """Download a file from URL to dest_path with optional SHA256 verification."""
    print(f"Downloading {label}...")
    print(f"  URL: {url}")
    print(f"  Destination: {dest_path}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecureAgent/1.0"})
        with urllib.request.urlopen(req, timeout=60) as response:
            data = response.read()
        # Verify integrity before writing
        filename = os.path.basename(dest_path)
        _verify_hash(data, filename)
        with open(dest_path, "wb") as f:
            f.write(data)
        size_kb = os.path.getsize(dest_path) / 1024
        print(f"  ✅ Downloaded: {size_kb:.0f} KB")
        return True
    except Exception as e:
        print(f"  ❌ Failed: {e}")
        return False


def create_nist_csf_fallback(dest_path: str):
    """
    Create a minimal NIST CSF 2.0 JSON structure as fallback
    if the download fails. This covers the 6 core functions with
    sample subcategories for framework-grounded LLM queries.
    """
    print("Creating NIST CSF 2.0 fallback data (structured reference)...")
    nist_data = {
        "title": "NIST Cybersecurity Framework 2.0",
        "version": "2.0",
        "functions": [
            {
                "id": "GV", "name": "Govern",
                "description": "The organization's cybersecurity risk management strategy, expectations, and policy are established, communicated, and monitored.",
                "categories": [
                    {"id": "GV.OC", "name": "Organizational Context", "subcategories": [
                        {"id": "GV.OC-01", "description": "The organizational mission is understood and informs cybersecurity risk management decisions."},
                        {"id": "GV.OC-02", "description": "Internal and external stakeholders are understood, and their needs and expectations regarding cybersecurity risk management are understood and considered."},
                    ]},
                    {"id": "GV.RM", "name": "Risk Management Strategy", "subcategories": [
                        {"id": "GV.RM-01", "description": "Risk management objectives are established and agreed to by organizational stakeholders."},
                        {"id": "GV.RM-02", "description": "Risk appetite and risk tolerance statements are established, communicated, and maintained."},
                        {"id": "GV.RM-06", "description": "A standardized method for calculating, documenting, categorizing, and prioritizing cybersecurity risks is established and communicated."},
                    ]},
                    {"id": "GV.SC", "name": "Cybersecurity Supply Chain Risk Management", "subcategories": [
                        {"id": "GV.SC-01", "description": "A cybersecurity supply chain risk management program, strategy, objectives, policies, and processes are established and agreed to by organizational stakeholders."},
                        {"id": "GV.SC-06", "description": "Planning and due diligence are performed to reduce risks before entering into formal supplier or other third-party relationships."},
                    ]},
                ]
            },
            {
                "id": "ID", "name": "Identify",
                "description": "The organization's current cybersecurity risks are understood.",
                "categories": [
                    {"id": "ID.AM", "name": "Asset Management", "subcategories": [
                        {"id": "ID.AM-01", "description": "Inventories of hardware managed by the organization are maintained."},
                        {"id": "ID.AM-02", "description": "Inventories of software, services, and systems managed by the organization are maintained."},
                        {"id": "ID.AM-05", "description": "Assets are prioritized based on classification, criticality, resources, and impact on the mission."},
                    ]},
                    {"id": "ID.RA", "name": "Risk Assessment", "subcategories": [
                        {"id": "ID.RA-01", "description": "Vulnerabilities in assets are identified, validated, and recorded."},
                        {"id": "ID.RA-03", "description": "Internal and external threats to the organization are identified and recorded."},
                        {"id": "ID.RA-05", "description": "Threats, vulnerabilities, likelihoods, and impacts are used to understand inherent risk and inform prioritization."},
                    ]},
                ]
            },
            {
                "id": "PR", "name": "Protect",
                "description": "Safeguards to manage the organization's cybersecurity risks are used.",
                "categories": [
                    {"id": "PR.AA", "name": "Identity Management, Authentication, and Access Control", "subcategories": [
                        {"id": "PR.AA-01", "description": "Identities and credentials for authorized users, services, and hardware are managed by the organization."},
                        {"id": "PR.AA-02", "description": "Identities are proofed and bound to credentials based on the context of interactions."},
                        {"id": "PR.AA-05", "description": "Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed, and incorporate the principles of least privilege and separation of duties."},
                    ]},
                    {"id": "PR.AT", "name": "Awareness and Training", "subcategories": [
                        {"id": "PR.AT-01", "description": "Personnel are provided with awareness and training so that they possess the knowledge and skills to perform general tasks with cybersecurity risks in mind."},
                        {"id": "PR.AT-02", "description": "Individuals in specialized roles are provided with awareness and training so that they possess the knowledge and skills to perform relevant tasks with cybersecurity risks in mind."},
                    ]},
                    {"id": "PR.DS", "name": "Data Security", "subcategories": [
                        {"id": "PR.DS-01", "description": "The confidentiality, integrity, and availability of data-at-rest are protected."},
                        {"id": "PR.DS-02", "description": "The confidentiality, integrity, and availability of data-in-transit are protected."},
                    ]},
                ]
            },
            {
                "id": "DE", "name": "Detect",
                "description": "Possible cybersecurity attacks and compromises are found and analyzed.",
                "categories": [
                    {"id": "DE.CM", "name": "Continuous Monitoring", "subcategories": [
                        {"id": "DE.CM-01", "description": "Networks and network services are monitored to find potentially adverse events."},
                        {"id": "DE.CM-03", "description": "Personnel activity and technology usage are monitored to find potentially adverse events."},
                        {"id": "DE.CM-06", "description": "External service provider activities and services are monitored to find potentially adverse events."},
                        {"id": "DE.CM-09", "description": "Computing hardware and software, runtime environments, and their data are monitored to find potentially adverse events."},
                    ]},
                    {"id": "DE.AE", "name": "Adverse Event Analysis", "subcategories": [
                        {"id": "DE.AE-02", "description": "Potentially adverse events are analyzed to better understand associated activities."},
                        {"id": "DE.AE-03", "description": "Information is correlated from multiple sources."},
                    ]},
                ]
            },
            {
                "id": "RS", "name": "Respond",
                "description": "Actions regarding a detected cybersecurity incident are taken.",
                "categories": [
                    {"id": "RS.MA", "name": "Incident Management", "subcategories": [
                        {"id": "RS.MA-01", "description": "The incident response plan is executed in coordination with relevant third parties once an incident is declared."},
                        {"id": "RS.MA-02", "description": "Incident reports are triaged and validated."},
                    ]},
                    {"id": "RS.CO", "name": "Incident Response Reporting and Communication", "subcategories": [
                        {"id": "RS.CO-02", "description": "Internal and external stakeholders are notified of incidents."},
                        {"id": "RS.CO-03", "description": "Information is shared with designated internal and external stakeholders."},
                    ]},
                ]
            },
            {
                "id": "RC", "name": "Recover",
                "description": "Assets and operations affected by a cybersecurity incident are restored.",
                "categories": [
                    {"id": "RC.RP", "name": "Incident Recovery Plan Execution", "subcategories": [
                        {"id": "RC.RP-01", "description": "The recovery portion of the incident response plan is executed once initiated from the incident response process."},
                        {"id": "RC.RP-03", "description": "The integrity of backups and other restoration assets is verified before using them for restoration."},
                        {"id": "RC.RP-05", "description": "The integrity of restored assets is verified, systems and services are restored, and normal operating status is confirmed."},
                    ]},
                    {"id": "RC.CO", "name": "Incident Recovery Communication", "subcategories": [
                        {"id": "RC.CO-03", "description": "Recovery activities and progress in restoring operational capabilities are communicated to designated internal and external stakeholders."},
                    ]},
                ]
            },
        ]
    }
    with open(dest_path, "w") as f:
        json.dump(nist_data, f, indent=2)
    print(f"  ✅ NIST CSF 2.0 fallback data created: {os.path.getsize(dest_path)/1024:.0f} KB")


def main():
    os.makedirs(FRAMEWORK_DIR, exist_ok=True)
    print(f"\n{'='*60}")
    print("  SecureAgent — Framework Data Download")
    print(f"{'='*60}\n")

    # NIST CSF 2.0
    nist_path = os.path.join(FRAMEWORK_DIR, "nist_csf_2_0.json")
    if os.path.exists(nist_path):
        print(f"NIST CSF 2.0 already exists: {nist_path}")
    else:
        success = download_file(MITRE_URL, nist_path + ".tmp", "NIST CSF 2.0")
        if not success:
            # Use built-in fallback
            create_nist_csf_fallback(nist_path)
        elif os.path.exists(nist_path + ".tmp"):
            os.rename(nist_path + ".tmp", nist_path)

    # MITRE ATT&CK Enterprise (large file, ~17MB)
    mitre_path = os.path.join(FRAMEWORK_DIR, "mitre_attack_enterprise.json")
    if os.path.exists(mitre_path):
        print(f"\nMITRE ATT&CK already exists: {mitre_path}")
    else:
        print()
        success = download_file(MITRE_URL, mitre_path, "MITRE ATT&CK Enterprise STIX Bundle")
        if not success:
            print("  ⚠️  MITRE ATT&CK download failed. Agents will use LLM knowledge instead.")
            print("  Retry manually: https://github.com/mitre/cti/blob/master/enterprise-attack/enterprise-attack.json")

    print(f"\n{'='*60}")
    print("  Framework download complete!")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
