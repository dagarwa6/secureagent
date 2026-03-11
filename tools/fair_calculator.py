"""
FAIR-lite Risk Calculator
Lightweight quantitative risk modeling for board-level financial impact communication.

FAIR (Factor Analysis of Information Risk) translates cybersecurity risk into
financial exposure estimates using:
  ALE = TEF × LM × (1 - CE)

Where:
  TEF = Threat Event Frequency (expected occurrences per year)
  LM  = Loss Magnitude (estimated financial impact per event, USD)
  CE  = Control Effectiveness (0.0 = no controls, 1.0 = perfect controls)
  ALE = Annual Loss Expectancy (USD)
"""

from dataclasses import dataclass, field
from typing import Optional

import numpy as np


@dataclass
class FAIRInput:
    risk_name: str
    asset: str
    threat_actor: str
    threat_event_frequency: float       # TEF: expected events per year (e.g., 0.3 = once every ~3 years)
    loss_magnitude: float               # LM: estimated financial impact per event (USD)
    control_effectiveness: float        # CE: 0.0 to 1.0 (0% to 100% effective)
    confidence: str = "Medium"          # "Low" | "Medium" | "High"
    notes: str = ""
    # Monte Carlo ranges: (min, most_likely, max) — triangular distribution
    tef_range: Optional[tuple] = None   # e.g., (0.15, 0.30, 0.60)
    lm_range: Optional[tuple] = None    # e.g., (2_000_000, 4_200_000, 8_000_000)
    ce_range: Optional[tuple] = None    # e.g., (0.05, 0.15, 0.30)


@dataclass
class FAIRResult:
    risk_name: str
    asset: str
    threat_actor: str
    tef: float
    loss_magnitude: float
    control_effectiveness: float
    ale: float                          # Annual Loss Expectancy (USD) — point estimate
    ale_formatted: str                  # "$1,070,000"
    risk_level: str                     # "Critical" | "High" | "Medium" | "Low"
    confidence: str
    notes: str
    # Monte Carlo confidence interval fields
    ale_median: Optional[float] = None
    ale_p10: Optional[float] = None     # 10th percentile (optimistic)
    ale_p90: Optional[float] = None     # 90th percentile (pessimistic)
    ale_mean: Optional[float] = None


def calculate_ale(
    threat_event_frequency: float,
    loss_magnitude: float,
    control_effectiveness: float,
) -> float:
    """
    Core FAIR-lite formula:
    ALE = TEF × LM × (1 - CE)

    Args:
        threat_event_frequency: Expected threat events per year (e.g., 0.3)
        loss_magnitude: Financial impact per event in USD (e.g., 4_200_000)
        control_effectiveness: Fraction of risk mitigated by existing controls (0.0–1.0)

    Returns:
        Annual Loss Expectancy in USD
    """
    control_effectiveness = max(0.0, min(1.0, control_effectiveness))  # clamp 0–1
    return threat_event_frequency * loss_magnitude * (1.0 - control_effectiveness)


def classify_risk(ale: float) -> str:
    """Classify ALE into risk level for executive reporting."""
    if ale >= 1_000_000:
        return "Critical"
    elif ale >= 500_000:
        return "High"
    elif ale >= 100_000:
        return "Medium"
    else:
        return "Low"


def monte_carlo_fair(
    tef_range: tuple,
    lm_range: tuple,
    ce_range: tuple,
    iterations: int = 10_000,
) -> dict:
    """
    Run Monte Carlo simulation for FAIR risk quantification using triangular distributions.

    Args:
        tef_range: (min, mode, max) for Threat Event Frequency per year
        lm_range: (min, mode, max) for Loss Magnitude in USD
        ce_range: (min, mode, max) for Control Effectiveness (0-1)
        iterations: Number of simulation iterations (default: 10,000)

    Returns:
        dict with median, p10 (optimistic), p90 (pessimistic), and mean ALE values
    """
    tef_samples = np.random.triangular(tef_range[0], tef_range[1], tef_range[2], iterations)
    lm_samples = np.random.triangular(lm_range[0], lm_range[1], lm_range[2], iterations)
    ce_samples = np.random.triangular(ce_range[0], ce_range[1], ce_range[2], iterations)

    # Clamp CE to [0, 1]
    ce_samples = np.clip(ce_samples, 0.0, 1.0)

    ale_samples = tef_samples * lm_samples * (1.0 - ce_samples)

    return {
        "median": float(np.median(ale_samples)),
        "p10": float(np.percentile(ale_samples, 10)),
        "p90": float(np.percentile(ale_samples, 90)),
        "mean": float(np.mean(ale_samples)),
    }


def run_fair_analysis(inputs: list[FAIRInput]) -> list[FAIRResult]:
    """
    Run FAIR-lite analysis on a list of risk scenarios.
    Returns results sorted by ALE descending (highest financial risk first).
    """
    results = []
    for inp in inputs:
        ale = calculate_ale(inp.threat_event_frequency, inp.loss_magnitude, inp.control_effectiveness)

        # Run Monte Carlo simulation if ranges are provided
        mc_median = mc_p10 = mc_p90 = mc_mean = None
        if inp.tef_range and inp.lm_range and inp.ce_range:
            mc = monte_carlo_fair(inp.tef_range, inp.lm_range, inp.ce_range)
            mc_median = mc["median"]
            mc_p10 = mc["p10"]
            mc_p90 = mc["p90"]
            mc_mean = mc["mean"]

        results.append(FAIRResult(
            risk_name=inp.risk_name,
            asset=inp.asset,
            threat_actor=inp.threat_actor,
            tef=inp.threat_event_frequency,
            loss_magnitude=inp.loss_magnitude,
            control_effectiveness=inp.control_effectiveness,
            ale=ale,
            ale_formatted=f"${ale:,.0f}",
            risk_level=classify_risk(ale),
            confidence=inp.confidence,
            notes=inp.notes,
            ale_median=mc_median,
            ale_p10=mc_p10,
            ale_p90=mc_p90,
            ale_mean=mc_mean,
        ))

    return sorted(results, key=lambda r: r.ale, reverse=True)


# ── Pre-defined MedBridge FAIR Scenarios ─────────────────────────────────────
# Used by the Gap & Risk Agent to produce the board-ready ALE analysis

MEDBRIDGE_FAIR_SCENARIOS = [
    FAIRInput(
        risk_name="Ransomware Attack on Epic EHR",
        asset="Epic EHR (APP-001) + Database (SRV-003/SRV-004)",
        threat_actor="FIN12 / ransomware affiliate (healthcare specialization)",
        threat_event_frequency=0.30,
        loss_magnitude=4_200_000,
        control_effectiveness=0.15,
        confidence="Medium",
        notes="Based on HC3 healthcare ransomware stats: avg downtime 3.5 days; $1.2M/day operational impact + HIPAA fines + recovery",
        tef_range=(0.15, 0.30, 0.60),
        lm_range=(2_000_000, 4_200_000, 8_000_000),
        ce_range=(0.05, 0.15, 0.30),
    ),
    FAIRInput(
        risk_name="PHI Data Breach via Insider Threat",
        asset="Epic EHR (all 340,000 patient records)",
        threat_actor="Malicious or negligent insider (clinical or IT staff)",
        threat_event_frequency=1.50,
        loss_magnitude=800_000,
        control_effectiveness=0.40,
        confidence="Medium",
        notes="Shared accounts and break-the-glass access create high insider risk. OCR enforcement: avg $100/record for small breaches",
        tef_range=(0.80, 1.50, 3.00),
        lm_range=(300_000, 800_000, 2_000_000),
        ce_range=(0.25, 0.40, 0.55),
    ),
    FAIRInput(
        risk_name="Third-Party Supply Chain Compromise (LabConnect)",
        asset="Rhapsody Integration Engine → Epic EHR access",
        threat_actor="Nation-state or criminal actor targeting healthcare supply chain",
        threat_event_frequency=0.20,
        loss_magnitude=1_500_000,
        control_effectiveness=0.30,
        confidence="Low",
        notes="LabConnect VPN provides path to Epic; PSK not rotated in 4 years; no MFA required by contract",
        tef_range=(0.05, 0.20, 0.50),
        lm_range=(500_000, 1_500_000, 4_000_000),
        ce_range=(0.10, 0.30, 0.50),
    ),
    FAIRInput(
        risk_name="Medical Device Exploit (Infusion Pump Compromise)",
        asset="120 Baxter Sigma infusion pumps (VLAN 40)",
        threat_actor="Advanced threat actor targeting patient safety (or ransomware pivot)",
        threat_event_frequency=0.10,
        loss_magnitude=2_000_000,
        control_effectiveness=0.20,
        confidence="Low",
        notes="Default credentials confirmed; FDA has issued alerts for Baxter pump vulnerabilities (CVSS 9.8 in 2022)",
        tef_range=(0.03, 0.10, 0.30),
        lm_range=(500_000, 2_000_000, 5_000_000),
        ce_range=(0.05, 0.20, 0.40),
    ),
    FAIRInput(
        risk_name="Identity Governance Failure (Privilege Escalation)",
        asset="Active Directory (127 service accounts, 14 domain admins)",
        threat_actor="External attacker or insider leveraging excessive privileges",
        threat_event_frequency=2.00,
        loss_magnitude=300_000,
        control_effectiveness=0.50,
        confidence="High",
        notes="14 domain admins use DA accounts daily (no tiering); 127 service accounts unmanaged; no PAM tool",
        tef_range=(1.00, 2.00, 4.00),
        lm_range=(100_000, 300_000, 800_000),
        ce_range=(0.30, 0.50, 0.70),
    ),
]


def get_medbridge_fair_results() -> list[FAIRResult]:
    """Returns pre-computed FAIR analysis for the 5 top MedBridge risk scenarios."""
    return run_fair_analysis(MEDBRIDGE_FAIR_SCENARIOS)


def fair_results_to_dict(results: list[FAIRResult]) -> list[dict]:
    """Convert FAIRResult list to dict for JSON serialization."""
    return [
        {
            "risk_name": r.risk_name,
            "asset": r.asset,
            "threat_actor": r.threat_actor,
            "tef_per_year": r.tef,
            "loss_magnitude_usd": r.loss_magnitude,
            "control_effectiveness": r.control_effectiveness,
            "ale_usd": r.ale,
            "ale_formatted": r.ale_formatted,
            "risk_level": r.risk_level,
            "confidence": r.confidence,
            "notes": r.notes,
            # Monte Carlo confidence interval
            "ale_median": r.ale_median,
            "ale_p10": r.ale_p10,
            "ale_p90": r.ale_p90,
            "ale_mean": r.ale_mean,
        }
        for r in results
    ]
