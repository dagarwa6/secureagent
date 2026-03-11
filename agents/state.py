"""
LangGraph Agent State Schema
Defines the shared state TypedDict that flows through all 5 agents in the pipeline.
"""

from typing import Optional, Any
from typing_extensions import TypedDict


class AgentState(TypedDict):
    """
    Shared state passed between all agents in the LangGraph pipeline.
    Each agent reads from and writes to this state.
    """

    # ── Input ──────────────────────────────────────────────────────────────────
    docs_path: str                                  # Path to directory with corpus documents

    # ── Agent 1: Ingestion Output ──────────────────────────────────────────────
    asset_inventory: Optional[list[dict]]           # [{name, type, environment, criticality, ...}]
    policy_refs: Optional[list[dict]]               # [{name, status, framework_mapping}]
    tech_refs: Optional[list[str]]                  # Technology/product names extracted
    vendor_risks: Optional[list[dict]]              # [{vendor, data_access, risk_notes}]
    ingestion_summary: Optional[str]                # LLM-generated executive summary of org

    # ── Agent 2: Threat Modeling Output ───────────────────────────────────────
    stride_threats: Optional[list[dict]]            # [{asset, category, description, likelihood, mitre_ids}]
    mitre_techniques: Optional[list[dict]]          # [{technique_id, name, tactic, relevance, priority}]
    kill_chain: Optional[list[dict]]                # [{stage, description, mapped_techniques}]
    top_threat_actors: Optional[list[str]]          # ["FIN12 (ransomware)", "Insider"]

    # ── Agent 3: Assessment Output ─────────────────────────────────────────────
    nist_scores: Optional[list[dict]]               # [{function, score, maturity_level, justification, gaps}]
    overall_maturity_score: Optional[float]         # Weighted average across 6 functions
    cis_controls_mapped: Optional[list[dict]]       # [{control_id, title, status}]
    industry_benchmark: Optional[float]             # Healthcare sector avg (~2.1)

    # ── Agent 4: Gap Analysis Output ──────────────────────────────────────────
    risk_findings: Optional[list[dict]]             # Full risk register (15+ findings)
    top_10_gaps: Optional[list[dict]]               # Top 10 by risk score
    fair_results: Optional[list[dict]]              # FAIR-lite ALE calculations
    systemic_count: Optional[int]                   # Count of systemic structural weaknesses
    isolated_count: Optional[int]                   # Count of isolated control failures

    # ── Agent 5: Report Output ─────────────────────────────────────────────────
    architecture_recommendations: Optional[str]     # Target-state architecture narrative
    governance_output: Optional[dict]               # {raci, policy_updates, training_plan, kpis}
    roadmap: Optional[list[dict]]                   # [{phase, timeframe, initiatives, budget}]
    change_management: Optional[dict]               # {stakeholder_plan, quick_wins, resistance_mitigation}
    executive_summary: Optional[str]                # Board-ready executive summary text
    report_path: Optional[str]                      # Path to generated .docx report

    # ── Pipeline Control ────────────────────────────────────────────────────────
    current_step: str                               # "ingestion" | "threat" | "assessment" | "gap" | "report"
    approved: Optional[bool]                        # Human-in-the-loop approval flag
    errors: list[str]                               # Error messages from any agent
    progress_messages: list[str]                    # Status messages for Streamlit UI

    # ── Data Provenance ──────────────────────────────────────────────────────────
    fallback_flags: Optional[dict]                  # {"agent_name": "llm_generated" | "fallback_static"}
