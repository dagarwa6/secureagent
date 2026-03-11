"""
LangGraph Pipeline — SecureAgent State Machine
Orchestrates all 5 agents in sequence with error handling and human-in-the-loop support.

Flow:
  ingestion → threat_modeling → assessment → gap_analysis → [human_review] → report_generation → END
"""

import logging
from typing import Literal

from langgraph.graph import StateGraph, END

from agents.state import AgentState
from agents.ingestion_agent import run_ingestion_node
from agents.threat_agent import run_threat_node
from agents.assessment_agent import run_assessment_node
from agents.gap_agent import run_gap_node

logger = logging.getLogger(__name__)


def run_report_node(state: AgentState) -> AgentState:
    """Lazy import to avoid circular deps and keep Sprint 3 code isolated."""
    from agents.report_agent import run_report_node as _run
    return _run(state)


def human_review_node(state: AgentState) -> AgentState:
    """
    Human-in-the-loop node: pauses pipeline for review.
    In CLI mode: auto-approves.
    In Streamlit mode: sets approved=False; Streamlit UI handles the approval button.
    """
    state["current_step"] = "human_review"
    # Default: auto-approve for CLI runs; Streamlit sets this before calling graph
    if state.get("approved") is None:
        state["approved"] = True  # CLI mode: skip review
    state["progress_messages"] = state.get("progress_messages", [])
    state["progress_messages"].append("Human Review: Risk register ready for review")
    return state


def should_generate_report(state: AgentState) -> Literal["report_generation", "human_review"]:
    """Conditional edge: only generate report if approved."""
    if state.get("approved"):
        return "report_generation"
    return "human_review"


def build_graph(include_report: bool = True) -> StateGraph:
    """
    Builds and compiles the SecureAgent LangGraph.

    Args:
        include_report: If True, include the report generation agent (Sprint 3+).
                        Set False to run just the analysis agents (Sprint 2 testing).
    """
    graph = StateGraph(AgentState)

    # ── Nodes ──────────────────────────────────────────────────────────────────
    graph.add_node("ingestion", run_ingestion_node)
    graph.add_node("threat_modeling", run_threat_node)
    graph.add_node("assessment", run_assessment_node)
    graph.add_node("gap_analysis", run_gap_node)
    graph.add_node("human_review", human_review_node)

    if include_report:
        graph.add_node("report_generation", run_report_node)

    # ── Edges ──────────────────────────────────────────────────────────────────
    graph.set_entry_point("ingestion")
    graph.add_edge("ingestion", "threat_modeling")
    graph.add_edge("threat_modeling", "assessment")
    graph.add_edge("assessment", "gap_analysis")
    graph.add_edge("gap_analysis", "human_review")

    if include_report:
        graph.add_conditional_edges(
            "human_review",
            should_generate_report,
            {
                "report_generation": "report_generation",
                "human_review": "human_review",
            }
        )
        graph.add_edge("report_generation", END)
    else:
        graph.add_edge("human_review", END)

    return graph.compile()


def run_pipeline(
    docs_path: str,
    include_report: bool = True,
    approved: bool = True,
) -> AgentState:
    """
    Run the full SecureAgent pipeline.

    Args:
        docs_path: Path to directory containing corpus documents
        include_report: Whether to run the report generation agent
        approved: Whether to auto-approve the human review step

    Returns:
        Final AgentState with all agent outputs
    """
    initial_state: AgentState = {
        "docs_path": docs_path,
        "asset_inventory": None,
        "policy_refs": None,
        "tech_refs": None,
        "vendor_risks": None,
        "ingestion_summary": None,
        "stride_threats": None,
        "mitre_techniques": None,
        "kill_chain": None,
        "top_threat_actors": None,
        "nist_scores": None,
        "overall_maturity_score": None,
        "cis_controls_mapped": None,
        "industry_benchmark": None,
        "risk_findings": None,
        "top_10_gaps": None,
        "fair_results": None,
        "systemic_count": None,
        "isolated_count": None,
        "architecture_recommendations": None,
        "governance_output": None,
        "roadmap": None,
        "change_management": None,
        "executive_summary": None,
        "report_path": None,
        "current_step": "starting",
        "approved": approved,
        "errors": [],
        "progress_messages": [],
        "fallback_flags": {},
    }

    app = build_graph(include_report=include_report)
    logger.info(f"Starting SecureAgent pipeline | docs_path={docs_path}")
    final_state = app.invoke(initial_state)
    logger.info(f"Pipeline complete | errors={len(final_state.get('errors', []))}")
    return final_state


# ── CLI Entry Point ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    import json
    import os
    import sys

    # Add project root to path
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s — %(message)s")

    parser = argparse.ArgumentParser(description="Run SecureAgent pipeline")
    parser.add_argument("--docs", default="corpus/", help="Path to corpus documents directory")
    parser.add_argument("--output", default="output/", help="Output directory for results")
    parser.add_argument("--no-report", action="store_true", help="Skip report generation (analysis only)")
    args = parser.parse_args()

    from config.settings import CORPUS_PATH
    docs_path = args.docs if args.docs != "corpus/" else CORPUS_PATH

    print(f"\n{'='*60}")
    print("  SecureAgent — AI Security Posture Assessment Pipeline")
    print(f"{'='*60}")
    print(f"  Documents: {docs_path}")
    print(f"  Mode: {'Analysis Only' if args.no_report else 'Full Pipeline'}")
    print(f"{'='*60}\n")

    result = run_pipeline(
        docs_path=docs_path,
        include_report=not args.no_report,
        approved=True,
    )

    # Save results to JSON
    os.makedirs(args.output, exist_ok=True)
    output_file = os.path.join(args.output, "pipeline_results.json")

    # Serialize (exclude non-JSON-serializable items)
    serializable = {k: v for k, v in result.items() if isinstance(v, (str, int, float, bool, list, dict, type(None)))}
    with open(output_file, "w") as f:
        json.dump(serializable, f, indent=2, default=str)

    print(f"\n{'='*60}")
    print("  Pipeline Complete")
    print(f"{'='*60}")
    print(f"  Assets found:     {len(result.get('asset_inventory', []))}")
    print(f"  Policies found:   {len(result.get('policy_refs', []))}")
    print(f"  STRIDE threats:   {len(result.get('stride_threats', []))}")
    print(f"  MITRE techniques: {len(result.get('mitre_techniques', []))}")
    print(f"  NIST score:       {result.get('overall_maturity_score', 'N/A'):.2f}/5.0")
    print(f"  Risk findings:    {len(result.get('risk_findings', []))}")
    print(f"  Report path:      {result.get('report_path', 'Not generated')}")
    print(f"  Errors:           {len(result.get('errors', []))}")
    if result.get("errors"):
        for err in result["errors"]:
            print(f"    ⚠ {err}")
    print(f"\n  Results saved to: {output_file}")
    print(f"{'='*60}\n")
