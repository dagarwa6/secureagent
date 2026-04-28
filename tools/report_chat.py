"""
SecureAgent Report Chatbot
Lets users ask natural-language questions about the generated security assessment.
Uses context-stuffing: the full pipeline state is serialized into the LLM prompt.
"""

import logging

from langchain_core.messages import HumanMessage, SystemMessage

from config.settings import get_llm

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are SecureAgent Assistant, an AI cybersecurity analyst. "
    "Answer questions about the security posture assessment report below. "
    "Be specific: cite finding IDs, NIST CSF function names and scores, "
    "dollar amounts, and risk levels when relevant. "
    "If the answer is not in the report data, say so clearly. "
    "Keep answers concise but thorough."
)


def build_report_context(state: dict) -> str:
    """Serialize pipeline state into a structured text block for the LLM."""
    sections = []

    # Executive summary
    if state.get("executive_summary"):
        sections.append(f"## Executive Summary\n{state['executive_summary']}")

    # Org context
    if state.get("ingestion_summary"):
        sections.append(f"## Organizational Context\n{state['ingestion_summary']}")

    # NIST scores
    nist = state.get("nist_scores") or []
    if nist:
        lines = ["## NIST CSF 2.0 Maturity Scores"]
        lines.append(f"Overall Score: {state.get('overall_maturity_score', 'N/A')}/5.0")
        lines.append(f"Industry Benchmark: {state.get('industry_benchmark', 2.1)}/5.0")
        for s in nist:
            lines.append(
                f"- {s.get('function', '?')} ({s.get('function_id', '')}): "
                f"{s.get('score', '?')}/5.0 — {s.get('maturity_level', '')}. "
                f"Gaps: {', '.join(s.get('key_gaps', []))}"
            )
        sections.append("\n".join(lines))

    # Risk findings
    findings = state.get("risk_findings") or []
    if findings:
        lines = ["## Risk Register"]
        lines.append(f"Total findings: {len(findings)}")
        lines.append(f"Systemic: {state.get('systemic_count', 0)}, Isolated: {state.get('isolated_count', 0)}")
        for f in findings:
            lines.append(
                f"- [{f.get('id', '?')}] {f.get('threat_scenario', '')[:120]} | "
                f"Asset: {f.get('asset', '')} | Score: {f.get('risk_score', '?')} | "
                f"Priority: {f.get('priority', '')} | NIST: {f.get('nist_function', '')}"
            )
        sections.append("\n".join(lines))

    # FAIR results
    fair = state.get("fair_results") or []
    if fair:
        lines = ["## FAIR Risk Quantification"]
        total_ale = sum(f.get("ale_usd", 0) for f in fair)
        lines.append(f"Total Annual Loss Exposure: ${total_ale:,.0f}")
        for f in fair:
            lines.append(
                f"- {f.get('risk_name', '')}: ALE ${f.get('ale_usd', 0):,.0f}/yr "
                f"(TEF {f.get('tef_per_year', '?')}/yr, Loss ${f.get('loss_magnitude_usd', 0):,.0f}, "
                f"Control Eff {f.get('control_effectiveness', 0)*100:.0f}%) — {f.get('risk_level', '')}"
            )
        sections.append("\n".join(lines))

    # Threat model
    stride = state.get("stride_threats") or []
    if stride:
        lines = ["## STRIDE Threats (top 15)"]
        sorted_threats = sorted(stride, key=lambda x: x.get("likelihood", 0) * x.get("impact", 0), reverse=True)[:15]
        for t in sorted_threats:
            lines.append(
                f"- [{t.get('stride_category', '')}] {t.get('asset', '')}: "
                f"{t.get('threat_description', '')[:100]} "
                f"(Likelihood: {t.get('likelihood', '?')})"
            )
        sections.append("\n".join(lines))

    mitre = state.get("mitre_techniques") or []
    if mitre:
        lines = ["## MITRE ATT&CK Techniques"]
        for m in mitre[:15]:
            lines.append(
                f"- {m.get('technique_id', '')}: {m.get('technique_name', '')} "
                f"({m.get('tactic', '')}) — Priority: {m.get('priority', '')}"
            )
        sections.append("\n".join(lines))

    kill_chain = state.get("kill_chain") or []
    if kill_chain:
        lines = ["## Kill Chain Scenario"]
        for stage in kill_chain:
            lines.append(
                f"- {stage.get('stage', '')}: {stage.get('description', '')[:120]}"
            )
        sections.append("\n".join(lines))

    # Roadmap
    roadmap = state.get("roadmap") or []
    if roadmap:
        lines = ["## Implementation Roadmap"]
        total_budget = sum(p.get("budget_estimate_usd", 0) for p in roadmap)
        lines.append(f"Total 18-month investment: ${total_budget:,}")
        for phase in roadmap:
            lines.append(f"\n### {phase.get('phase', 'Phase')}")
            lines.append(f"Timeframe: {phase.get('timeframe', '')} | Budget: ${phase.get('budget_estimate_usd', 0):,}")
            for init in phase.get("initiatives", []):
                lines.append(
                    f"  - {init.get('name', '')}: {init.get('description', '')[:80]} "
                    f"(${init.get('cost_usd', 0):,}, {init.get('priority', '')})"
                )
        sections.append("\n".join(lines))

    # Governance
    gov = state.get("governance_output") or {}
    if gov:
        lines = ["## Governance"]
        kpis = gov.get("kpis") or []
        if kpis:
            lines.append("### KPIs")
            for k in kpis:
                lines.append(
                    f"- {k.get('metric', '')}: Current {k.get('current', '?')} → Target {k.get('target', '?')} "
                    f"({k.get('timeline', '')})"
                )
        policies = gov.get("policy_updates") or []
        if policies:
            lines.append("### Policy Updates")
            for p in policies:
                lines.append(
                    f"- {p.get('policy', '')}: {p.get('status', '')} — Priority: {p.get('priority', '')}, "
                    f"Owner: {p.get('owner', '')}"
                )
        sections.append("\n".join(lines))

    # Assets
    assets = state.get("asset_inventory") or []
    if assets:
        lines = ["## Asset Inventory"]
        for a in assets:
            lines.append(
                f"- {a.get('name', '')}: {a.get('type', '')} | "
                f"Environment: {a.get('environment', '')} | Criticality: {a.get('criticality', '')}"
            )
        sections.append("\n".join(lines))

    # Architecture recommendations
    if state.get("architecture_recommendations"):
        sections.append(f"## Architecture Recommendations\n{state['architecture_recommendations']}")

    # Data provenance
    flags = state.get("fallback_flags") or {}
    if flags:
        lines = ["## Data Provenance"]
        for agent, source in flags.items():
            label = "LLM Generated" if source == "llm_generated" else "Fallback (Static)"
            lines.append(f"- {agent}: {label}")
        sections.append("\n".join(lines))

    return "\n\n".join(sections)


def get_chat_response(user_question: str, report_context: str, chat_history: list) -> str:
    """Send user question + report context to LLM and return the answer."""
    llm = get_llm()

    messages = [
        SystemMessage(content=f"{SYSTEM_PROMPT}\n\n---\n\n# SECURITY ASSESSMENT REPORT\n\n{report_context}"),
    ]

    # Add conversation history
    for msg in chat_history:
        if msg["role"] == "user":
            messages.append(HumanMessage(content=msg["content"]))
        else:
            from langchain_core.messages import AIMessage
            messages.append(AIMessage(content=msg["content"]))

    # Add current question
    messages.append(HumanMessage(content=user_question))

    try:
        response = llm.invoke(messages)
        return response.content
    except Exception as e:
        logger.error(f"Chat LLM error: {e}")
        return f"Sorry, I couldn't process that question. Error: {str(e)}"
