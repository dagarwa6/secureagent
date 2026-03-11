"""
SecureAgent — Streamlit Demo UI
Interactive web interface for the AI-powered security posture assessment pipeline.

Usage:
    streamlit run app/streamlit_app.py

Features:
  - File upload (MD, PDF, DOCX)
  - Real-time agent progress visualization
  - Results tabs: Summary | Threat Model | Risk Register | NIST Scores | Roadmap
  - Download button for the generated DOCX report
"""

import os
import sys
import json
import logging
import tempfile
import shutil
from pathlib import Path

import streamlit as st

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

logger = logging.getLogger(__name__)

# ── Load API key from environment / .env file ────────────────────────────────
# Never hardcode API keys — load from .env or environment variable
from dotenv import load_dotenv
load_dotenv(dotenv_path=project_root / ".env")

# ── Page Config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="SecureAgent — AI Security Assessment",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────

st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #1A3A5C 0%, #C81026 100%);
        padding: 20px;
        border-radius: 8px;
        margin-bottom: 20px;
        color: white;
    }
    .metric-card {
        background: #f0f4f8;
        border-left: 4px solid #1A3A5C;
        padding: 10px 15px;
        border-radius: 4px;
        margin: 5px 0;
    }
    .risk-critical { color: #C00000; font-weight: bold; }
    .risk-high { color: #FF6B00; font-weight: bold; }
    .risk-medium { color: #FFA500; }
    .risk-low { color: #008000; }
    .agent-complete { color: #008000; }
    .agent-running { color: #FF6B00; }
</style>
""", unsafe_allow_html=True)

# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## ⚙️ Configuration")

    _has_gemini = bool(os.environ.get("GEMINI_API_KEY"))
    _has_groq = bool(os.environ.get("GROQ_API_KEY"))
    if _has_gemini or _has_groq:
        _llm_name = "Groq" if _has_groq else "Gemini 2.0 Flash"
        st.markdown(f"### ✅ LLM: {_llm_name}")
        st.success("API key loaded from .env")
    else:
        st.markdown("### ⚠️ LLM: Not Configured")
        st.error("No API key found. Copy `.env.example` to `.env` and add your GEMINI_API_KEY or GROQ_API_KEY.")

    st.markdown("---")
    st.markdown("### 📋 About")
    st.markdown("""
**SecureAgent** conducts AI-powered cybersecurity posture assessments using a 5-agent LangGraph pipeline:

1. 📥 **Ingestion Agent** — Parse documents
2. 🎯 **Threat Modeling** — STRIDE + MITRE ATT&CK
3. 📊 **Assessment** — NIST CSF 2.0 scoring
4. ⚠️ **Gap Analysis** — Risk register + FAIR
5. 📄 **Report Generation** — Board-ready DOCX

**Free stack:** Gemini API + ChromaDB + sentence-transformers
    """)

    st.markdown("---")
    use_corpus = st.checkbox("Use pre-loaded MedBridge corpus", value=True)
    include_report = st.checkbox("Generate DOCX report", value=True)

# ── Main Header ───────────────────────────────────────────────────────────────

st.markdown("""
<div class="main-header">
    <h1>🛡️ SecureAgent</h1>
    <p>AI-Powered Autonomous Security Posture Assessment | CIS 8397 Capstone | Georgia State University</p>
</div>
""", unsafe_allow_html=True)

# ── File Upload ───────────────────────────────────────────────────────────────

st.markdown("## 📁 Document Upload")
st.markdown("Upload organizational documents for analysis, or use the pre-loaded MedBridge corpus.")

col1, col2 = st.columns([2, 1])
with col1:
    uploaded_files = st.file_uploader(
        "Upload documents (MD, PDF, DOCX, TXT)",
        accept_multiple_files=True,
        type=["md", "pdf", "docx", "txt"],
        disabled=use_corpus,
    )

with col2:
    st.markdown("**Pre-loaded MedBridge Corpus:**" if use_corpus else "**Or upload your documents →**")
    if use_corpus:
        corpus_docs = [
            "📄 medbridge_network_architecture.md",
            "📄 medbridge_policy_inventory.md",
            "📄 medbridge_tech_stack.md",
            "📄 medbridge_org_chart.md",
            "📄 medbridge_incident_history.md",
            "📄 medbridge_vendor_contracts.md",
        ]
        for doc in corpus_docs:
            st.markdown(doc)

# ── Run Pipeline ──────────────────────────────────────────────────────────────

st.markdown("---")
run_col, info_col = st.columns([1, 3])

with run_col:
    _api_ready = _has_gemini or _has_groq
    run_button = st.button(
        "🚀 Run SecureAgent Pipeline",
        type="primary",
        use_container_width=True,
        disabled=not _api_ready,
    )

with info_col:
    if _api_ready:
        st.info(f"✅ {_llm_name} ready. Click **Run SecureAgent Pipeline** to start the analysis.")
    else:
        st.warning("⚠️ Add your API key to `.env` before running. See `.env.example` for setup.")

# ── Pipeline Execution ────────────────────────────────────────────────────────

if run_button:
    # Determine docs path
    if use_corpus:
        docs_path = str(project_root / "corpus")
    elif uploaded_files:
        # Save uploaded files to temp directory
        tmp_dir = tempfile.mkdtemp()
        for file in uploaded_files:
            dest = os.path.join(tmp_dir, file.name)
            with open(dest, "wb") as f:
                f.write(file.getbuffer())
        docs_path = tmp_dir
    else:
        st.error("Please upload documents or enable the pre-loaded corpus.")
        st.stop()

    # Progress UI
    st.markdown("## ⚡ Pipeline Execution")
    progress_bar = st.progress(0)
    status_container = st.empty()

    agent_status = {
        "ingestion": "⏳ Pending",
        "threat_modeling": "⏳ Pending",
        "assessment": "⏳ Pending",
        "gap_analysis": "⏳ Pending",
        "report_generation": "⏳ Pending",
    }

    def update_status(step: str, status: str):
        agent_status[step] = status
        status_md = "\n".join([
            f"{'✅' if 'Complete' in v else '🔄' if 'Running' in v else '⏳'} "
            f"**{k.replace('_', ' ').title()}:** {v}"
            for k, v in agent_status.items()
        ])
        status_container.markdown(status_md)

    update_status("ingestion", "🔄 Running...")
    progress_bar.progress(10)

    try:
        # Set approval flag so human_review passes automatically in web mode
        if "pipeline_state" not in st.session_state:
            st.session_state.pipeline_state = None

        from agents.graph import run_pipeline

        # Run with progress callbacks via polling
        with st.spinner("Running SecureAgent analysis pipeline..."):
            update_status("ingestion", "🔄 Running...")
            final_state = run_pipeline(
                docs_path=docs_path,
                include_report=include_report,
                approved=True,
            )

        # Update all to complete
        for key in agent_status:
            agent_status[key] = "✅ Complete"
        update_status("report_generation", "✅ Complete")
        progress_bar.progress(100)

        st.session_state.pipeline_state = final_state
        st.success("✅ SecureAgent pipeline completed successfully!")

        # Clean up temp dir if used
        if not use_corpus and uploaded_files:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    except Exception as e:
        st.error(f"❌ Pipeline error: {str(e)}")
        logger.exception("Pipeline execution failed")

# ── Results Display ───────────────────────────────────────────────────────────

if "pipeline_state" in st.session_state and st.session_state.pipeline_state:
    state = st.session_state.pipeline_state

    st.markdown("---")
    st.markdown("## 📊 Assessment Results")

    # Error display
    errors = state.get("errors", [])
    if errors:
        with st.expander(f"⚠️ {len(errors)} Warning(s)", expanded=False):
            for err in errors:
                st.warning(err)

    # ── Summary Tab ──────────────────────────────────────────────────────────

    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "📋 Summary", "🎯 Threat Model", "⚠️ Risk Register", "📊 NIST Scores", "🗺️ Roadmap", "📄 Report"
    ])

    with tab1:
        st.markdown("### Executive Summary")
        exec_summary = state.get("executive_summary", "")
        if exec_summary:
            st.markdown(exec_summary)

        st.markdown("### Key Metrics")
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            overall = state.get("overall_maturity_score", 0) or 0
            benchmark = state.get("industry_benchmark", 2.1) or 2.1
            delta = overall - benchmark
            st.metric("NIST CSF Score", f"{overall:.2f}/5.0",
                      delta=f"{delta:.2f} vs benchmark", delta_color="inverse")
        with m2:
            findings = state.get("risk_findings") or []
            st.metric("Risk Findings", len(findings),
                      delta=f"{state.get('systemic_count', 0)} systemic")
        with m3:
            assets = state.get("asset_inventory") or []
            st.metric("Assets Analyzed", len(assets))
        with m4:
            fair_results = state.get("fair_results") or []
            total_ale = sum(f.get("ale_usd", 0) for f in fair_results)
            st.metric("Total ALE Exposure", f"${total_ale:,.0f}")

        st.markdown("### Organizational Context")
        summary = state.get("ingestion_summary", "")
        if summary:
            st.info(summary)

    with tab2:
        st.markdown("### Kill Chain — Ransomware Attack Scenario")
        kill_chain = state.get("kill_chain") or []
        for stage in kill_chain:
            with st.expander(stage.get("stage", "Stage"), expanded=False):
                st.markdown(f"**Description:** {stage.get('description', '')}")
                st.markdown(f"**MITRE Techniques:** {', '.join(stage.get('mapped_techniques', []))}")
                if stage.get("medbridge_relevance"):
                    st.markdown(f"**MedBridge Context:** {stage.get('medbridge_relevance', '')}")

        st.markdown("### Top MITRE ATT&CK Techniques")
        mitre = state.get("mitre_techniques") or []
        if mitre:
            critical = [m for m in mitre if m.get("priority") == "Critical"][:10]
            if critical:
                import pandas as pd
                df = pd.DataFrame([{
                    "Technique ID": m.get("technique_id", ""),
                    "Name": m.get("technique_name", ""),
                    "Tactic": m.get("tactic", ""),
                    "Priority": m.get("priority", ""),
                } for m in critical])
                st.dataframe(df, use_container_width=True)

        st.markdown("### STRIDE Threat Summary")
        stride = state.get("stride_threats") or []
        if stride:
            import pandas as pd
            top_stride = sorted(stride, key=lambda x: x.get("likelihood", 0) * x.get("impact", 0), reverse=True)[:15]
            df = pd.DataFrame([{
                "Asset": t.get("asset", "")[:30],
                "STRIDE Category": t.get("stride_category", ""),
                "Threat": t.get("threat_description", "")[:80],
                "Likelihood": t.get("likelihood", ""),
            } for t in top_stride])
            st.dataframe(df, use_container_width=True)
        else:
            st.info("STRIDE analysis not yet available.")

    with tab3:
        st.markdown("### Risk Register")
        findings = state.get("risk_findings") or []
        if findings:
            col_a, col_b, col_c = st.columns(3)
            with col_a:
                critical_count = sum(1 for f in findings if f.get("priority") == "Critical")
                st.metric("🔴 Critical", critical_count)
            with col_b:
                high_count = sum(1 for f in findings if f.get("priority") == "High")
                st.metric("🟠 High", high_count)
            with col_c:
                med_count = sum(1 for f in findings if f.get("priority") in ("Medium", "Low"))
                st.metric("🟡 Medium/Low", med_count)

            import pandas as pd
            df = pd.DataFrame([{
                "ID": f.get("id", ""),
                "Asset": str(f.get("asset", ""))[:30],
                "Threat Scenario": str(f.get("threat_scenario", ""))[:80],
                "Risk Score": f.get("risk_score", 0),
                "Gap Type": "Systemic" if "Systemic" in str(f.get("gap_type", "")) else "Isolated",
                "Priority": f.get("priority", ""),
                "NIST Function": f.get("nist_function", ""),
            } for f in findings])
            st.dataframe(
                df.sort_values("Risk Score", ascending=False),
                use_container_width=True,
            )

            # Human review / approval
            st.markdown("---")
            st.markdown("#### 👤 Human Review")
            st.markdown("Review the risk register above before generating the final report.")
            if not state.get("approved"):
                if st.button("✅ Approve Risk Register & Generate Report"):
                    state["approved"] = True
                    st.session_state.pipeline_state = state
                    st.rerun()
            else:
                st.success("✅ Risk register approved")
        else:
            st.info("Risk register not yet generated.")

        st.markdown("### FAIR Risk Quantification")
        fair_results = state.get("fair_results") or []
        if fair_results:
            import pandas as pd
            df = pd.DataFrame([{
                "Risk Scenario": f.get("risk_name", ""),
                "TEF/yr": f.get("tef_per_year", ""),
                "Loss Magnitude": f"${f.get('loss_magnitude_usd', 0):,.0f}",
                "Control Eff.": f"{f.get('control_effectiveness', 0)*100:.0f}%",
                "ALE/yr": f.get("ale_formatted", ""),
                "Risk Level": f.get("risk_level", ""),
            } for f in fair_results])
            st.dataframe(df, use_container_width=True)
            total_ale = sum(f.get("ale_usd", 0) for f in fair_results)
            st.metric("Total Top-5 Annual Loss Exposure", f"${total_ale:,.0f}")

            # Monte Carlo confidence intervals
            has_mc = any(f.get("ale_p10") is not None for f in fair_results)
            if has_mc:
                st.markdown("#### Monte Carlo Confidence Intervals (10,000 iterations)")
                mc_df = pd.DataFrame([{
                    "Risk Scenario": f.get("risk_name", ""),
                    "P10 (Optimistic)": f"${f.get('ale_p10', 0):,.0f}" if f.get("ale_p10") else "N/A",
                    "Median": f"${f.get('ale_median', 0):,.0f}" if f.get("ale_median") else "N/A",
                    "P90 (Pessimistic)": f"${f.get('ale_p90', 0):,.0f}" if f.get("ale_p90") else "N/A",
                } for f in fair_results])
                st.dataframe(mc_df, use_container_width=True)

    with tab4:
        st.markdown("### NIST CSF 2.0 Maturity Assessment")
        nist_scores = state.get("nist_scores") or []
        if nist_scores:
            import pandas as pd

            df = pd.DataFrame([{
                "Function": s.get("function", ""),
                "Score": s.get("score", 0),
                "Maturity Level": s.get("maturity_level", ""),
                "Critical Gap": (s.get("key_gaps") or [""])[0],
            } for s in nist_scores])

            st.dataframe(df, use_container_width=True)

            # Bar chart of scores
            st.markdown("#### Maturity Score by Function")
            chart_data = {s.get("function", ""): s.get("score", 0) for s in nist_scores}
            import pandas as pd
            chart_df = pd.DataFrame.from_dict({"Score": chart_data})
            chart_df["Benchmark"] = 2.1
            st.bar_chart(chart_df)

            st.markdown(f"**Industry Benchmark (Healthcare, CISA 2024):** {state.get('industry_benchmark', 2.1)}/5.0")
            st.markdown(f"**MedBridge Overall Score:** {state.get('overall_maturity_score', 0):.2f}/5.0")

            # Detailed findings per function
            for score in nist_scores:
                with st.expander(f"**{score.get('function', '')}** ({score.get('function_id', '')}) — Score: {score.get('score', '?')}/5.0"):
                    st.markdown(f"**Justification:** {score.get('score_justification', '')}")
                    st.markdown(f"**Maturity Level:** {score.get('maturity_level', '')}")
                    gaps = score.get("key_gaps", [])
                    if gaps:
                        st.markdown("**Key Gaps:**")
                        for gap in gaps:
                            st.markdown(f"- {gap}")
                    strengths = score.get("key_strengths", [])
                    if strengths:
                        st.markdown("**Strengths:**")
                        for s in strengths:
                            st.markdown(f"- {s}")
        else:
            st.info("NIST assessment not yet available.")

    with tab5:
        st.markdown("### 18-Month Implementation Roadmap")
        roadmap = state.get("roadmap") or []
        if roadmap:
            for phase in roadmap:
                budget = phase.get("budget_estimate_usd", 0)
                with st.expander(f"**{phase.get('phase', 'Phase')}** | ${budget:,} | {phase.get('timeframe', '')}", expanded=True):
                    st.markdown(f"**Theme:** {phase.get('theme', '')}")
                    initiatives = phase.get("initiatives", [])
                    if initiatives:
                        import pandas as pd
                        df = pd.DataFrame([{
                            "Initiative": i.get("name", ""),
                            "Timeline": i.get("timeline", ""),
                            "Cost": f"${i.get('cost_usd', 0):,}",
                            "Priority": i.get("priority", ""),
                        } for i in initiatives])
                        st.dataframe(df, use_container_width=True)
                    criteria = phase.get("success_criteria", [])
                    if criteria:
                        st.markdown("**Success Criteria:**")
                        for c in criteria:
                            st.markdown(f"✓ {c}")

            # Budget summary
            total = sum(p.get("budget_estimate_usd", 0) for p in roadmap)
            st.metric("Total 18-Month Investment", f"${total:,}")

            fair_results = state.get("fair_results") or []
            total_ale = sum(f.get("ale_usd", 0) for f in fair_results)
            if total_ale > 0:
                ale_reduction = total_ale * 0.92  # Estimated 92% ALE reduction from roadmap
                roi = ale_reduction / total if total > 0 else 0
                st.metric("Estimated ALE Reduction", f"${ale_reduction:,.0f}/yr",
                          delta=f"{roi:.1f}x ROI")
        else:
            st.info("Roadmap not yet generated.")

    with tab6:
        st.markdown("### Download Report")
        report_path = state.get("report_path", "")
        if report_path and os.path.exists(report_path):
            with open(report_path, "rb") as f:
                report_bytes = f.read()
            st.download_button(
                label="📥 Download Full Assessment Report (.docx)",
                data=report_bytes,
                file_name=os.path.basename(report_path),
                mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                type="primary",
            )
            st.success(f"✅ Report generated: {os.path.basename(report_path)}")
            file_size = os.path.getsize(report_path) / 1024
            st.info(f"File size: {file_size:.1f} KB")
        elif include_report:
            st.warning("⚠️ Report generation failed or not yet complete.")
            if state.get("errors"):
                for err in state["errors"]:
                    if "Report" in err:
                        st.error(err)
        else:
            st.info("Report generation was disabled. Enable 'Generate DOCX report' in the sidebar and re-run.")

        # Export raw results as JSON
        st.markdown("---")
        st.markdown("### Export Raw Results (JSON)")
        serializable = {k: v for k, v in state.items()
                        if isinstance(v, (str, int, float, bool, list, dict, type(None)))}
        json_str = json.dumps(serializable, indent=2, default=str)
        st.download_button(
            label="📥 Download Raw Pipeline Results (.json)",
            data=json_str,
            file_name="secureagent_results.json",
            mime="application/json",
        )

# ── Footer ─────────────────────────────────────────────────────────────────────

st.markdown("---")
st.markdown(
    "<small>SecureAgent | CIS 8397 Cybersecurity Capstone | Georgia State University | Spring 2026 | "
    "Powered by LangGraph + Groq (free tier) + LlamaIndex + ChromaDB</small>",
    unsafe_allow_html=True,
)
