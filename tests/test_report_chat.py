"""Tests for tools/report_chat.py — report chatbot context and response."""

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.report_chat import build_report_context, get_chat_response


# ── Sample pipeline state for testing ────────────────────────────────────────

SAMPLE_STATE = {
    "executive_summary": "MedBridge faces critical security gaps in endpoint protection and identity management.",
    "ingestion_summary": "Mid-size healthcare org with 47 employees, 3 clinics, hybrid cloud.",
    "overall_maturity_score": 1.25,
    "industry_benchmark": 2.1,
    "nist_scores": [
        {"function": "Govern", "function_id": "GV", "score": 1.0, "maturity_level": "Initial",
         "key_gaps": ["No CISO role", "No security steering committee"]},
        {"function": "Identify", "function_id": "ID", "score": 1.5, "maturity_level": "Initial",
         "key_gaps": ["Incomplete asset inventory"]},
        {"function": "Protect", "function_id": "PR", "score": 1.5, "maturity_level": "Initial",
         "key_gaps": ["No MFA", "No EDR"]},
        {"function": "Detect", "function_id": "DE", "score": 1.0, "maturity_level": "Initial",
         "key_gaps": ["No SIEM"]},
        {"function": "Respond", "function_id": "RS", "score": 1.5, "maturity_level": "Initial",
         "key_gaps": ["No IR playbooks"]},
        {"function": "Recover", "function_id": "RC", "score": 1.0, "maturity_level": "Initial",
         "key_gaps": ["BCP untested"]},
    ],
    "risk_findings": [
        {"id": "RISK-001", "asset": "EHR Server", "threat_scenario": "Ransomware encryption of patient records",
         "risk_score": 20, "priority": "Critical", "nist_function": "PR", "gap_type": "Systemic"},
        {"id": "RISK-002", "asset": "Domain Controller", "threat_scenario": "Credential theft via pass-the-hash",
         "risk_score": 16, "priority": "Critical", "nist_function": "PR", "gap_type": "Systemic"},
    ],
    "fair_results": [
        {"risk_name": "Ransomware", "ale_usd": 1200000, "tef_per_year": 0.4,
         "loss_magnitude_usd": 5000000, "control_effectiveness": 0.1, "risk_level": "Critical"},
    ],
    "stride_threats": [
        {"stride_category": "Spoofing", "asset": "VPN Gateway",
         "threat_description": "Credential stuffing against VPN", "likelihood": 4, "impact": 4},
    ],
    "mitre_techniques": [
        {"technique_id": "T1566", "technique_name": "Phishing", "tactic": "Initial Access", "priority": "Critical"},
    ],
    "kill_chain": [
        {"stage": "Reconnaissance", "description": "Attacker profiles org via LinkedIn and job postings"},
    ],
    "roadmap": [
        {"phase": "Phase 1: Quick Wins", "timeframe": "0-6 months", "budget_estimate_usd": 155000,
         "initiatives": [{"name": "Deploy MFA", "description": "MFA for all users", "cost_usd": 25000, "priority": "Critical"}]},
    ],
    "governance_output": {
        "kpis": [{"metric": "MFA Enrollment", "current": "0%", "target": "100%", "timeline": "Q2 2026"}],
        "policy_updates": [{"policy": "Access Control Policy", "status": "Missing", "priority": "Critical", "owner": "CISO"}],
    },
    "asset_inventory": [
        {"name": "EHR Server", "type": "Server", "environment": "On-Prem", "criticality": "Critical"},
    ],
    "architecture_recommendations": "Implement Zero Trust Network Architecture with micro-segmentation.",
    "fallback_flags": {"ingestion": "llm_generated", "threat_modeling": "fallback_static"},
    "systemic_count": 8,
    "isolated_count": 7,
}


# ── Tests for build_report_context ───────────────────────────────────────────

class TestBuildReportContext:

    def test_returns_nonempty_string(self):
        ctx = build_report_context(SAMPLE_STATE)
        assert isinstance(ctx, str)
        assert len(ctx) > 100

    def test_includes_executive_summary(self):
        ctx = build_report_context(SAMPLE_STATE)
        assert "Executive Summary" in ctx
        assert "critical security gaps" in ctx

    def test_includes_nist_scores(self):
        ctx = build_report_context(SAMPLE_STATE)
        assert "NIST CSF" in ctx
        assert "1.25" in ctx  # overall score
        assert "Govern" in ctx
        assert "Protect" in ctx

    def test_includes_risk_findings(self):
        ctx = build_report_context(SAMPLE_STATE)
        assert "RISK-001" in ctx
        assert "Ransomware" in ctx
        assert "Critical" in ctx

    def test_includes_fair_results(self):
        ctx = build_report_context(SAMPLE_STATE)
        assert "FAIR" in ctx
        assert "1,200,000" in ctx

    def test_includes_roadmap(self):
        ctx = build_report_context(SAMPLE_STATE)
        assert "Roadmap" in ctx
        assert "Phase 1" in ctx
        assert "MFA" in ctx

    def test_includes_asset_inventory(self):
        ctx = build_report_context(SAMPLE_STATE)
        assert "Asset Inventory" in ctx
        assert "EHR Server" in ctx

    def test_includes_data_provenance(self):
        ctx = build_report_context(SAMPLE_STATE)
        assert "Data Provenance" in ctx
        assert "LLM Generated" in ctx
        assert "Fallback" in ctx

    def test_handles_empty_state(self):
        ctx = build_report_context({})
        assert isinstance(ctx, str)

    def test_handles_partial_state(self):
        ctx = build_report_context({"executive_summary": "Test summary only"})
        assert "Test summary only" in ctx


# ── Tests for get_chat_response ──────────────────────────────────────────────

class TestGetChatResponse:

    @patch("tools.report_chat.get_llm")
    def test_returns_string(self, mock_get_llm):
        mock_llm = MagicMock()
        mock_llm.invoke.return_value = MagicMock(content="The overall NIST score is 1.25/5.0.")
        mock_get_llm.return_value = mock_llm

        result = get_chat_response("What is the NIST score?", "report context here", [])
        assert isinstance(result, str)
        assert "1.25" in result

    @patch("tools.report_chat.get_llm")
    def test_passes_chat_history(self, mock_get_llm):
        mock_llm = MagicMock()
        mock_llm.invoke.return_value = MagicMock(content="Phase 1 costs $155,000.")
        mock_get_llm.return_value = mock_llm

        history = [
            {"role": "user", "content": "What is the NIST score?"},
            {"role": "assistant", "content": "The score is 1.25."},
        ]
        result = get_chat_response("What about the roadmap?", "context", history)
        assert isinstance(result, str)

        # Verify history was included in messages (system + 2 history + 1 current = 4)
        call_args = mock_llm.invoke.call_args[0][0]
        assert len(call_args) == 4

    @patch("tools.report_chat.get_llm")
    def test_handles_llm_error(self, mock_get_llm):
        mock_llm = MagicMock()
        mock_llm.invoke.side_effect = Exception("Rate limit exceeded")
        mock_get_llm.return_value = mock_llm

        result = get_chat_response("test question", "context", [])
        assert "Sorry" in result
        assert "Rate limit" in result
