"""
Tests for agent fallback behavior and output structure.
Validates that agents gracefully handle LLM failures and produce valid output.
"""

import os
import sys
import pytest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))



def _make_initial_state(**overrides) -> dict:
    """Create a minimal AgentState dict for testing."""
    state = {
        "docs_path": "/tmp/test_corpus",
        "include_report": False,
        "approved": True,
        "errors": [],
        "progress_messages": [],
        "fallback_flags": {},
        "asset_inventory": [],
        "policy_refs": [],
        "tech_refs": [],
        "vendor_risks": [],
        "ingestion_summary": "Test organization — healthcare org, hybrid cloud",
        "stride_threats": [],
        "mitre_techniques": [],
        "kill_chain": [],
        "top_threat_actors": [],
        "nist_scores": [],
        "overall_maturity_score": 0,
        "industry_benchmark": 2.1,
        "cis_controls_mapped": [],
        "risk_findings": [],
        "top_10_gaps": [],
        "fair_results": [],
        "systemic_count": 0,
        "isolated_count": 0,
        "architecture_recommendations": "",
        "governance_output": {},
        "roadmap": [],
        "change_management": {},
        "executive_summary": "",
        "report_path": "",
        "current_step": "start",
    }
    state.update(overrides)
    return state


class TestAssessmentAgentFallback:
    def test_fallback_scores_valid_range(self):
        """All fallback scores must be between 1.0 and 5.0."""
        from agents.assessment_agent import _get_fallback_scores
        scores = _get_fallback_scores()
        assert len(scores) == 6, "Must have exactly 6 NIST function scores"
        for s in scores:
            assert 1.0 <= s["score"] <= 5.0, f"{s['function']} score {s['score']} out of range"
            assert s["maturity_level"] in ("Initial", "Developing", "Defined", "Managed", "Optimizing")
            assert len(s["score_justification"]) > 50, f"{s['function']} justification too short"
            assert len(s["key_gaps"]) >= 2, f"{s['function']} needs at least 2 gaps"

    def test_protect_score_conservative(self):
        """Protect fallback score must be <= 1.5 given no EDR, low MFA."""
        from agents.assessment_agent import _get_fallback_scores
        scores = _get_fallback_scores()
        protect = next(s for s in scores if s["function_id"] == "PR")
        assert protect["score"] <= 1.5, f"Protect score {protect['score']} is not conservative enough"

    def test_detect_score_minimal(self):
        """Detect fallback score must be 1.0 given no SIEM, no EDR."""
        from agents.assessment_agent import _get_fallback_scores
        scores = _get_fallback_scores()
        detect = next(s for s in scores if s["function_id"] == "DE")
        assert detect["score"] == 1.0

    def test_fallback_triggered_on_llm_error(self):
        """Assessment agent should set fallback_static flag when LLM fails."""
        from agents.assessment_agent import run_assessment_node
        state = _make_initial_state()
        with patch("agents.assessment_agent.get_llm", side_effect=Exception("LLM unavailable")):
            result = run_assessment_node(state)
        assert result["fallback_flags"]["assessment"] == "fallback_static"
        assert len(result["nist_scores"]) == 6


class TestGapAgentFallback:
    def test_fallback_produces_minimum_findings(self):
        """Gap agent fallback must produce at least 15 risk findings."""
        from agents.gap_agent import _get_fallback_findings
        findings = _get_fallback_findings()
        assert len(findings) >= 15, f"Only {len(findings)} fallback findings, need >= 15"

    def test_fallback_risk_scores_valid(self):
        """All fallback risk scores must be likelihood * impact."""
        from agents.gap_agent import _get_fallback_findings
        findings = _get_fallback_findings()
        for f in findings:
            expected = f["likelihood"] * f["impact"]
            assert f["risk_score"] == expected, (
                f"{f['id']}: risk_score {f['risk_score']} != {f['likelihood']} * {f['impact']}"
            )

    def test_fallback_has_required_fields(self):
        """Each fallback finding must have all required fields."""
        from agents.gap_agent import _get_fallback_findings
        required = {"id", "asset", "threat_scenario", "likelihood", "impact",
                    "risk_score", "control_gap", "gap_type", "priority", "nist_function"}
        findings = _get_fallback_findings()
        for f in findings:
            missing = required - set(f.keys())
            assert not missing, f"{f.get('id', '?')}: missing fields {missing}"


class TestThreatAgentFallback:
    def test_kill_chain_has_stages(self):
        """Pre-defined kill chain must have 7+ stages."""
        from agents.threat_agent import MEDBRIDGE_KILL_CHAIN
        assert len(MEDBRIDGE_KILL_CHAIN) >= 7

    def test_kill_chain_has_mitre_ids(self):
        """Each kill chain stage must reference MITRE technique IDs."""
        from agents.threat_agent import MEDBRIDGE_KILL_CHAIN
        for stage in MEDBRIDGE_KILL_CHAIN:
            assert "mapped_techniques" in stage
            assert len(stage["mapped_techniques"]) > 0, f"Stage '{stage['stage']}' has no techniques"


class TestScoreValidation:
    def test_validate_score_conservatism_flags_inflated(self):
        """Validation should warn when Detect scores > 2.0 with no SIEM."""
        from agents.assessment_agent import _validate_score_conservatism
        import logging
        score_data = {"function_id": "DE", "score": 3.0}
        org_context = "No SIEM deployed. No EDR."
        with patch.object(logging.getLogger("agents.assessment_agent"), "warning") as mock_warn:
            _validate_score_conservatism(score_data, org_context)
            mock_warn.assert_called_once()

    def test_validate_score_conservatism_passes_valid(self):
        """Validation should not warn when Detect scores <= 2.0 with no SIEM."""
        from agents.assessment_agent import _validate_score_conservatism
        import logging
        score_data = {"function_id": "DE", "score": 1.5}
        org_context = "No SIEM deployed."
        with patch.object(logging.getLogger("agents.assessment_agent"), "warning") as mock_warn:
            _validate_score_conservatism(score_data, org_context)
            mock_warn.assert_not_called()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
