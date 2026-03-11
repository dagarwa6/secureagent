"""
Tests for AgentState schema
Validates that AgentState can be instantiated and has correct fields.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.state import AgentState


class TestAgentState:
    def test_minimal_instantiation(self):
        """AgentState can be instantiated with minimal required fields."""
        state: AgentState = {
            "docs_path": "/tmp/test",
            "current_step": "starting",
            "errors": [],
            "progress_messages": [],
        }
        assert state["docs_path"] == "/tmp/test"
        assert state["current_step"] == "starting"

    def test_fallback_flags_field_exists(self):
        """fallback_flags field should be supported in AgentState."""
        state: AgentState = {
            "docs_path": "/tmp/test",
            "current_step": "starting",
            "errors": [],
            "progress_messages": [],
            "fallback_flags": {},
        }
        assert state["fallback_flags"] == {}

    def test_fallback_flags_tracks_agents(self):
        """fallback_flags should support tracking per-agent data source."""
        state: AgentState = {
            "docs_path": "/tmp/test",
            "current_step": "assessment",
            "errors": [],
            "progress_messages": [],
            "fallback_flags": {
                "ingestion": "llm_generated",
                "threat_modeling": "fallback_static",
                "assessment": "llm_generated",
            },
        }
        assert state["fallback_flags"]["ingestion"] == "llm_generated"
        assert state["fallback_flags"]["threat_modeling"] == "fallback_static"

    def test_all_optional_fields_none(self):
        """All optional fields should accept None."""
        state: AgentState = {
            "docs_path": "/tmp/test",
            "current_step": "starting",
            "errors": [],
            "progress_messages": [],
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
            "approved": None,
            "fallback_flags": None,
        }
        assert state["asset_inventory"] is None
        assert state["fallback_flags"] is None

    def test_errors_is_list(self):
        state: AgentState = {
            "docs_path": "/tmp/test",
            "current_step": "starting",
            "errors": ["Error 1", "Error 2"],
            "progress_messages": [],
        }
        assert len(state["errors"]) == 2
        state["errors"].append("Error 3")
        assert len(state["errors"]) == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
