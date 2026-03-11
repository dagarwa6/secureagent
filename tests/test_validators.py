"""
Tests for Output Validators
Validates that the validator correctly catches bad data and passes good data.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.validators import OutputValidator, ValidationResult


def _make_valid_state():
    """Create a minimal valid pipeline state for testing."""
    nist_scores = [
        {"function": "Govern", "function_id": "GV", "score": 1.0, "maturity_level": "Initial",
         "score_justification": "No CISO, no security strategy, no steering committee.",
         "key_gaps": ["No CISO"], "key_strengths": ["CCO exists"]},
        {"function": "Identify", "function_id": "ID", "score": 1.5, "maturity_level": "Initial",
         "score_justification": "Spreadsheet-based asset inventory, no risk assessment.",
         "key_gaps": ["No asset mgmt tool"], "key_strengths": ["Tenable acquired"]},
        {"function": "Protect", "function_id": "PR", "score": 2.0, "maturity_level": "Developing",
         "score_justification": "MFA at 35%, no EDR, no PAM.",
         "key_gaps": ["Low MFA coverage"], "key_strengths": ["Azure AD exists"]},
        {"function": "Detect", "function_id": "DE", "score": 1.0, "maturity_level": "Initial",
         "score_justification": "No SIEM, no EDR, no centralized logging.",
         "key_gaps": ["No SIEM"], "key_strengths": ["Firewall logs exist"]},
        {"function": "Respond", "function_id": "RS", "score": 1.5, "maturity_level": "Initial",
         "score_justification": "Outdated IRP from 2021, no playbooks.",
         "key_gaps": ["IRP outdated"], "key_strengths": ["IRP exists"]},
        {"function": "Recover", "function_id": "RC", "score": 1.0, "maturity_level": "Initial",
         "score_justification": "BCP untested since 2020, no RTO/RPO.",
         "key_gaps": ["BCP untested"], "key_strengths": ["Veeam deployed"]},
    ]
    findings = [
        {
            "id": f"RISK-{i:03d}",
            "asset": f"Asset {i}",
            "threat_scenario": f"Threat scenario description for finding {i}",
            "likelihood": 3,
            "impact": 4,
            "risk_score": 12,
            "control_gap": f"Gap {i}",
            "gap_type": "Systemic Structural Weakness" if i % 2 == 0 else "Isolated Control Failure",
            "nist_function": "Protect",
            "priority": "Medium",
        }
        for i in range(1, 17)
    ]
    fair_results = [
        {
            "risk_name": "Test Scenario",
            "tef_per_year": 0.3,
            "loss_magnitude_usd": 4_200_000,
            "control_effectiveness": 0.15,
            "ale_usd": 0.3 * 4_200_000 * (1 - 0.15),
            "ale_formatted": "$1,071,000",
            "risk_level": "Critical",
        },
        {
            "risk_name": "Test Scenario 2",
            "tef_per_year": 1.5,
            "loss_magnitude_usd": 800_000,
            "control_effectiveness": 0.40,
            "ale_usd": 1.5 * 800_000 * (1 - 0.40),
            "ale_formatted": "$720,000",
            "risk_level": "High",
        },
        {
            "risk_name": "Test Scenario 3",
            "tef_per_year": 0.2,
            "loss_magnitude_usd": 1_500_000,
            "control_effectiveness": 0.30,
            "ale_usd": 0.2 * 1_500_000 * (1 - 0.30),
            "ale_formatted": "$210,000",
            "risk_level": "Medium",
        },
    ]
    return {
        "asset_inventory": [{"name": f"Asset{i}", "type": "Server"} for i in range(20)],
        "policy_refs": [{"name": f"Policy{i}", "status": "Active"} for i in range(15)],
        "vendor_risks": [{"vendor_name": "LabConnect"}],
        "ingestion_summary": "MedBridge Health Systems is a mid-size healthcare organization with " * 5,
        "nist_scores": nist_scores,
        "overall_maturity_score": 1.33,
        "risk_findings": findings,
        "fair_results": fair_results,
    }


class TestValidationPasses:
    def test_valid_state_passes(self):
        """Well-formed state data should pass validation."""
        v = OutputValidator()
        result = v.validate_all(_make_valid_state())
        assert result.passed is True

    def test_valid_state_no_errors(self):
        v = OutputValidator()
        result = v.validate_all(_make_valid_state())
        assert len(result.errors) == 0


class TestValidationFailures:
    def test_risk_score_mismatch(self):
        """Validation should warn when risk_score != likelihood × impact."""
        state = _make_valid_state()
        state["risk_findings"][0]["risk_score"] = 99  # wrong
        v = OutputValidator()
        result = v.validate_all(state)
        assert any("risk_score" in w for w in result.warnings)

    def test_fewer_than_15_findings_fails(self):
        """Validation should fail when fewer than 15 findings exist."""
        state = _make_valid_state()
        state["risk_findings"] = state["risk_findings"][:10]
        v = OutputValidator()
        result = v.validate_all(state)
        assert result.passed is False
        assert any("15" in e or "minimum" in e.lower() for e in result.errors)

    def test_duplicate_finding_ids_fail(self):
        """Validation should fail on duplicate finding IDs."""
        state = _make_valid_state()
        state["risk_findings"][1]["id"] = state["risk_findings"][0]["id"]
        v = OutputValidator()
        result = v.validate_all(state)
        assert any("Duplicate" in e for e in result.errors)

    def test_incomplete_nist_fails(self):
        """Validation should fail when fewer than 6 NIST functions scored."""
        state = _make_valid_state()
        state["nist_scores"] = state["nist_scores"][:3]
        v = OutputValidator()
        result = v.validate_all(state)
        assert result.passed is False

    def test_score_out_of_range_fails(self):
        """Score outside 1.0-5.0 should fail."""
        state = _make_valid_state()
        state["nist_scores"][0]["score"] = 6.5
        v = OutputValidator()
        result = v.validate_all(state)
        assert result.passed is False

    def test_low_asset_count_warns(self):
        """Low asset count should produce a warning."""
        state = _make_valid_state()
        state["asset_inventory"] = [{"name": "Asset1"}]
        v = OutputValidator()
        result = v.validate_all(state)
        assert any("asset" in w.lower() for w in result.warnings)

    def test_short_summary_warns(self):
        """Very short summary should produce a warning."""
        state = _make_valid_state()
        state["ingestion_summary"] = "Short."
        v = OutputValidator()
        result = v.validate_all(state)
        assert any("summary" in w.lower() for w in result.warnings)

    def test_invalid_nist_function_warns(self):
        """Invalid NIST function in findings should warn."""
        state = _make_valid_state()
        state["risk_findings"][0]["nist_function"] = "InvalidFunc"
        v = OutputValidator()
        result = v.validate_all(state)
        assert any("NIST function" in w for w in result.warnings)


class TestValidationResult:
    def test_default_passed(self):
        result = ValidationResult()
        assert result.passed is True

    def test_fail_sets_passed_false(self):
        result = ValidationResult()
        result.fail("test error")
        assert result.passed is False
        assert "test error" in result.errors

    def test_warn_keeps_passed_true(self):
        result = ValidationResult()
        result.warn("test warning")
        assert result.passed is True
        assert "test warning" in result.warnings

    def test_summary_format(self):
        result = ValidationResult()
        result.fail("err1")
        result.warn("warn1")
        summary = result.summary()
        assert "FAILED" in summary
        assert "err1" in summary
        assert "warn1" in summary


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
