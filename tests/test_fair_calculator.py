"""
Tests for FAIR-lite Risk Calculator
Validates point-estimate ALE, Monte Carlo simulation, and edge cases.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.fair_calculator import (
    calculate_ale,
    classify_risk,
    monte_carlo_fair,
    run_fair_analysis,
    get_medbridge_fair_results,
    fair_results_to_dict,
    FAIRInput,
)


# ── Point Estimate Tests ─────────────────────────────────────────────────────

class TestCalculateALE:
    def test_basic_formula(self):
        """ALE = TEF × LM × (1 - CE) for known inputs."""
        ale = calculate_ale(0.30, 4_200_000, 0.15)
        expected = 0.30 * 4_200_000 * (1 - 0.15)
        assert abs(ale - expected) < 1.0

    def test_no_controls(self):
        """CE = 0 → full exposure: ALE = TEF × LM."""
        ale = calculate_ale(1.0, 1_000_000, 0.0)
        assert ale == 1_000_000.0

    def test_perfect_controls(self):
        """CE = 1.0 → zero loss: ALE = 0."""
        ale = calculate_ale(2.0, 5_000_000, 1.0)
        assert ale == 0.0

    def test_no_threat(self):
        """TEF = 0 → no loss regardless of other inputs."""
        ale = calculate_ale(0.0, 10_000_000, 0.5)
        assert ale == 0.0

    def test_ce_clamping_above_one(self):
        """CE > 1.0 should be clamped to 1.0."""
        ale = calculate_ale(1.0, 1_000_000, 1.5)
        assert ale == 0.0

    def test_ce_clamping_below_zero(self):
        """CE < 0.0 should be clamped to 0.0."""
        ale = calculate_ale(1.0, 1_000_000, -0.5)
        assert ale == 1_000_000.0


class TestClassifyRisk:
    def test_critical(self):
        assert classify_risk(1_500_000) == "Critical"

    def test_high(self):
        assert classify_risk(750_000) == "High"

    def test_medium(self):
        assert classify_risk(250_000) == "Medium"

    def test_low(self):
        assert classify_risk(50_000) == "Low"

    def test_boundary_critical(self):
        assert classify_risk(1_000_000) == "Critical"

    def test_boundary_high(self):
        assert classify_risk(500_000) == "High"

    def test_boundary_medium(self):
        assert classify_risk(100_000) == "Medium"


# ── Monte Carlo Tests ─────────────────────────────────────────────────────────

class TestMonteCarlo:
    def test_output_keys(self):
        """Monte Carlo output includes median, p10, p90, mean."""
        result = monte_carlo_fair(
            tef_range=(0.1, 0.3, 0.6),
            lm_range=(1_000_000, 4_000_000, 8_000_000),
            ce_range=(0.05, 0.15, 0.30),
        )
        assert "median" in result
        assert "p10" in result
        assert "p90" in result
        assert "mean" in result

    def test_p10_less_than_median_less_than_p90(self):
        """For non-degenerate inputs: p10 < median < p90."""
        result = monte_carlo_fair(
            tef_range=(0.1, 0.5, 1.0),
            lm_range=(500_000, 2_000_000, 5_000_000),
            ce_range=(0.1, 0.3, 0.5),
        )
        assert result["p10"] < result["median"]
        assert result["median"] < result["p90"]

    def test_all_values_positive(self):
        """All Monte Carlo ALE values should be non-negative."""
        result = monte_carlo_fair(
            tef_range=(0.01, 0.1, 0.3),
            lm_range=(100_000, 500_000, 1_000_000),
            ce_range=(0.0, 0.2, 0.5),
        )
        assert result["p10"] >= 0
        assert result["median"] >= 0
        assert result["p90"] >= 0
        assert result["mean"] >= 0

    def test_narrow_range_low_variance(self):
        """When ranges are very narrow, variance should be near zero."""
        result = monte_carlo_fair(
            tef_range=(0.49, 0.50, 0.51),
            lm_range=(999_000, 1_000_000, 1_001_000),
            ce_range=(0.19, 0.20, 0.21),
        )
        expected = 0.50 * 1_000_000 * (1 - 0.20)
        assert abs(result["median"] - expected) < 10_000
        assert abs(result["p10"] - result["p90"]) < 20_000


# ── Integration Tests ─────────────────────────────────────────────────────────

class TestRunFairAnalysis:
    def test_sorted_by_ale_descending(self):
        """Results should be sorted by ALE descending."""
        inputs = [
            FAIRInput("Low Risk", "Asset A", "Actor", 0.1, 100_000, 0.5),
            FAIRInput("High Risk", "Asset B", "Actor", 1.0, 5_000_000, 0.1),
        ]
        results = run_fair_analysis(inputs)
        assert results[0].risk_name == "High Risk"
        assert results[1].risk_name == "Low Risk"

    def test_monte_carlo_populated_when_ranges_given(self):
        """When ranges are provided, Monte Carlo fields should be populated."""
        inputs = [
            FAIRInput(
                "Test", "Asset", "Actor", 0.3, 1_000_000, 0.2,
                tef_range=(0.1, 0.3, 0.5),
                lm_range=(500_000, 1_000_000, 2_000_000),
                ce_range=(0.1, 0.2, 0.4),
            ),
        ]
        results = run_fair_analysis(inputs)
        assert results[0].ale_median is not None
        assert results[0].ale_p10 is not None
        assert results[0].ale_p90 is not None

    def test_monte_carlo_none_when_no_ranges(self):
        """When no ranges provided, Monte Carlo fields should be None."""
        inputs = [FAIRInput("Test", "Asset", "Actor", 0.3, 1_000_000, 0.2)]
        results = run_fair_analysis(inputs)
        assert results[0].ale_median is None
        assert results[0].ale_p10 is None


class TestMedbridgeScenarios:
    def test_five_scenarios_returned(self):
        results = get_medbridge_fair_results()
        assert len(results) == 5

    def test_all_have_monte_carlo(self):
        """All MedBridge scenarios should have Monte Carlo data."""
        results = get_medbridge_fair_results()
        for r in results:
            assert r.ale_median is not None, f"{r.risk_name} missing MC median"
            assert r.ale_p10 is not None, f"{r.risk_name} missing MC p10"
            assert r.ale_p90 is not None, f"{r.risk_name} missing MC p90"

    def test_dict_serialization_includes_mc(self):
        """Serialized dict should include Monte Carlo fields."""
        results = get_medbridge_fair_results()
        dicts = fair_results_to_dict(results)
        for d in dicts:
            assert "ale_median" in d
            assert "ale_p10" in d
            assert "ale_p90" in d


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
