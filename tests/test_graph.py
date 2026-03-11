"""
Tests for LangGraph Pipeline
Validates pipeline construction and edge-case handling.
"""

import pytest
import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.graph import build_graph


class TestBuildGraph:
    def test_graph_compiles_with_report(self):
        """Graph should compile successfully with report generation."""
        app = build_graph(include_report=True)
        assert app is not None

    def test_graph_compiles_without_report(self):
        """Graph should compile successfully without report generation."""
        app = build_graph(include_report=False)
        assert app is not None

    def test_graph_has_nodes(self):
        """Compiled graph should have all expected nodes."""
        app = build_graph(include_report=True)
        # LangGraph compiled graphs have get_graph() method
        graph = app.get_graph()
        # graph.nodes is a dict keyed by node name
        node_ids = list(graph.nodes.keys())
        assert "ingestion" in node_ids
        assert "threat_modeling" in node_ids
        assert "assessment" in node_ids
        assert "gap_analysis" in node_ids
        assert "human_review" in node_ids
        assert "report_generation" in node_ids


_has_api_key = bool(os.environ.get("GEMINI_API_KEY") or os.environ.get("GROQ_API_KEY"))


@pytest.mark.skipif(not _has_api_key, reason="No LLM API key — skipping integration tests")
class TestPipelineEdgeCases:
    def test_empty_corpus_directory(self):
        """Pipeline should handle an empty corpus directory gracefully (errors but no crash)."""
        from agents.graph import run_pipeline
        with tempfile.TemporaryDirectory() as tmpdir:
            # Run pipeline with empty dir — should not raise, but will have errors
            result = run_pipeline(
                docs_path=tmpdir,
                include_report=False,
                approved=True,
            )
            assert isinstance(result, dict)
            assert "errors" in result
            # Pipeline should still complete (agents catch their own errors)
            assert result.get("current_step") is not None

    def test_malformed_documents(self):
        """Pipeline should handle malformed documents gracefully."""
        from agents.graph import run_pipeline
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a malformed file
            with open(os.path.join(tmpdir, "bad_file.md"), "w") as f:
                f.write("")  # empty file
            result = run_pipeline(
                docs_path=tmpdir,
                include_report=False,
                approved=True,
            )
            assert isinstance(result, dict)
            # Should still produce some output (fallback data)
            assert result.get("current_step") is not None

    def test_initial_state_has_fallback_flags(self):
        """Initial state should include fallback_flags."""
        from agents.graph import run_pipeline
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "test.md"), "w") as f:
                f.write("# Test\nSome content for testing.")
            result = run_pipeline(
                docs_path=tmpdir,
                include_report=False,
                approved=True,
            )
            assert "fallback_flags" in result
            assert isinstance(result["fallback_flags"], dict)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
