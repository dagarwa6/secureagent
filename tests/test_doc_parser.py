"""
Tests for doc_parser path validation and security.
"""

import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.doc_parser import validate_corpus_path


class TestValidateCorpusPath:
    def test_accepts_corpus_directory(self):
        """Should accept paths within the project root."""
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        corpus_path = os.path.join(project_root, "corpus")
        result = validate_corpus_path(corpus_path)
        assert result == os.path.realpath(corpus_path)

    def test_accepts_temp_directory(self):
        """Should accept paths within system temp directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = validate_corpus_path(tmpdir)
            assert result == os.path.realpath(tmpdir)

    def test_rejects_path_traversal(self):
        """Should reject paths with .. that escape the project root."""
        with pytest.raises(ValueError, match="Path traversal blocked"):
            validate_corpus_path("../../../etc/passwd")

    def test_rejects_absolute_system_path(self):
        """Should reject absolute paths outside project root and temp."""
        with pytest.raises(ValueError, match="Path traversal blocked"):
            validate_corpus_path("/etc/shadow")

    def test_rejects_home_directory(self):
        """Should reject paths to user home directory."""
        home = os.path.expanduser("~")
        with pytest.raises(ValueError, match="Path traversal blocked"):
            validate_corpus_path(home)

    def test_resolves_relative_paths(self):
        """Should resolve relative paths before validation."""
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        # This relative path should resolve to within project root
        corpus_path = os.path.join(project_root, "corpus", "..", "corpus")
        result = validate_corpus_path(corpus_path)
        assert os.path.realpath(os.path.join(project_root, "corpus")) == result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
