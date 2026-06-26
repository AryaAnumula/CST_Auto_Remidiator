import os
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch

from cst_auto_remediator.pipeline import remediate_file, semantic_verify
from cst_auto_remediator.models import Action

def test_semantic_verify() -> None:
    # 1. Clean workflow, semantic verify passes
    clean_yaml = """
name: Clean GHA
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: run safe echo
        run: echo "hello world"
"""
    assert semantic_verify(clean_yaml, set()) is True

    # 2. Workflow with untrusted in non-patched step, semantic verify passes
    mixed_yaml = """
name: Mixed GHA
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: run untrusted in non-patched step
        run: echo "${{ github.event.issue.title }}"
"""
    # Non-patched, so step index 0 is not in patched_steps
    assert semantic_verify(mixed_yaml, set()) is True

    # 3. Workflow with untrusted in patched step, semantic verify fails
    assert semantic_verify(mixed_yaml, {("build", 0)}) is False


def test_atomic_write_success() -> None:
    # Test successful atomic update
    original_content = """
name: Test GHA
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: run step
        run: echo "${{ github.event.issue.title }}"
"""
    with tempfile.TemporaryDirectory() as tmp_dir:
        file_path = Path(tmp_dir) / "workflow.yml"
        # Write with newline="" to prevent default OS-based conversion
        with open(file_path, "w", encoding="utf-8", newline="") as f:
            f.write(original_content)
        
        # Run remediate with write_back=True
        output, report = remediate_file(file_path, write_back=True)
        
        # The file on disk should be updated and match output bytes
        disk_content = file_path.read_bytes().decode("utf-8")
        assert disk_content == output
        assert "env:" in disk_content
        assert "$ISSUE_TITLE" in disk_content
        assert report[0]["action"] == "PATCHED"


def test_atomic_write_rollback_on_failure() -> None:
    # Test rollback if os.replace fails
    original_content = """
name: Test GHA
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: run step
        run: echo "${{ github.event.issue.title }}"
"""
    with tempfile.TemporaryDirectory() as tmp_dir:
        file_path = Path(tmp_dir) / "workflow.yml"
        with open(file_path, "w", encoding="utf-8", newline="") as f:
            f.write(original_content)
        
        def mock_replace(src, dst):
            raise IOError("Simulated disk/permission failure during atomic swap")
            
        with patch("os.replace", side_effect=mock_replace):
            with pytest.raises(IOError, match="Simulated disk/permission failure"):
                remediate_file(file_path, write_back=True)
                
        # File content on disk MUST remain unchanged (rollback/untouched)
        disk_content = file_path.read_bytes().decode("utf-8")
        assert disk_content == original_content
