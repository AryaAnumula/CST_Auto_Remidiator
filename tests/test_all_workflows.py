"""
Automated validation of all workflows and datasets in the repository.
Tests 10 stage3 workflows, and all 16 edge case datasets.
"""

from __future__ import annotations

import glob
from pathlib import Path
import pytest

from cst_auto_remediator import remediate_file
from cst_auto_remediator.ingest import ingest
from cst_auto_remediator.models import IngestSuccess
from cst_auto_remediator.traverse import traverse_jobs
from cst_auto_remediator.yaml_cst.parser import parse_yaml
from cst_auto_remediator.yaml_cst.builder import build_cst
from cst_auto_remediator.gha_semantic.builder import build_semantic_model
from cst_auto_remediator.gha_metadata.engine import MetadataWrapper
from cst_auto_remediator.gha_analysis.analyzer import analyze_workflow

ROOT = Path(__file__).resolve().parent.parent
STAGE3_DIR = ROOT / "testing" / "stage3"
EDGE_CASES_DIR = ROOT / "edge_cases"


def test_stage3_workflows() -> None:
    """Verify that all 10 Stage 3 workflows are successfully parsed, remediated, and verified."""
    yaml_files = sorted(STAGE3_DIR.glob("*.yml"))
    assert len(yaml_files) == 10, f"Expected 10 stage3 workflows, found {len(yaml_files)}"

    for path in yaml_files:
        # 1. Run remediation
        yaml_out, report = remediate_file(path)
        assert yaml_out is not None, f"Remediation returned None output for {path.name}"
        assert len(report) == 1, f"Expected exactly 1 report entry for {path.name}"
        
        entry = report[0]
        assert entry["action"] == "PATCHED", f"Expected action PATCHED for {path.name}, got {entry['action']}"
        assert entry["env_var_added"] is not None, f"Expected env_var_added to be populated for {path.name}"
        assert entry["expression_text"] is not None, f"Expected expression_text to be populated for {path.name}"

        # 2. Verify offset slicing correctness on original input
        ingest_res = ingest(path)
        assert isinstance(ingest_res, IngestSuccess)
        sites = traverse_jobs(ingest_res.document)
        assert len(sites) == 1
        site = sites[0]
        
        # Verify slice matches expression text
        start, end = entry["start_offset"], entry["end_offset"]
        assert start is not None and end is not None
        assert site.run_value[start:end] == entry["expression_text"]

        # 3. Verify the output is valid YAML and passes semantic verify post-check
        from cst_auto_remediator.pipeline import semantic_verify
        patched_steps = {(entry["job_id"], entry["step"])}
        assert semantic_verify(yaml_out, patched_steps), f"Semantic verification failed for {path.name}"


def test_edge_cases_empty() -> None:
    """Verify empty.yml fails at ingest stage with PARSE_ERROR as expected."""
    path = EDGE_CASES_DIR / "yaml_boundaries" / "empty.yml"
    yaml_out, report = remediate_file(path)
    assert yaml_out is None
    assert len(report) == 1
    assert report[0]["action"] == "BAILED"
    assert report[0]["reason"] == "PARSE_ERROR"


def test_edge_cases_general() -> None:
    """Verify security classifications and decisions for all non-empty edge cases."""
    yaml_files = sorted(list(EDGE_CASES_DIR.glob("**/*.yml")))
    # Remove empty.yml from the general list
    yaml_files = [f for f in yaml_files if f.name != "empty.yml"]
    assert len(yaml_files) == 16, f"Expected 16 non-empty edge case files, found {len(yaml_files)}"

    for path in yaml_files:
        # Ensure it parses, semantic models, and analyzes correctly without exception
        doc, meta = parse_yaml(path.read_bytes())
        cst = build_cst(doc, meta)
        res = build_semantic_model(cst)
        wrapper = MetadataWrapper(res.workflow)
        analysis = analyze_workflow(res.workflow, wrapper)

        # Check file-specific expected decisions and diagnostics
        if path.name == "command_injection.yml":
            decisions = [c.decision.name for c in analysis.expression_classifications.values()]
            diags = [d.code for d in analysis.diagnostics]
            assert "REMEDIATE" in decisions
            assert "ANA004" in diags

        elif path.name == "unsupported_shells.yml":
            decisions = [c.decision.name for c in analysis.expression_classifications.values()]
            diags = [d.code for d in analysis.diagnostics]
            assert "BAILOUT" in decisions
            assert "ANA002" in diags

        elif path.name == "block_scalars.yml":
            decisions = [c.decision.name for c in analysis.expression_classifications.values()]
            diags = [d.code for d in analysis.diagnostics]
            assert "BAILOUT" in decisions
            assert "ANA003" in diags

        elif path.name == "quoted_block.yml":
            decisions = [c.decision.name for c in analysis.expression_classifications.values()]
            assert "SKIP" in decisions

        elif path.name == "already_remediated.yml":
            decisions = [c.decision.name for c in analysis.expression_classifications.values()]
            assert "SKIP" in decisions

        elif path.name == "escaped_malformed.yml":
            decisions = [c.decision.name for c in analysis.expression_classifications.values()]
            assert "SAFE" in decisions

        # For all extracted expression sites in the analyzed workflows, verify that character offsets are correct
        for classif in analysis.expression_classifications.values():
            site = classif.expression_site
            start, end = site.start_offset, site.end_offset
            assert site.node.value[start:end] == site.expression_text
