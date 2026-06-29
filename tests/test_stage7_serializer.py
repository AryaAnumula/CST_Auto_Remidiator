"""
Unit and integration tests for Stage 7 — Serializer.
Verifies round-trip accuracy, formatting preservation, idempotence, and semantic safety.
"""

from __future__ import annotations

from pathlib import Path
import pytest

from cst_auto_remediator.yaml_cst.parser import parse_yaml
from cst_auto_remediator.yaml_cst.builder import build_cst
from cst_auto_remediator.gha_semantic.builder import build_semantic_model
from cst_auto_remediator.gha_metadata.engine import MetadataWrapper
from cst_auto_remediator.gha_analysis.analyzer import analyze_workflow
from cst_auto_remediator.gha_analysis.nodes import AnalysisDecision
from cst_auto_remediator.gha_transform.planner import MutationPlanner
from cst_auto_remediator.gha_transform.transformer import CSTTransformer
from cst_auto_remediator.gha_transform.serializer import serialize_document

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
EDGE_CASES_DIR = Path(__file__).parent.parent / "edge_cases"
STAGE3_DIR = Path(__file__).parent.parent / "testing" / "stage3"


def _run_stage1_to_6(content: bytes):
    """Utility to run Stages 1-6 and return (original_ruamel, original_cst, mutated_cst, analysis, plan)."""
    doc, meta = parse_yaml(content)
    cst = build_cst(doc, meta)
    semantic = build_semantic_model(cst)
    if semantic.workflow is None:
        return doc, cst, cst, None, None
    wrapper = MetadataWrapper(semantic.workflow)
    analysis = analyze_workflow(semantic.workflow, wrapper)
    plan = MutationPlanner(wrapper).build_plan(analysis)
    result = CSTTransformer().transform(plan)
    return doc, cst, result.cst, analysis, plan


def test_round_trip_preservation() -> None:
    """Verify that serializing an unmodified CST yields identical bytes for various inputs."""
    inputs = [
        # Standard LF file
        b"name: test-lf\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\n",
        # CRLF line ending file
        b"name: test-crlf\r\non: push\r\njobs:\r\n  test:\r\n    runs-on: ubuntu-latest\r\n    steps:\r\n      - run: echo hello\r\n",
        # Comments & whitespace
        b"# Header comment\nname: test-comments\n\n# Job comment\njobs:\n  test:\n    runs-on: ubuntu-latest  # inline comment\n    steps:\n      - name: setup\n        # Step comment\n        run: echo hello\n",
        # Anchors, aliases, merge keys
        b"name: test-anchors\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - &anchor_step\n        name: step1\n        run: echo 1\n      - <<: *anchor_step\n",
        # Emojis/Unicode
        "name: test-unicode-🚀\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo '🔥 emoji'\n".encode("utf-8"),
    ]

    for content in inputs:
        doc, cst, _, _, _ = _run_stage1_to_6(content)
        output_bytes = serialize_document(cst, doc, cst, content.decode("utf-8"))
        assert output_bytes == content, f"Expected round-trip to yield identical bytes. Got: {output_bytes!r}"


def test_mutation_formatting_preservation() -> None:
    """Verify that mutations are correctly formatted and all untouched nodes retain original formatting."""
    content = (
        b"# Header comment\n"
        b"name: Vuln Workflow\n"
        b"on: push\n"
        b"jobs:\n"
        b"  test:\n"
        b"    runs-on: ubuntu-latest  # runner\n"
        b"    steps:\n"
        b"      - name: setup\n"
        b"        # untouched step comment\n"
        b"        run: echo 'hello'\n"
        b"      - name: vuln\n"
        b"        # vulnerable step comment\n"
        b"        run: 'echo \"title: ${{ github.event.issue.title }}\"'\n"
    )

    doc, orig_cst, mutated_cst, _, _ = _run_stage1_to_6(content)
    output_bytes = serialize_document(mutated_cst, doc, orig_cst, content.decode("utf-8"))

    # 1. Output must contain the env addition and replacement
    assert b"env:" in output_bytes
    assert b"ISSUE_TITLE" in output_bytes
    assert b"$ISSUE_TITLE" in output_bytes
    assert b"${{ github.event.issue.title }}" in output_bytes

    # 2. Header and untouched step comments/layout must be perfectly preserved
    assert b"# Header comment" in output_bytes
    assert b"# runner" in output_bytes
    assert b"# untouched step comment" in output_bytes
    assert b"# vulnerable step comment" in output_bytes


def test_idempotence_invariant() -> None:
    """Verify the idempotence invariant: serialize(parse(serialize(parse(x)))) == serialize(parse(x))"""
    vulnerable_files = [
        EDGE_CASES_DIR / "security" / "command_injection.yml",
        EDGE_CASES_DIR / "security" / "gobang.yml",
        FIXTURES_DIR / "clean_passthrough.yml",
    ]

    for path in vulnerable_files:
        content = path.read_bytes()
        orig_text = content.decode("utf-8")
        
        # Iteration 1
        doc_1, orig_cst_1, mutated_cst_1, _, _ = _run_stage1_to_6(content)
        output_bytes_1 = serialize_document(mutated_cst_1, doc_1, orig_cst_1, orig_text)
        
        # Iteration 2 (should find zero new mutations on already remediated file)
        doc_2, orig_cst_2, mutated_cst_2, _, _ = _run_stage1_to_6(output_bytes_1)
        output_bytes_2 = serialize_document(mutated_cst_2, doc_2, orig_cst_2, output_bytes_1.decode("utf-8"))
        
        assert output_bytes_1 == output_bytes_2, f"Idempotence check failed for {path.name}"


def test_semantic_safety_invariant() -> None:
    """Verify that Stage 5 reports no remaining REMEDIATE decisions on the locations transformed by Stage 6."""
    from cst_auto_remediator.gha_metadata.providers import PositionProvider
    path = EDGE_CASES_DIR / "security" / "command_injection.yml"
    content = path.read_bytes()
    orig_text = content.decode("utf-8")

    # 1. Remediate and serialize
    doc, orig_cst, mutated_cst, analysis, plan = _run_stage1_to_6(content)
    # Ensure there was a remediate step
    remediated_steps = {(m.job_id, m.step_index) for m in plan.step_mutations}
    assert len(remediated_steps) > 0

    output_bytes = serialize_document(mutated_cst, doc, orig_cst, orig_text)

    # 2. Re-parse and analyze output
    doc_out, cst_out = parse_yaml(output_bytes)
    cst_built_out = build_cst(doc_out, cst_out)
    semantic_out = build_semantic_model(cst_built_out)
    assert semantic_out.workflow is not None
    
    wrapper_out = MetadataWrapper(semantic_out.workflow)
    analysis_out = analyze_workflow(semantic_out.workflow, wrapper_out)

    # 3. Assert that transformed locations have no REMEDIATE decisions
    for classif in analysis_out.expression_classifications.values():
        expr = classif.expression_site
        pos = wrapper_out.get(PositionProvider, expr)
        if pos is not None and pos.job_id is not None:
            step_key = (pos.job_id, pos.step_index)
            if step_key in remediated_steps:
                assert classif.decision != AnalysisDecision.REMEDIATE, (
                    f"Expected transformed step {step_key} to contain no REMEDIATE decisions, "
                    f"but found {expr.expression_text} marked as {classif.decision}"
                )
