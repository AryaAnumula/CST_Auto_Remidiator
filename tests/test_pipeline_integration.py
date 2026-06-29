"""
Compiler Pipeline End-to-End Integration Test.

Takes a real GHA workflow fixture, runs all four compiler phases:
1. Parser (Stage 1)
2. Green CST (Stage 2)
3. Semantic Builder (Stage 3)
4. Metadata Engine (Stage 4)

And verifies diagnostic correctness and complete metadata coverage.
"""

from pathlib import Path
from cst_auto_remediator.yaml_cst.parser import parse_yaml
from cst_auto_remediator.yaml_cst.builder import build_cst
from cst_auto_remediator.gha_semantic.builder import build_semantic_model
from cst_auto_remediator.gha_metadata.engine import MetadataWrapper
from cst_auto_remediator.gha_metadata.providers import (
    PositionProvider,
    ScopeProvider,
    ShellProvider,
    ExpressionProvider,
)


def test_end_to_end_pipeline_integration() -> None:
    # 1. Read real GHA workflow fixture
    fixture_path = Path(__file__).parent.parent / "fixtures" / "clean_passthrough2.yml"
    content = fixture_path.read_bytes()

    # 2. Run Parser -> Green CST -> Semantic Builder -> Metadata Engine
    doc, meta = parse_yaml(content)
    cst = build_cst(doc, meta)
    res = build_semantic_model(cst)

    # Verifications
    # A. No diagnostics (for valid workflow)
    assert len(res.diagnostics) == 0, f"Expected no diagnostics, but got: {res.diagnostics}"
    assert res.workflow is not None

    # B. Metadata exists
    wrapper = MetadataWrapper(res.workflow)

    # Traverse step and expression sites
    steps_checked = 0
    exprs_checked = 0

    for job in res.workflow.jobs.values():
        for step in job.steps:
            steps_checked += 1

            # Every Step has PositionMetadata
            step_pos = wrapper.get(PositionProvider, step)
            assert step_pos is not None
            assert step_pos.node_path.startswith("jobs.")
            assert step_pos.path_segments[0] == "jobs"

            # Every Step has ScopeMetadata
            step_scope = wrapper.get(ScopeProvider, step)
            assert step_scope is not None
            assert step_scope.scope_type == "step"

            # Every Step has ShellMetadata
            step_shell = wrapper.get(ShellProvider, step)
            assert step_shell is not None
            assert step_shell.effective_shell == "bash"

            # Traverse and check step expressions
            expr_sites = []
            if step.run_command is not None:
                expr_sites.extend(step.run_command.expression_sites)
            for binding in step.env_bindings:
                expr_sites.extend(binding.expression_sites)

            for expr in expr_sites:
                exprs_checked += 1

                # Every ExpressionSite has metadata
                bundle = wrapper.get_bundle(expr)
                assert bundle.position is not None
                assert bundle.scope is not None
                assert bundle.shell is not None
                assert bundle.expression is not None

                # Every ExpressionSite has ExpressionMetadata
                expr_meta = wrapper.get(ExpressionProvider, expr)
                assert expr_meta is not None
                assert expr_meta.stable_id.startswith("jobs.")
                assert expr_meta.expression_order >= 0

    # Ensure we actually checked steps and expressions in the fixture
    assert steps_checked == 3
    assert exprs_checked == 1
