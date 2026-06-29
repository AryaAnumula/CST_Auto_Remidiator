"""
Stage 6 Integration Tests — Full Stage 1→6 pipeline on real fixture files.

These tests complement the unit-level tests in test_stage6_comprehensive.py.
They drive real on-disk YAML fixtures through the complete compiler pipeline:

  Stage 1: parse_yaml  (yaml_cst/parser.py)
  Stage 2: build_cst   (yaml_cst/builder.py)
  Stage 3: build_semantic_model (gha_semantic/builder.py)
  Stage 4: MetadataWrapper     (gha_metadata/engine.py)
  Stage 5: analyze_workflow    (gha_analysis/analyzer.py)
  Stage 6: MutationPlanner + CSTTransformer (gha_transform/)

After Stage 6, the semantic model is rebuilt in the test itself to verify
correctness — this is intentional: Stage 6 now returns workflow=None, and
the semantic rebuild is the caller's responsibility.
"""

from __future__ import annotations

from pathlib import Path

from cst_auto_remediator.gha_analysis.analyzer import analyze_workflow
from cst_auto_remediator.gha_analysis.nodes import AnalysisDecision
from cst_auto_remediator.gha_metadata.engine import MetadataWrapper
from cst_auto_remediator.gha_semantic.builder import build_semantic_model
from cst_auto_remediator.gha_transform.planner import MutationPlanner
from cst_auto_remediator.gha_transform.transformer import CSTTransformer
from cst_auto_remediator.yaml_cst.builder import build_cst
from cst_auto_remediator.yaml_cst.parser import parse_yaml

FIXTURES = Path(__file__).parent.parent / "fixtures"
TESTING_INPUTS = Path(__file__).parent.parent / "testing" / "inputs"


def _run_pipeline(content: bytes):
    """Drive content through the full Stage 1→6 pipeline. Returns (cst_in, result)."""
    doc, meta = parse_yaml(content)
    cst = build_cst(doc, meta)
    semantic = build_semantic_model(cst)
    assert semantic.workflow is not None, "fixture must be a valid workflow"
    wrapper = MetadataWrapper(semantic.workflow)
    analysis = analyze_workflow(semantic.workflow, wrapper)
    plan = MutationPlanner(wrapper).build_plan(analysis)
    result = CSTTransformer().transform(plan)
    return cst, result


def test_stage6_integration_clean_passthrough_fixture() -> None:
    """
    fixtures/clean_passthrough.yml has one REMEDIATE step.
    Verify: pipeline runs end-to-end, exactly one mutation applied,
    output CST is a new object, no YAML serialization occurred.
    """
    content = (FIXTURES / "clean_passthrough.yml").read_bytes()
    cst_in, result = _run_pipeline(content)

    # Stage 6 contract: workflow is None, cst is non-None and is a new object.
    assert result.workflow is None, "Stage 6 must not rebuild the semantic model"
    assert result.cst is not None
    assert result.cst is not cst_in, "output CST must be a new object, not the input"

    # Exactly one step mutation was applied (the single REMEDIATE expression).
    assert len(result.applied_step_mutations) == 1
    mutation = result.applied_step_mutations[0]
    assert mutation.job_id == "test"
    assert mutation.step_index == 0
    assert len(mutation.env_entries) == 1
    assert mutation.env_entries[0].name == "ISSUE_TITLE"

    # Verify the output CST content by rebuilding the semantic model.
    rebuilt = build_semantic_model(result.cst)
    assert rebuilt.workflow is not None
    step = rebuilt.workflow.jobs["test"].steps[0]
    assert step.run_command is not None
    assert "${{" not in step.run_command.command.value, (
        "expression must have been replaced — raw ${{ }} must not remain in run:"
    )
    assert "$ISSUE_TITLE" in step.run_command.command.value
    assert any(b.key.value == "ISSUE_TITLE" for b in step.env_bindings)

    # No YAML serialization side effect: result has no 'yaml_out' or similar attribute,
    # and the original fixture bytes are not written or modified (this is structural —
    # Stage 8 does not exist yet, so any serialization would be a bug).
    assert not hasattr(result, "yaml_out")
    assert not hasattr(result, "serialized")


def test_stage6_integration_mixed_fixture_only_remediate_sites_transformed() -> None:
    """
    testing/inputs/multi_step_mixed.yml contains:
      step 0 — already-remediated  → SKIP  (env: binds the expression)
      step 1 — vulnerable body     → REMEDIATE
      step 2 — block scalar        → BAILOUT (block scalar out of scope)
      step 3 — eval expression     → REMEDIATE (Stage 5 does not detect eval sink;
                                                 that is a legacy-pipeline concern only)

    Stage 5 (the new compiler analyzer) does not replicate the legacy validate.py
    eval-sink rule — it classifies the eval step as REMEDIATE rather than BAILOUT.
    This test documents real pipeline behavior rather than assuming parity with the
    legacy pipeline.

    Verify: only steps 1 and 3 are mutated; steps 0 and 2 are the same objects in
    the output tree (structural sharing via is-identity).
    """
    content = (TESTING_INPUTS / "multi_step_mixed.yml").read_bytes()
    cst_in, result = _run_pipeline(content)

    assert result.workflow is None, "Stage 6 must not rebuild the semantic model"
    assert result.cst is not None
    assert result.cst is not cst_in

    # Two REMEDIATE steps: step 1 (body) and step 3 (eval — Stage 5 does not bail on eval).
    assert len(result.applied_step_mutations) == 2
    mutated_indices = {m.step_index for m in result.applied_step_mutations}
    assert mutated_indices == {1, 3}, (
        f"Expected steps 1 and 3 to be mutated, got indices: {mutated_indices}"
    )

    # Verify structural sharing via is-identity.
    from cst_auto_remediator.yaml_cst.nodes import YamlMapping, YamlScalar, YamlSequence

    def _steps_seq(cst, job_id: str) -> YamlSequence:
        assert isinstance(cst.root, YamlMapping)
        for e in cst.root.entries:
            if isinstance(e.key, YamlScalar) and e.key.value == "jobs":
                assert isinstance(e.value, YamlMapping)
                for je in e.value.entries:
                    if isinstance(je.key, YamlScalar) and je.key.value == job_id:
                        assert isinstance(je.value, YamlMapping)
                        for se in je.value.entries:
                            if isinstance(se.key, YamlScalar) and se.key.value == "steps":
                                assert isinstance(se.value, YamlSequence)
                                return se.value
        raise AssertionError(f"steps sequence not found for job {job_id!r}")

    in_steps = _steps_seq(cst_in, "mixed")
    out_steps = _steps_seq(result.cst, "mixed")

    assert out_steps.items[0] is in_steps.items[0], "already-remediated step must be same object"
    assert out_steps.items[1] is not in_steps.items[1], "REMEDIATE step 1 must be a new object"
    assert out_steps.items[2] is in_steps.items[2], "block-scalar step must be same object"
    assert out_steps.items[3] is not in_steps.items[3], "REMEDIATE step 3 must be a new object"

    # Verify output content via semantic rebuild.
    rebuilt = build_semantic_model(result.cst)
    assert rebuilt.workflow is not None
    remediated_step1 = rebuilt.workflow.jobs["mixed"].steps[1]
    assert remediated_step1.run_command is not None
    assert "${{" not in remediated_step1.run_command.command.value
    # namer derives PULL_REQUEST_BODY from github.event.pull_request.body
    env_names = [b.key.value for b in remediated_step1.env_bindings]
    assert any("PULL_REQUEST_BODY" in name or "BODY" in name for name in env_names), (
        f"expected an env var containing BODY for github.event.pull_request.body, got: {env_names}"
    )

