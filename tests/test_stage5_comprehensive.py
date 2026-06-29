"""
Comprehensive unit and integration tests for Stage 5: Security Analysis.
Verifies all Stage 5 trust classifications, decisions, bailouts, statistics,
and architectural invariants (immutability, determinism, cache reuse, and non-mutation).
"""

import hashlib
import pytest
from typing import Any
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
from cst_auto_remediator.gha_analysis.analyzer import analyze_workflow
from cst_auto_remediator.gha_analysis.nodes import (
    TrustLevel,
    SourceKind,
    SinkKind,
    BailoutReason,
    AnalysisDecision,
)


def _get_resources(yaml_bytes: bytes) -> tuple[Any, MetadataWrapper]:
    doc, meta = parse_yaml(yaml_bytes)
    cst = build_cst(doc, meta)
    res = build_semantic_model(cst)
    wrapper = MetadataWrapper(res.workflow)
    return res.workflow, wrapper


def test_trusted_and_untrusted_classification() -> None:
    content = (
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - run: echo ${{ github.sha }}\n"  # Trusted
        b"      - run: echo ${{ github.event.issue.title }}\n"  # Untrusted
    )
    workflow, wrapper = _get_resources(content)
    result = analyze_workflow(workflow, wrapper)

    assert result.statistics.total_expressions == 2
    assert result.statistics.trusted_expressions == 1
    assert result.statistics.untrusted_expressions == 1

    # Check safe (trusted) step expression
    classif_trusted = result.expression_classifications["jobs.build.steps.0.run.exprs.0"]
    assert classif_trusted.trust_level is TrustLevel.TRUSTED
    assert classif_trusted.source_kind is SourceKind.GITHUB_CONTEXT
    assert classif_trusted.sink_kind is SinkKind.RUN_COMMAND
    assert classif_trusted.decision is AnalysisDecision.SAFE
    assert classif_trusted.bailout_reason is BailoutReason.NONE

    # Check unsafe (untrusted) step expression
    classif_untrusted = result.expression_classifications["jobs.build.steps.1.run.exprs.0"]
    assert classif_untrusted.trust_level is TrustLevel.UNTRUSTED
    assert classif_untrusted.source_kind is SourceKind.GITHUB_CONTEXT
    assert classif_untrusted.sink_kind is SinkKind.RUN_COMMAND
    assert classif_untrusted.decision is AnalysisDecision.REMEDIATE
    assert classif_untrusted.bailout_reason is BailoutReason.NONE
    assert len(classif_untrusted.diagnostics) == 1
    assert classif_untrusted.diagnostics[0].code == "ANA004"


def test_mixed_and_unknown_classification() -> None:
    content = (
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      # Mixed: trusted + untrusted\n"
        b"      - run: echo ${{ format('{0} and {1}', github.sha, github.event.issue.title) }}\n"
        b"      # Unknown: not in model list\n"
        b"      - run: echo ${{ github.actor }}\n"
    )
    workflow, wrapper = _get_resources(content)
    result = analyze_workflow(workflow, wrapper)

    assert result.statistics.total_expressions == 2

    # Mixed
    m_class = result.expression_classifications["jobs.build.steps.0.run.exprs.0"]
    assert m_class.trust_level is TrustLevel.MIXED
    assert m_class.decision is AnalysisDecision.REMEDIATE

    # Unknown
    u_class = result.expression_classifications["jobs.build.steps.1.run.exprs.0"]
    assert u_class.trust_level is TrustLevel.UNKNOWN
    assert u_class.decision is AnalysisDecision.BAILOUT
    assert u_class.bailout_reason is BailoutReason.UNKNOWN_SOURCE
    assert u_class.diagnostics[0].code == "ANA001"


def test_env_expressions_and_duplicate_handling() -> None:
    content = (
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - env:\n"
        b"          TITLE: ${{ github.event.issue.title }}\n"  # env expression (skip/safe_already)
        b"        run: echo ${{ github.event.issue.title }}\n"  # duplicate expression
    )
    workflow, wrapper = _get_resources(content)
    result = analyze_workflow(workflow, wrapper)

    assert result.statistics.total_expressions == 2
    assert result.statistics.needs_remediation == 1
    assert result.statistics.skipped == 1

    # Env expression
    env_class = result.expression_classifications["jobs.build.steps.0.env.TITLE.exprs.0"]
    assert env_class.sink_kind is SinkKind.ENV_ASSIGNMENT
    assert env_class.decision is AnalysisDecision.SKIP
    assert env_class.bailout_reason is BailoutReason.DEFERRED_ENV_REMEDIATION

    # Run expression (remediate)
    run_class = result.expression_classifications["jobs.build.steps.0.run.exprs.0"]
    assert run_class.sink_kind is SinkKind.RUN_COMMAND
    assert run_class.decision is AnalysisDecision.REMEDIATE


def test_multiple_jobs_and_steps() -> None:
    content = (
        b"jobs:\n"
        b"  job1:\n"
        b"    steps:\n"
        b"      - run: echo ${{ github.sha }}\n"
        b"  job2:\n"
        b"    steps:\n"
        b"      - run: echo ${{ github.event.issue.title }}\n"
    )
    workflow, wrapper = _get_resources(content)
    result = analyze_workflow(workflow, wrapper)

    assert result.statistics.total_expressions == 2
    assert "jobs.job1.steps.0.run.exprs.0" in result.expression_classifications
    assert "jobs.job2.steps.0.run.exprs.0" in result.expression_classifications


def test_block_scalar_bailout() -> None:
    content = (
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - run: |\n"
        b"          echo ${{ github.event.issue.title }}\n"
    )
    workflow, wrapper = _get_resources(content)
    result = analyze_workflow(workflow, wrapper)

    assert result.statistics.total_expressions == 1
    classif = result.expression_classifications["jobs.build.steps.0.run.exprs.0"]
    assert classif.decision is AnalysisDecision.BAILOUT
    assert classif.bailout_reason is BailoutReason.BLOCK_SCALAR
    assert classif.diagnostics[0].code == "ANA003"


def test_unsupported_shell_and_runner_bailouts() -> None:
    # 1. Unsupported shell: python
    content_shell = (
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - run: print('${{ github.event.issue.title }}')\n"
        b"        shell: python\n"
    )
    workflow, wrapper = _get_resources(content_shell)
    result = analyze_workflow(workflow, wrapper)
    classif = result.expression_classifications["jobs.build.steps.0.run.exprs.0"]
    assert classif.decision is AnalysisDecision.BAILOUT
    assert classif.bailout_reason is BailoutReason.UNSUPPORTED_SHELL
    assert classif.diagnostics[0].code == "ANA002"

    # 2. Unsupported runner: windows (resolves default shell to pwsh)
    content_runner = (
        b"jobs:\n"
        b"  build:\n"
        b"    runs-on: windows-latest\n"
        b"    steps:\n"
        b"      - run: Write-Output ${{ github.event.issue.title }}\n"
    )
    workflow, wrapper = _get_resources(content_runner)
    result = analyze_workflow(workflow, wrapper)
    classif = result.expression_classifications["jobs.build.steps.0.run.exprs.0"]
    assert classif.decision is AnalysisDecision.BAILOUT
    assert classif.bailout_reason is BailoutReason.UNSUPPORTED_RUNNER


def test_single_quoted_skip_remediation() -> None:
    content = (
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - run: echo '${{ github.event.issue.title }}'\n"
    )
    workflow, wrapper = _get_resources(content)
    result = analyze_workflow(workflow, wrapper)
    classif = result.expression_classifications["jobs.build.steps.0.run.exprs.0"]
    assert classif.decision is AnalysisDecision.SKIP
    assert classif.bailout_reason is BailoutReason.NONE


def test_no_expressions_handling() -> None:
    content = (
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - run: echo hello\n"
    )
    workflow, wrapper = _get_resources(content)
    result = analyze_workflow(workflow, wrapper)
    assert result.statistics.total_expressions == 0
    assert len(result.expression_classifications) == 0


def test_invalid_structure_bailout() -> None:
    # GHA002: Missing jobs section
    content = b"name: invalid-workflow\n"
    workflow, wrapper = _get_resources(content)
    result = analyze_workflow(workflow, wrapper)
    assert result.summary["status"] == "invalid_structure"
    assert result.statistics.bailouts == 1


# --- 4 Architectural Invariant Tests ---

def test_invariant_a_repeated_analysis_is_deterministic() -> None:
    content = (
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - run: echo ${{ github.event.issue.title }}\n"
    )
    workflow, wrapper = _get_resources(content)

    # First analysis run
    res1 = analyze_workflow(workflow, wrapper)

    # Second analysis run
    res2 = analyze_workflow(workflow, wrapper)

    # Assert exactly isomorphic classifications and summary counts
    assert len(res1.expression_classifications) == len(res2.expression_classifications)
    assert res1.statistics == res2.statistics
    assert res1.summary == res2.summary

    for key, c1 in res1.expression_classifications.items():
        c2 = res2.expression_classifications[key]
        assert c1.stable_expression_id == c2.stable_expression_id
        assert c1.trust_level == c2.trust_level
        assert c1.decision == c2.decision
        assert c1.bailout_reason == c2.bailout_reason


def test_invariant_b_green_cst_not_mutated() -> None:
    content = (
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - run: echo ${{ github.event.issue.title }}\n"
    )
    doc, meta = parse_yaml(content)
    cst = build_cst(doc, meta)

    # Compute a representation hash before analysis
    cst_repr_before = repr(cst.root)

    res = build_semantic_model(cst)
    wrapper = MetadataWrapper(res.workflow)

    # Perform analysis
    _ = analyze_workflow(res.workflow, wrapper)

    # Verify that the representation is completely unchanged
    cst_repr_after = repr(cst.root)
    assert cst_repr_before == cst_repr_after


def test_invariant_c_metadata_cache_object_reused() -> None:
    content = (
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - run: echo ${{ github.event.issue.title }}\n"
    )
    workflow, wrapper = _get_resources(content)

    # Execute analyzer
    _ = analyze_workflow(workflow, wrapper)

    # Retrieve providers and check cache reuse
    # They should be cached in the registry mapping
    assert PositionProvider in wrapper.cache
    assert ScopeProvider in wrapper.cache
    assert ShellProvider in wrapper.cache
    assert ExpressionProvider in wrapper.cache


def test_invariant_d_semantic_tree_object_reused() -> None:
    content = (
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - run: echo ${{ github.event.issue.title }}\n"
    )
    workflow, wrapper = _get_resources(content)

    original_job_ids = list(workflow.jobs.keys())
    original_step_count = len(workflow.jobs["build"].steps)

    # Run analysis
    _ = analyze_workflow(workflow, wrapper)

    # Assert semantic tree elements were not replaced or mutated in-place
    assert list(workflow.jobs.keys()) == original_job_ids
    assert len(workflow.jobs["build"].steps) == original_step_count
