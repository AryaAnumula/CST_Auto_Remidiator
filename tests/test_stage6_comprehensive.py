"""
Comprehensive tests for Stage 6: Transformation.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from cst_auto_remediator.gha_analysis.analyzer import analyze_workflow
from cst_auto_remediator.gha_metadata.engine import MetadataWrapper
from cst_auto_remediator.gha_metadata.nodes import ScopeMetadata
from cst_auto_remediator.gha_semantic.builder import build_semantic_model
from cst_auto_remediator.gha_transform.namer import gen_safe_var_name
from cst_auto_remediator.gha_transform.nodes import SiteReplacement
from cst_auto_remediator.gha_transform.planner import (
    MutationPlanner,
    Stage6InvariantError,
)
from cst_auto_remediator.gha_transform.rtl import apply_rtl_substitutions
from cst_auto_remediator.gha_transform.transformer import CSTTransformer
from cst_auto_remediator.yaml_cst.builder import build_cst
from cst_auto_remediator.yaml_cst.nodes import YamlDocument, YamlKeyValue, YamlMapping, YamlScalar, YamlSequence
from cst_auto_remediator.yaml_cst.parser import parse_yaml


def _find_entry(mapping: YamlMapping, key_name: str) -> YamlKeyValue:
    for entry in mapping.entries:
        if isinstance(entry.key, YamlScalar) and entry.key.value == key_name:
            return entry
    raise AssertionError(f"missing mapping entry {key_name!r}")


def _workflow_resources(content: bytes) -> tuple[YamlDocument, Any, MetadataWrapper, Any]:
    doc, meta = parse_yaml(content)
    cst = build_cst(doc, meta)
    semantic = build_semantic_model(cst)
    assert semantic.workflow is not None
    wrapper = MetadataWrapper(semantic.workflow)
    analysis = analyze_workflow(semantic.workflow, wrapper)
    return cst, semantic.workflow, wrapper, analysis


def _steps_sequence(cst: YamlDocument, job_id: str) -> YamlSequence:
    assert isinstance(cst.root, YamlMapping)
    jobs_entry = _find_entry(cst.root, "jobs")
    assert isinstance(jobs_entry.value, YamlMapping)
    job_entry = _find_entry(jobs_entry.value, job_id)
    assert isinstance(job_entry.value, YamlMapping)
    steps_entry = _find_entry(job_entry.value, "steps")
    assert isinstance(steps_entry.value, YamlSequence)
    return steps_entry.value


def _replacement(script: str, original: str, replacement: str, expression_id: str) -> SiteReplacement:
    start = script.index(original)
    return SiteReplacement(
        expression_id=expression_id,
        start_offset=start,
        end_offset=start + len(original),
        original_text=original,
        replacement_text=replacement,
        env_var_name=replacement.removeprefix("$"),
    )


def test_gen_safe_var_name_basic_cases() -> None:
    scope = ScopeMetadata(scope_type="step", env={}, parent_scope=None)

    assert gen_safe_var_name("${{ github.event.issue.title }}", scope) == "ISSUE_TITLE"
    assert gen_safe_var_name("${{ github.head_ref }}", scope) == "HEAD_REF"
    assert gen_safe_var_name("${{ fromJSON(inputs.pr_title) }}", scope) == "PR_TITLE"


def test_gen_safe_var_name_collision_and_hash_determinism() -> None:
    scope = ScopeMetadata(
        scope_type="step",
        env={"ISSUE_TITLE": YamlScalar(value="already", raw_text="already")},
        parent_scope=None,
    )

    first = gen_safe_var_name("${{ github.event.issue.title }}", scope)
    second = gen_safe_var_name("${{ github.event.issue.title }}", scope)

    assert first == second
    assert first.startswith("ISSUE_TITLE_")
    assert len(first.rsplit("_", 1)[1]) == 8


def test_gen_safe_var_name_truncates_and_keeps_suffix_within_limit() -> None:
    scope = ScopeMetadata(scope_type="step", env={}, parent_scope=None)
    long_expr = "${{ github.event.pull_request.very.deeply.nested.field.name.value }}"

    name = gen_safe_var_name(long_expr, scope, max_length=40)
    assert len(name) <= 40

    colliding_scope = ScopeMetadata(
        scope_type="step",
        env={name: YamlScalar(value="already", raw_text="already")},
        parent_scope=None,
    )
    colliding_name = gen_safe_var_name(long_expr, colliding_scope, max_length=40)
    assert len(colliding_name) <= 40
    assert colliding_name != name
    assert len(colliding_name.rsplit("_", 1)[1]) == 8


def test_apply_rtl_substitutions_handles_multiple_sites() -> None:
    script = (
        "echo ${{ github.event.issue.title }} and "
        "${{ github.event.comment.body }}"
    )
    replacements = (
        _replacement(script, "${{ github.event.issue.title }}", "$ISSUE_TITLE", "expr0"),
        _replacement(script, "${{ github.event.comment.body }}", "$COMMENT_BODY", "expr1"),
    )

    assert apply_rtl_substitutions(script, replacements) == "echo $ISSUE_TITLE and $COMMENT_BODY"


def test_apply_rtl_substitutions_proves_left_to_right_offsets_would_be_wrong() -> None:
    script = (
        "echo ${{ github.event.issue.title }} and "
        "${{ github.event.comment.body }}"
    )
    replacements = (
        _replacement(script, "${{ github.event.issue.title }}", "$ISSUE_TITLE", "expr0"),
        _replacement(script, "${{ github.event.comment.body }}", "$COMMENT_BODY", "expr1"),
    )

    naive = script
    for item in sorted(replacements, key=lambda repl: repl.start_offset):
        naive = naive[: item.start_offset] + item.replacement_text + naive[item.end_offset :]

    assert naive != "echo $ISSUE_TITLE and $COMMENT_BODY"
    assert apply_rtl_substitutions(script, replacements) == "echo $ISSUE_TITLE and $COMMENT_BODY"


def test_mutation_planner_filters_to_remediate_only() -> None:
    content = (
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - run: echo ${{ github.sha }}\n"
        b"      - run: echo ${{ github.event.issue.title }}\n"
        b"      - run: echo ${{ github.actor }}\n"
        b"      - run: echo '${{ github.event.issue.body }}'\n"
    )
    _, _, wrapper, analysis = _workflow_resources(content)

    plan = MutationPlanner(wrapper).build_plan(analysis)

    assert len(plan.step_mutations) == 1
    mutation = plan.step_mutations[0]
    assert mutation.job_id == "build"
    assert mutation.step_index == 1
    assert [entry.name for entry in mutation.env_entries] == ["ISSUE_TITLE"]
    assert [replacement.replacement_text for replacement in mutation.replacements] == ["$ISSUE_TITLE"]


def test_mutation_planner_raises_when_remediate_scope_is_missing() -> None:
    content = (
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - run: echo ${{ github.event.issue.title }}\n"
    )
    _, _, wrapper, analysis = _workflow_resources(content)
    key = "jobs.build.steps.0.run.exprs.0"
    bad_classification = replace(analysis.expression_classifications[key], scope=None)
    bad_analysis = replace(analysis, expression_classifications={key: bad_classification})

    with pytest.raises(Stage6InvariantError, match="has no ScopeMetadata"):
        MutationPlanner(wrapper).build_plan(bad_analysis)


def test_cst_transformer_preserves_original_tree_and_untouched_sibling_identity() -> None:
    content = (
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - name: trusted\n"
        b"        run: echo ${{ github.sha }}\n"
        b"      - name: vulnerable\n"
        b"        run: echo ${{ github.event.issue.title }} and ${{ github.event.comment.body }}\n"
        b"      - name: plain\n"
        b"        run: echo done\n"
    )
    cst, _, wrapper, analysis = _workflow_resources(content)
    original_repr = repr(cst)
    original_steps = _steps_sequence(cst, "build")

    plan = MutationPlanner(wrapper).build_plan(analysis)
    result = CSTTransformer().transform(plan)

    assert repr(cst) == original_repr
    assert result.cst is not None
    output_steps = _steps_sequence(result.cst, "build")
    assert output_steps.items[0] is original_steps.items[0]
    assert output_steps.items[1] is not original_steps.items[1]
    assert output_steps.items[2] is original_steps.items[2]

    # Stage 6 no longer rebuilds the semantic model — workflow is always None.
    # Callers (Stage 7 / orchestrator) are responsible for the semantic rebuild.
    assert result.workflow is None

    # Verify CST content by rebuilding the semantic model here in the test.
    rebuilt = build_semantic_model(result.cst)
    assert rebuilt.workflow is not None
    transformed_step = rebuilt.workflow.jobs["build"].steps[1]
    assert transformed_step.run_command is not None
    assert transformed_step.run_command.command.value == "echo $ISSUE_TITLE and $COMMENT_BODY"
    assert [binding.key.value for binding in transformed_step.env_bindings] == [
        "ISSUE_TITLE",
        "COMMENT_BODY",
    ]


def test_cst_transformer_mutates_only_remediate_sites_across_jobs() -> None:
    content = (
        b"jobs:\n"
        b"  safe:\n"
        b"    steps:\n"
        b"      - run: echo ${{ github.sha }}\n"
        b"  mixed:\n"
        b"    steps:\n"
        b"      - run: echo ${{ github.event.issue.title }}\n"
        b"      - run: echo ${{ github.actor }}\n"
    )
    cst, _, wrapper, analysis = _workflow_resources(content)
    safe_steps = _steps_sequence(cst, "safe")
    mixed_steps = _steps_sequence(cst, "mixed")

    plan = MutationPlanner(wrapper).build_plan(analysis)
    result = CSTTransformer().transform(plan)

    assert result.cst is not None
    output_safe_steps = _steps_sequence(result.cst, "safe")
    output_mixed_steps = _steps_sequence(result.cst, "mixed")
    assert output_safe_steps.items[0] is safe_steps.items[0]
    assert output_mixed_steps.items[0] is not mixed_steps.items[0]
    assert output_mixed_steps.items[1] is mixed_steps.items[1]

    # Stage 6 no longer rebuilds the semantic model — workflow is always None.
    assert result.workflow is None

    # Verify CST content by rebuilding the semantic model here in the test.
    rebuilt = build_semantic_model(result.cst)
    assert rebuilt.workflow is not None
    remediated = rebuilt.workflow.jobs["mixed"].steps[0]
    bailed = rebuilt.workflow.jobs["mixed"].steps[1]
    assert remediated.run_command is not None
    assert bailed.run_command is not None
    assert remediated.run_command.command.value == "echo $ISSUE_TITLE"
    assert bailed.run_command.command.value == "echo ${{ github.actor }}"


# ── GAP-1: 3-expression RTL ────────────────────────────────────────────────────

def test_apply_rtl_substitutions_three_sites() -> None:
    """Exercises the third RTL iteration — the `previous_start` guard runs twice."""
    script = (
        "echo ${{ github.event.issue.title }} "
        "${{ github.event.comment.body }} "
        "${{ github.head_ref }}"
    )
    r1 = _replacement(script, "${{ github.event.issue.title }}", "$A", "e0")
    r2 = _replacement(script, "${{ github.event.comment.body }}", "$B", "e1")
    r3 = _replacement(script, "${{ github.head_ref }}", "$C", "e2")
    result = apply_rtl_substitutions(script, (r1, r2, r3))
    assert result == "echo $A $B $C"


# ── GAP-3: pre-existing env: block augmentation ────────────────────────────────

def test_cst_transformer_augments_pre_existing_env_block_preserving_identity() -> None:
    """
    When a REMEDIATE step already has an env: block, Stage 6 appends the new var
    after the existing entries. The existing entry must be the same object (is-identity),
    not a copy — structural sharing must apply within the augmented env: block.
    """
    content = (
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - name: pre-existing-env\n"
        b"        env:\n"
        b"          KEEP_ME: static-value\n"
        b"        run: echo ${{ github.event.issue.title }}\n"
    )
    cst, _, wrapper, analysis = _workflow_resources(content)
    plan = MutationPlanner(wrapper).build_plan(analysis)
    result = CSTTransformer().transform(plan)

    assert result.cst is not None
    assert len(result.applied_step_mutations) == 1

    # Navigate to the env: block in the output CST to check entry identity.
    out_step = _steps_sequence(result.cst, "build").items[0]
    assert isinstance(out_step, YamlMapping)
    env_entry = _find_entry(out_step, "env")
    assert env_entry is not None
    assert isinstance(env_entry.value, YamlMapping)
    out_env_entries = env_entry.value.entries

    # The original env: block in the input CST.
    in_step = _steps_sequence(cst, "build").items[0]
    assert isinstance(in_step, YamlMapping)
    in_env_entry = _find_entry(in_step, "env")
    assert isinstance(in_env_entry.value, YamlMapping)
    original_keep_me = in_env_entry.value.entries[0]

    # KEEP_ME entry must be the same object (not a copy).
    assert out_env_entries[0] is original_keep_me, (
        "pre-existing KEEP_ME env entry must be structurally shared (same object), not copied"
    )
    # A new env entry was appended after KEEP_ME.
    assert len(out_env_entries) == 2
    assert out_env_entries[1] is not original_keep_me
    assert isinstance(out_env_entries[1].key, YamlScalar)
    assert out_env_entries[1].key.value == "ISSUE_TITLE"


# ── GAP-4: REMEDIATE + wrong sink_kind raises Stage6InvariantError ─────────────

def test_mutation_planner_raises_when_remediate_has_wrong_sink_kind() -> None:
    """
    planner.py:59–62 raises Stage6InvariantError if a REMEDIATE classification
    has sink_kind != SinkKind.RUN_COMMAND. Exercises the guard path.
    """
    from dataclasses import replace as _replace
    from cst_auto_remediator.gha_analysis.nodes import SinkKind

    content = (
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - run: echo ${{ github.event.issue.title }}\n"
    )
    _, _, wrapper, analysis = _workflow_resources(content)

    # There must be exactly one classification; patch its sink_kind.
    assert len(analysis.expression_classifications) == 1
    key, classification = next(iter(analysis.expression_classifications.items()))
    # Force a non-RUN_COMMAND sink while keeping REMEDIATE decision.
    bad_classification = _replace(classification, sink_kind=SinkKind.ENV_ASSIGNMENT)
    bad_analysis = _replace(
        analysis,
        expression_classifications={key: bad_classification},
    )
    with pytest.raises(Stage6InvariantError, match="not in a run command"):
        MutationPlanner(wrapper).build_plan(bad_analysis)


# ── GAP-5: two expressions with same base name get distinct hash-suffixed names ─

def test_gen_safe_var_name_two_expressions_with_same_base_get_distinct_names() -> None:
    """
    github.event.issue_title and github.event.issue.title both produce the base
    ISSUE_TITLE. When the first result is passed as a reserved name, the second call
    must produce a distinct, hash-suffixed name that also satisfies the length limit.
    """
    scope = ScopeMetadata(scope_type="step", env={}, parent_scope=None)

    # First expression: establishes the base name.
    name_a = gen_safe_var_name("${{ github.event.issue.title }}", scope)
    assert name_a == "ISSUE_TITLE"

    # Second expression with a different path that produces the same base.
    # Pass name_a as reserved so the namer must differentiate.
    name_b = gen_safe_var_name(
        "${{ github.event.issue_title }}",
        scope,
        reserved_names=[name_a],
    )
    assert name_b != name_a, "both names must be distinct"
    assert len(name_b) <= 40, "name must respect max_length"
    # Hash suffix is 8 hex chars; the name must contain an underscore-separated suffix.
    parts = name_b.rsplit("_", 1)
    assert len(parts) == 2, f"expected BASENAME_HEXHASH format, got {name_b!r}"
    assert len(parts[1]) == 8, f"expected 8-char hex suffix, got {parts[1]!r}"

