"""Unit tests for Stage 3 validation rules."""

import pytest
from ruamel.yaml.comments import CommentedMap

from cst_auto_remediator.models import (
    Action,
    Classification,
    ExpressionSite,
    ReasonCode,
    ScalarType,
)
from cst_auto_remediator.validate import (
    detect_sink,
    generate_env_var_name,
    validate_site,
)


def _site(
    run_value: str,
    start: int,
    end: int,
    *,
    scalar_type: ScalarType = ScalarType.PLAIN,
    classification: Classification = Classification.UNTRUSTED,
    body: str = "github.event.issue.title",
) -> ExpressionSite:
    return ExpressionSite(
        job_id="test",
        step_index=0,
        step_id=None,
        expression_text=run_value[start:end],
        expression_body=body,
        classification=classification,
        scalar_type=scalar_type,
        start_offset=start,
        end_offset=end,
        run_value=run_value,
    )


def test_generate_env_var_name() -> None:
    assert generate_env_var_name("github.event.issue.title") == "ISSUE_TITLE"
    assert generate_env_var_name("github.head_ref") == "HEAD_REF"
    assert generate_env_var_name("fromJSON(inputs.pr_title)") == "PR_TITLE"


def test_detect_sink_eval() -> None:
    run_value = 'eval "echo ${{ github.event.issue.title }}"'
    expr = "${{ github.event.issue.title }}"
    start = run_value.index(expr)
    end = start + len(expr)
    assert detect_sink(run_value, start, end) is ReasonCode.SINK_EVAL


def test_detect_sink_command_substitution() -> None:
    run_value = "echo $(echo ${{ github.event.issue.title }})"
    expr = "${{ github.event.issue.title }}"
    start = run_value.index(expr)
    end = start + len(expr)
    assert detect_sink(run_value, start, end) is ReasonCode.SINK_COMMAND_SUBSTITUTION


def test_env_name_collision() -> None:
    run_value = 'echo "${{ github.event.issue.title }}"'
    expr = "${{ github.event.issue.title }}"
    start = run_value.index(expr)
    site = _site(run_value, start, start + len(expr))
    step = CommentedMap()
    step["env"] = CommentedMap({"issue_title": "already"})
    result = validate_site(site, step, {})
    assert result.action is Action.BAILED
    assert result.reason is ReasonCode.ENV_NAME_COLLISION


def test_block_scalar_skipped() -> None:
    run_value = 'echo "${{ github.event.issue.title }}"'
    expr = "${{ github.event.issue.title }}"
    start = run_value.index(expr)
    site = _site(run_value, start, start + len(expr), scalar_type=ScalarType.BLOCK)
    result = validate_site(site, CommentedMap(), {})
    assert result.action is Action.SKIPPED
    assert result.reason is ReasonCode.BLOCK_SCALAR_OUT_OF_SCOPE


def test_folded_block_scalar_skipped() -> None:
    # A GHA step with a folded block scalar (>)
    run_value = "echo >\n  ${{ github.event.issue.title }}\n"
    expr = "${{ github.event.issue.title }}"
    start = run_value.index(expr)
    site = _site(run_value, start, start + len(expr), scalar_type=ScalarType.BLOCK)
    result = validate_site(site, CommentedMap(), {})
    assert result.action is Action.SKIPPED
    assert result.reason is ReasonCode.BLOCK_SCALAR_OUT_OF_SCOPE


def test_non_untrusted_skipped() -> None:
    # TRUSTED
    run_value = 'echo "${{ secrets.TOKEN }}"'
    expr = "${{ secrets.TOKEN }}"
    start = run_value.index(expr)
    site = _site(run_value, start, start + len(expr), classification=Classification.TRUSTED, body="secrets.TOKEN")
    result = validate_site(site, CommentedMap(), {})
    assert result.action is Action.SKIPPED
    assert result.reason is ReasonCode.TRUSTED

    # AMBIGUOUS
    run_value = 'echo "${{ inputs.name }}"'
    expr = "${{ inputs.name }}"
    start = run_value.index(expr)
    site = _site(run_value, start, start + len(expr), classification=Classification.AMBIGUOUS, body="inputs.name")
    result = validate_site(site, CommentedMap(), {})
    assert result.action is Action.SKIPPED
    assert result.reason is ReasonCode.AMBIGUOUS_EXPRESSION


def test_job_wide_env_name_collision() -> None:
    run_value = 'echo "${{ github.event.issue.title }}"'
    expr = "${{ github.event.issue.title }}"
    start = run_value.index(expr)
    site = _site(run_value, start, start + len(expr))
    
    # Current step has no collision
    step = CommentedMap()
    
    # Another step in the job has a collision
    sibling_step = CommentedMap({"env": CommentedMap({"ISSUE_TITLE": "colliding_value"})})
    job_steps = [step, sibling_step]
    
    result = validate_site(site, step, {}, job_steps)
    assert result.action is Action.BAILED
    assert result.reason is ReasonCode.ENV_NAME_COLLISION


def test_multiple_expressions_in_one_run() -> None:
    # A single run line containing two untrusted expressions
    run_value = 'echo "${{ github.event.issue.title }}" and "${{ github.event.issue.body }}"'
    
    expr1 = "${{ github.event.issue.title }}"
    start1 = run_value.index(expr1)
    site1 = _site(run_value, start1, start1 + len(expr1), body="github.event.issue.title")
    
    expr2 = "${{ github.event.issue.body }}"
    start2 = run_value.index(expr2)
    site2 = _site(run_value, start2, start2 + len(expr2), body="github.event.issue.body")
    
    pending_env_names = {}
    step = CommentedMap()
    
    result1 = validate_site(site1, step, pending_env_names)
    assert result1.action is Action.PATCHED
    assert result1.env_var_name == "ISSUE_TITLE"
    
    result2 = validate_site(site2, step, pending_env_names)
    assert result2.action is Action.PATCHED
    assert result2.env_var_name == "ISSUE_BODY"

