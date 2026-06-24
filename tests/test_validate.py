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
