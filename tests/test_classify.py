"""Unit tests for expression classification."""

import pytest

from cst_auto_remediator.classify import (
    classify_expression,
    extract_expression_body,
    find_expressions,
)
from cst_auto_remediator.models import Classification


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("github.event.pull_request.title", Classification.UNTRUSTED),
        ("github.event.inputs.foo", Classification.UNTRUSTED),
        ("github.head_ref", Classification.UNTRUSTED),
        ("github.base_ref", Classification.UNTRUSTED),
        ("fromJSON(inputs.pr_title)", Classification.UNTRUSTED),
        ("fromJSON(needs.build.outputs.x)", Classification.AMBIGUOUS),
        ("secrets.GITHUB_TOKEN", Classification.TRUSTED),
        ("vars.MY_VAR", Classification.TRUSTED),
        ("github.sha", Classification.TRUSTED),
        ("github.run_id", Classification.TRUSTED),
        ("github.repository", Classification.AMBIGUOUS),
    ],
)
def test_classify_expression(body: str, expected: Classification) -> None:
    assert classify_expression(body) is expected


def test_find_expressions_offsets() -> None:
    value = 'echo "${{ github.event.issue.title }}" and ${{ secrets.TOKEN }}'
    matches = find_expressions(value)
    assert len(matches) == 2
    assert matches[0][0] == "${{ github.event.issue.title }}"
    assert value[matches[0][1] : matches[0][2]] == matches[0][0]


def test_extract_expression_body() -> None:
    assert extract_expression_body("${{  github.event.issue.title  }}") == "github.event.issue.title"
