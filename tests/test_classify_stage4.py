"""
Stage 4 — taint classifier edge-case tests (single-line run: scope).

Covers obfuscation, bracket access, mixed-trust lines, and balanced expression
extraction per the architecture diagram Step 4 edge classes.
"""

from __future__ import annotations

import pytest

from cst_auto_remediator.classify import (
    classify_expression,
    extract_expression_body,
    find_expressions,
    normalize_for_classification,
)
from cst_auto_remediator.models import Classification


# ---------------------------------------------------------------------------
# Stage 4 — direct classification (Step 4 edge classes)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("body", "expected"),
    [
        # Baseline (unchanged behaviour)
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
        # Parenthetical wrapping evasion
        ("(github.event).issue.title", Classification.UNTRUSTED),
        ("((github.event.issue)).title", Classification.UNTRUSTED),
        ("( github.event.pull_request.body )", Classification.UNTRUSTED),
        # Bracket property access
        ("github['event']['issue']['title']", Classification.UNTRUSTED),
        ('github["event"]["pull_request"]["title"]', Classification.UNTRUSTED),
        ("github['head_ref']", Classification.UNTRUSTED),
        # Function wrappers (dynamic expression obfuscation)
        ("format('{0}', github.event.issue.title)", Classification.UNTRUSTED),
        ("join('', github.event.commits[0].message)", Classification.UNTRUSTED),
        # inputs.* ambiguity trap — remains SKIP per diagram
        ("inputs.branch_name", Classification.AMBIGUOUS),
        ("inputs.ref", Classification.AMBIGUOUS),
        # Mixed trust inside one expression — conservative UNTRUSTED if any untrusted path
        ("format('{0}{1}', github.event.sender.login, secrets.GITHUB_TOKEN)", Classification.UNTRUSTED),
        # Trusted-only wrappers
        ("format('{0}', secrets.GITHUB_TOKEN)", Classification.TRUSTED),
        ("(secrets.GITHUB_TOKEN)", Classification.TRUSTED),
        ("vars['DEPLOY_KEY']", Classification.TRUSTED),
    ],
)
def test_stage4_classify_expression(body: str, expected: Classification) -> None:
    assert classify_expression(body) is expected


@pytest.mark.parametrize(
    ("body", "expected_normalized"),
    [
        ("(github.event).issue.title", "github.event.issue.title"),
        ("github['event']['issue']['title']", "github.event.issue.title"),
        ("github.event.commits[0].message", "github.event.commits.0.message"),
    ],
)
def test_normalize_for_classification(body: str, expected_normalized: str) -> None:
    assert normalize_for_classification(body) == expected_normalized


# ---------------------------------------------------------------------------
# Mixed-trust single-line run: (per-expression isolation)
# ---------------------------------------------------------------------------

def test_mixed_trust_single_line_two_expressions() -> None:
    run_value = (
        'echo "User: ${{ github.event.sender.login }} Token: ${{ secrets.GITHUB_TOKEN }}"'
    )
    matches = find_expressions(run_value)
    assert len(matches) == 2
    bodies = [extract_expression_body(m[0]) for m in matches]
    assert classify_expression(bodies[0]) is Classification.UNTRUSTED
    assert classify_expression(bodies[1]) is Classification.TRUSTED


# ---------------------------------------------------------------------------
# Balanced expression extraction (nested-${{ string-literal edge class)
# ---------------------------------------------------------------------------

def test_find_expressions_balanced_nested_delimiters() -> None:
    """Non-greedy regex would truncate at the first ``}}`` inside a string literal."""
    run_value = "echo ${{ github.event.title == '${{ malicious }}' }}"
    matches = find_expressions(run_value)
    assert len(matches) == 1
    expr_text, start, end = matches[0]
    assert expr_text == run_value[start:end]
    assert "malicious" in expr_text
    assert classify_expression(extract_expression_body(expr_text)) is Classification.UNTRUSTED


def test_find_expressions_multiple_on_one_line() -> None:
    value = 'echo "${{ github.event.issue.title }}" and ${{ secrets.TOKEN }}'
    matches = find_expressions(value)
    assert len(matches) == 2
    assert matches[0][0] == "${{ github.event.issue.title }}"
    assert value[matches[0][1] : matches[0][2]] == matches[0][0]
    assert classify_expression(extract_expression_body(matches[1][0])) is Classification.TRUSTED


def test_extract_expression_body() -> None:
    assert extract_expression_body("${{  github.event.issue.title  }}") == "github.event.issue.title"
