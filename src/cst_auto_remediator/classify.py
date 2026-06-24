"""
Stage 2 — deterministic expression taint classification.

Pure functions only: find ${{ ... }} spans and classify expression bodies.
No YAML traversal — see traverse.py for orchestration.

MAINTAINER NOTE: When you change this file, update explanation.md at the project root.
"""

from __future__ import annotations

import re

from cst_auto_remediator.models import Classification

_EXPRESSION_PATTERN = re.compile(r"\$\{\{.*?\}\}")

_UNTRUSTED_PREFIXES = (
    "github.event.",
)
_UNTRUSTED_EXACT = frozenset({"github.head_ref", "github.base_ref"})
_FROMJSON_INPUTS = re.compile(r"^fromJSON\s*\(\s*inputs\.", re.IGNORECASE)

_TRUSTED_PREFIXES = (
    "secrets.",
    "vars.",
)
_TRUSTED_EXACT = frozenset({"github.sha", "github.run_id"})


def extract_expression_body(expression_text: str) -> str:
    """Strip the ``${{ ... }}`` wrapper and outer whitespace."""
    inner = expression_text[3:-2] if expression_text.startswith("${{") else expression_text
    return inner.strip()


def find_expressions(value: str) -> list[tuple[str, int, int]]:
    """
    Find all ``${{ ... }}`` spans on the same logical line.

    Returns a list of (expression_text, start_offset, end_offset) tuples
    relative to *value*.
    """
    results: list[tuple[str, int, int]] = []
    offset = 0
    for line in value.splitlines(keepends=True):
        for match in _EXPRESSION_PATTERN.finditer(line):
            results.append(
                (
                    match.group(0),
                    offset + match.start(),
                    offset + match.end(),
                )
            )
        offset += len(line)
    return results


def classify_expression(expression_body: str) -> Classification:
    """Classify a single expression body using prefix / exact rules."""
    body = expression_body.strip()

    for prefix in _UNTRUSTED_PREFIXES:
        if body.startswith(prefix):
            return Classification.UNTRUSTED
    if body in _UNTRUSTED_EXACT:
        return Classification.UNTRUSTED
    if _FROMJSON_INPUTS.match(body):
        return Classification.UNTRUSTED

    for prefix in _TRUSTED_PREFIXES:
        if body.startswith(prefix):
            return Classification.TRUSTED
    if body in _TRUSTED_EXACT:
        return Classification.TRUSTED

    return Classification.AMBIGUOUS
