"""
Stage 4 — hardened taint-source classification.

Pure functions: find ${{ ... }} spans (balanced closing) and classify expression
bodies against UNTRUSTED / TRUSTED / AMBIGUOUS rules with obfuscation normalization.

No YAML traversal — see traverse.py for orchestration.

MAINTAINER NOTE: When you change this file, update explanation.md at the project root.
"""

import warnings

warnings.warn(
    "Module cst_auto_remediator.classify is deprecated and will be removed in a future release.",
    DeprecationWarning,
    stacklevel=2,
)

import re

from cst_auto_remediator.models import Classification

_UNTRUSTED_PREFIXES = (
    "github.event.",
)
_UNTRUSTED_EXACT = frozenset({"github.head_ref", "github.base_ref"})
_FROMJSON_INPUTS = re.compile(r"fromJSON\s*\(\s*inputs\.", re.IGNORECASE)

_TRUSTED_PREFIXES = (
    "secrets.",
    "vars.",
)
_TRUSTED_EXACT = frozenset({"github.sha", "github.run_id"})

# Embedded path detection after normalization (format/join/paren/bracket evasion).
_UNTRUSTED_PATH_PATTERN = re.compile(
    r"(?:"
    r"github\.event(?:\.[\w]+|\[\s*['\"][\w]+['\"]\s*\])*"
    r"|github\s*\[\s*['\"]event['\"]\s*\]"
    r"|github\.(?:head_ref|base_ref)\b"
    r"|github\s*\[\s*['\"](?:head_ref|base_ref)['\"]\s*\]"
    r")",
    re.IGNORECASE,
)
_TRUSTED_PATH_PATTERN = re.compile(
    r"(?:"
    r"(?:secrets|vars)\.(?:[\w]+|\[\s*['\"][\w]+['\"]\s*\])+"
    r"|github\.(?:sha|run_id)\b"
    r"|github\s*\[\s*['\"](?:sha|run_id)['\"]\s*\]"
    r")",
    re.IGNORECASE,
)
_AMBIGUOUS_INPUTS_PATTERN = re.compile(r"\binputs\.[\w]+", re.IGNORECASE)
_BRACKET_SEGMENT = re.compile(r"([\w]+)\[\s*['\"]([\w]+)['\"]\s*\]")
_NUMERIC_INDEX = re.compile(r"\[(\d+)\]")


def extract_expression_body(expression_text: str) -> str:
    """Strip the ``${{ ... }}`` wrapper and outer whitespace."""
    inner = expression_text[3:-2] if expression_text.startswith("${{") else expression_text
    return inner.strip()


def _find_expression_close(text: str, start: int) -> int:
    """
    Return the exclusive end index of a ``${{ ... }}`` span starting at *start*.

    Uses balanced ``}}`` scanning so nested ``${{`` inside the body does not
    terminate the match early (double-wrap / string-literal edge class).
    """
    if start + 3 > len(text) or text[start : start + 3] != "${{":
        return -1

    pos = start + 3
    depth = 1
    while pos < len(text):
        if text.startswith("${{", pos):
            depth += 1
            pos += 3
        elif text.startswith("}}", pos):
            depth -= 1
            pos += 2
            if depth == 0:
                return pos
        else:
            pos += 1
    return -1


def find_expressions(value: str) -> list[tuple[str, int, int]]:
    """
    Find all ``${{ ... }}`` spans in *value*.

    Returns a list of (expression_text, start_offset, end_offset) tuples
    relative to *value*. Offsets are byte-accurate across logical lines.
    """
    results: list[tuple[str, int, int]] = []
    offset = 0
    for line in value.splitlines(keepends=True):
        cursor = 0
        while cursor < len(line):
            start = line.find("${{", cursor)
            if start == -1:
                break
            end = _find_expression_close(line, start)
            if end == -1:
                cursor = start + 3
                continue
            results.append(
                (
                    line[start:end],
                    offset + start,
                    offset + end,
                )
            )
            cursor = end
        offset += len(line)
    return results


def _unwrap_balanced_outer_parens(text: str) -> str | None:
    """Return inner text only when parentheses wrap the entire string."""
    stripped = text.strip()
    if not stripped.startswith("("):
        return None
    depth = 0
    for index, char in enumerate(stripped):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                if index == len(stripped) - 1:
                    return stripped[1:-1].strip()
                return None
    return None


def _strip_inline_path_parens(text: str) -> str:
    """Remove parens wrapping a ``github.*`` path segment: ``(github.event).x``."""
    pattern = re.compile(r"\(\s*(github\.[\w.]+)\s*\)")
    previous = None
    while previous != text:
        previous = text
        text = pattern.sub(r"\1", text)
    return text


def normalize_for_classification(body: str) -> str:
    """
    Canonicalize an expression body for deterministic prefix / path matching.

    Handles parenthetical wrapping, bracket property access, and numeric indices
    without altering string-literal contents beyond bracket-to-dot conversion on
    identifier paths.
    """
    text = body.strip()

    while True:
        inner = _unwrap_balanced_outer_parens(text)
        if inner is None:
            break
        text = inner

    text = _strip_inline_path_parens(text)

    previous = None
    while previous != text:
        previous = text
        text = _BRACKET_SEGMENT.sub(r"\1.\2", text)
    text = _NUMERIC_INDEX.sub(r".\1", text)
    return text


def _contains_untrusted_path(text: str) -> bool:
    normalized = normalize_for_classification(text)
    compact = re.sub(r"\s+", "", normalized)

    for prefix in _UNTRUSTED_PREFIXES:
        if compact.startswith(prefix) or f".{prefix}" in compact:
            return True
    if compact in _UNTRUSTED_EXACT:
        return True
    if _FROMJSON_INPUTS.search(compact):
        return True
    if _UNTRUSTED_PATH_PATTERN.search(normalized):
        return True
    return False


def _contains_trusted_path(text: str) -> bool:
    normalized = normalize_for_classification(text)
    if _TRUSTED_PATH_PATTERN.search(normalized):
        return True
    compact = re.sub(r"\s+", "", normalized)
    for prefix in _TRUSTED_PREFIXES:
        if compact.startswith(prefix):
            return True
    if compact in _TRUSTED_EXACT:
        return True
    return False


def classify_expression(expression_body: str) -> Classification:
    """
    Classify a single expression body using hardened Stage 4 rules.

    Order (bailout-first for ambiguous workflow inputs):

    1. UNTRUSTED — direct prefix, fromJSON(inputs.*), or embedded github.event /
       head_ref / base_ref after normalization (parens, brackets, format wrappers).
    2. TRUSTED — secrets.*, vars.*, github.sha, github.run_id (no untrusted paths).
    3. AMBIGUOUS — everything else (including bare ``inputs.*`` per architecture).
    """
    body = expression_body.strip()
    normalized = normalize_for_classification(body)

    if _contains_untrusted_path(body):
        return Classification.UNTRUSTED

    for prefix in _UNTRUSTED_PREFIXES:
        if normalized.startswith(prefix):
            return Classification.UNTRUSTED
    if normalized in _UNTRUSTED_EXACT:
        return Classification.UNTRUSTED
    if _FROMJSON_INPUTS.search(normalized):
        return Classification.UNTRUSTED

    if _contains_trusted_path(body):
        return Classification.TRUSTED

    for prefix in _TRUSTED_PREFIXES:
        if normalized.startswith(prefix):
            return Classification.TRUSTED
    if normalized in _TRUSTED_EXACT:
        return Classification.TRUSTED

    return Classification.AMBIGUOUS
