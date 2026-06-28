"""
Stage 5 — GitHub Actions Security Analysis Classifier.

Implements trust and source context classification rules based on V1 threat model.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from cst_auto_remediator.gha_analysis.nodes import TrustLevel, SourceKind, SinkKind

if TYPE_CHECKING:
    from cst_auto_remediator.gha_metadata.nodes import ScopeMetadata

# Matches GHA contexts and paths: github.event.issue.title, env.VAR, secrets.X, etc.
_PATH_PATTERN = re.compile(
    r"\b(github|secrets|vars|runner|inputs|matrix|env|needs)(?:\.[\w-]+|\[\s*['\"][\w-]+['\"]\s*\])+",
    re.IGNORECASE,
)

# Bracket replacement helper
_BRACKET_PATTERN = re.compile(r"\[\s*['\"]([\w-]+)['\"]\s*\]")


def normalize_path(path_str: str) -> str:
    """Normalize brackets to dots and convert to lowercase for prefix checks."""
    normalized = _BRACKET_PATTERN.sub(r".\1", path_str)
    return normalized.lower()


def extract_paths(expr_body: str) -> list[str]:
    """Find all context paths inside the expression body."""
    matches = _PATH_PATTERN.findall(expr_body)
    # The findall returns only the first group if we have groups, let's get whole matches instead.
    # To do that, we find iterators.
    results = []
    for match in _PATH_PATTERN.finditer(expr_body):
        results.append(match.group(0))
    return results


def classify_single_path(normalized_path: str, scope: ScopeMetadata | None) -> tuple[TrustLevel, SourceKind]:
    """Determine trust level and source kind for a single normalized dot-path."""
    if normalized_path.startswith("github.event.") or normalized_path.startswith("github.event["):
        return TrustLevel.UNTRUSTED, SourceKind.GITHUB_CONTEXT
    if normalized_path in ("github.head_ref", "github.base_ref"):
        return TrustLevel.UNTRUSTED, SourceKind.GITHUB_CONTEXT
    if normalized_path in ("github.repository", "github.workflow", "github.sha", "github.run_id"):
        return TrustLevel.TRUSTED, SourceKind.GITHUB_CONTEXT
    if normalized_path.startswith("github."):
        return TrustLevel.UNKNOWN, SourceKind.GITHUB_CONTEXT

    if normalized_path.startswith("runner."):
        return TrustLevel.TRUSTED, SourceKind.GITHUB_CONTEXT

    if normalized_path.startswith("secrets."):
        return TrustLevel.TRUSTED, SourceKind.SECRET

    if normalized_path.startswith("vars."):
        return TrustLevel.TRUSTED, SourceKind.VARS

    if normalized_path.startswith("inputs."):
        return TrustLevel.UNTRUSTED, SourceKind.INPUTS

    if normalized_path.startswith("matrix."):
        return TrustLevel.UNTRUSTED, SourceKind.MATRIX

    if normalized_path.startswith("needs."):
        return TrustLevel.UNKNOWN, SourceKind.NEEDS

    if normalized_path.startswith("env."):
        var_name = normalized_path[4:]
        trust = classify_env_variable(var_name, scope)
        return trust, SourceKind.ENVIRONMENT

    return TrustLevel.UNKNOWN, SourceKind.UNKNOWN


def classify_env_variable(var_name: str, scope: ScopeMetadata | None) -> TrustLevel:
    """
    Perform analytical data-flow classification on environment variables.
    If the variable matches a declared env key, check if its value contains
    any untrusted expression. If so, propagate the UNTRUSTED status (taint tracking).
    """
    if scope is None or var_name not in scope.env:
        return TrustLevel.UNKNOWN

    val_node = scope.env[var_name]
    val_text = val_node.value
    if not isinstance(val_text, str):
        return TrustLevel.TRUSTED  # Literal non-string is safe

    # Recursively check expression sites inside the variable declaration
    from cst_auto_remediator.gha_semantic.scanner import extract_expression_sites
    sites = extract_expression_sites(val_node)
    if not sites:
        return TrustLevel.TRUSTED  # Static string is safe

    # Classify nested sites
    untrusted_found = False
    unknown_found = False
    for site in sites:
        sub_paths = extract_paths(site.expression_body)
        for p in sub_paths:
            p_norm = normalize_path(p)
            # Avoid infinite recursion if env.A references env.A (should not occur in valid yaml)
            if p_norm.startswith("env.") and p_norm[4:] == var_name:
                continue
            sub_trust, _ = classify_single_path(p_norm, scope.parent_scope)
            if sub_trust is TrustLevel.UNTRUSTED or sub_trust is TrustLevel.MIXED:
                untrusted_found = True
            elif sub_trust is TrustLevel.UNKNOWN:
                unknown_found = True

    if untrusted_found:
        return TrustLevel.UNTRUSTED
    if unknown_found:
        return TrustLevel.UNKNOWN
    return TrustLevel.TRUSTED


def classify_expression(expr_body: str, scope: ScopeMetadata | None) -> tuple[TrustLevel, SourceKind]:
    """
    Classify the trust level and dominant source kind of an expression body.
    Handles multiple nested or concatenated path targets.
    """
    paths = extract_paths(expr_body)
    if not paths:
        # If there are no context paths, it is classified as a literal
        return TrustLevel.TRUSTED, SourceKind.LITERAL

    trust_set = set()
    source_kinds = set()

    for p in paths:
        norm = normalize_path(p)
        t, s = classify_single_path(norm, scope)
        trust_set.add(t)
        source_kinds.add(s)

    # Determine overall trust level
    if TrustLevel.UNTRUSTED in trust_set:
        if TrustLevel.TRUSTED in trust_set:
            overall_trust = TrustLevel.MIXED
        else:
            overall_trust = TrustLevel.UNTRUSTED
    elif TrustLevel.UNKNOWN in trust_set:
        overall_trust = TrustLevel.UNKNOWN
    else:
        overall_trust = TrustLevel.TRUSTED

    # Determine dominant source kind
    if len(source_kinds) == 1:
        dominant_source = list(source_kinds)[0]
    elif len(source_kinds) > 1:
        # If mixed, pick the first non-literal kind, or default to GITHUB_CONTEXT
        non_literals = [s for s in source_kinds if s is not SourceKind.LITERAL]
        dominant_source = non_literals[0] if non_literals else SourceKind.GITHUB_CONTEXT
    else:
        dominant_source = SourceKind.UNKNOWN

    return overall_trust, dominant_source
