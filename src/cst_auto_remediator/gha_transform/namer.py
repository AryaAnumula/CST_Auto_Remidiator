"""
Stage 6 - Deterministic environment variable naming.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable

from cst_auto_remediator.gha_metadata.nodes import ScopeMetadata

_PATH_PATTERN = re.compile(
    r"\b(?:github|secrets|vars|runner|inputs|matrix|env|needs)(?:\.[\w-]+|\[\s*['\"][\w-]+['\"]\s*\])+",
    re.IGNORECASE,
)
_BRACKET_PATTERN = re.compile(r"\[\s*['\"]([\w-]+)['\"]\s*\]")
_FROM_JSON_INPUT_PATTERN = re.compile(
    r"fromJSON\s*\(\s*inputs\.([A-Za-z0-9_.-]+)\s*\)",
    re.IGNORECASE,
)


def _extract_expression_body(expression_text: str) -> str:
    body = expression_text.strip()
    if body.startswith("${{") and body.endswith("}}"):
        return body[3:-2].strip()
    return body


def _candidate_source(expression_body: str) -> str:
    from_json_match = _FROM_JSON_INPUT_PATTERN.search(expression_body)
    if from_json_match:
        return from_json_match.group(1)

    path_match = _PATH_PATTERN.search(expression_body)
    if not path_match:
        return expression_body

    path = _BRACKET_PATTERN.sub(r".\1", path_match.group(0)).lower()
    for prefix in (
        "github.event.",
        "github.",
        "inputs.",
        "matrix.",
        "env.",
        "vars.",
        "secrets.",
        "needs.",
        "runner.",
    ):
        if path.startswith(prefix):
            return path[len(prefix) :]
    return path


def _to_posix_screaming_snake(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_]+", "_", value)
    normalized = re.sub(r"_+", "_", normalized).strip("_").upper()
    if not normalized:
        normalized = "EXPR"
    if normalized[0].isdigit():
        normalized = f"EXPR_{normalized}"
    return normalized


def _truncate_name(name: str, max_length: int) -> str:
    if len(name) <= max_length:
        return name
    return name[:max_length].rstrip("_") or "EXPR"


def _collision_set(scope: ScopeMetadata, reserved_names: Iterable[str]) -> set[str]:
    visible_names = {name.upper() for name in scope.env}
    visible_names.update(name.upper() for name in reserved_names)
    return visible_names


def gen_safe_var_name(
    expression_text: str,
    scope: ScopeMetadata,
    *,
    reserved_names: Iterable[str] = (),
    max_length: int = 40,
) -> str:
    """
    Generate a deterministic POSIX-safe env var name for an expression.

    Collisions are checked against ScopeMetadata.env plus any caller-provided
    in-plan names. The suffix is derived only from stable input text.
    """
    if max_length < 10:
        raise ValueError("max_length must be at least 10 to allow hash suffixes")

    expression_body = _extract_expression_body(expression_text)
    base = _truncate_name(_to_posix_screaming_snake(_candidate_source(expression_body)), max_length)

    collisions = _collision_set(scope, reserved_names)
    if base.upper() not in collisions:
        return base

    digest_input = f"{expression_body}|{base}".encode("utf-8")
    suffix = hashlib.sha256(digest_input).hexdigest()[:8].upper()
    prefix_limit = max_length - len(suffix) - 1
    prefix = _truncate_name(base, prefix_limit)
    return f"{prefix}_{suffix}"
