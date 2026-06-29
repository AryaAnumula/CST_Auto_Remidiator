"""
Stage 3 — deterministic validation rule chain.

Decides PATCHED / SKIPPED / BAILED per ExpressionSite (sinks, collisions, scope).
Does not mutate files — see mutate.py.

MAINTAINER NOTE: When you change this file, update explanation.md at the project root.
"""

import warnings

warnings.warn(
    "Module cst_auto_remediator.validate is deprecated and will be removed in a future release.",
    DeprecationWarning,
    stacklevel=2,
)

import re
from ruamel.yaml.comments import CommentedMap

from cst_auto_remediator.models import (
    Action,
    Classification,
    ExpressionSite,
    ReasonCode,
    ScalarType,
    ValidationResult,
)

_EVAL_PATTERN = re.compile(r"\beval\b")
_BASH_C_PATTERN = re.compile(r"\bbash\s+-c\b")
_SH_C_PATTERN = re.compile(r"\bsh\s+-c\b")


def generate_env_var_name(expression_body: str) -> str:
    """Derive a safe env var name from an expression body."""
    body = expression_body.strip()

    if body.startswith("github.event."):
        remainder = body[len("github.event.") :]
        return remainder.replace(".", "_").upper()

    if body.startswith("github."):
        remainder = body[len("github.") :]
        return remainder.replace(".", "_").upper()

    fromjson_match = re.match(r"fromJSON\s*\(\s*inputs\.(.+?)\s*\)", body, re.IGNORECASE)
    if fromjson_match:
        return fromjson_match.group(1).replace(".", "_").upper()

    # Fallback for unexpected untrusted bodies — should not reach mutator.
    sanitized = re.sub(r"[^A-Za-z0-9_]", "_", body)
    return sanitized.upper()


def _find_dollar_paren_regions(text: str) -> list[tuple[int, int]]:
    regions: list[tuple[int, int]] = []
    index = 0
    while index < len(text):
        if text[index : index + 2] == "$(":
            depth = 1
            cursor = index + 2
            while cursor < len(text) and depth > 0:
                if text[cursor : cursor + 2] == "$(":
                    depth += 1
                    cursor += 2
                elif text[cursor] == ")":
                    depth -= 1
                    cursor += 1
                else:
                    cursor += 1
            regions.append((index, cursor))
            index = cursor
        else:
            index += 1
    return regions


def _find_backtick_regions(text: str) -> list[tuple[int, int]]:
    regions: list[tuple[int, int]] = []
    index = 0
    while index < len(text):
        if text[index] == "`":
            cursor = index + 1
            while cursor < len(text) and text[cursor] != "`":
                cursor += 1
            if cursor < len(text):
                regions.append((index, cursor + 1))
                cursor += 1
            index = cursor
        else:
            index += 1
    return regions


def _argument_region_after(text: str, start: int) -> tuple[int, int]:
    """Return the span of the shell argument beginning at *start*."""
    if start >= len(text):
        return start, start

    quote = text[start]
    if quote in "\"'":
        cursor = start + 1
        while cursor < len(text):
            if text[cursor] == "\\" and cursor + 1 < len(text):
                cursor += 2
                continue
            if text[cursor] == quote:
                return start, cursor + 1
            cursor += 1
        return start, len(text)

    return start, len(text)


def _expression_in_region(start: int, end: int, region: tuple[int, int]) -> bool:
    return region[0] <= start and end <= region[1]


def detect_sink(run_value: str, start: int, end: int) -> ReasonCode | None:
    """Return a sink reason if the expression span sits inside a dangerous construct."""
    for region in _find_dollar_paren_regions(run_value) + _find_backtick_regions(run_value):
        if _expression_in_region(start, end, region):
            return ReasonCode.SINK_COMMAND_SUBSTITUTION

    for match in _EVAL_PATTERN.finditer(run_value):
        arg_start = match.end()
        whitespace = re.match(r"\s*", run_value[arg_start:])
        arg_begin = arg_start + (whitespace.end() if whitespace else 0)
        arg_region = _argument_region_after(run_value, arg_begin)
        if _expression_in_region(start, end, arg_region):
            return ReasonCode.SINK_EVAL

    for match in _BASH_C_PATTERN.finditer(run_value):
        arg_start = match.end()
        whitespace = re.match(r"\s*", run_value[arg_start:])
        arg_begin = arg_start + (whitespace.end() if whitespace else 0)
        arg_region = _argument_region_after(run_value, arg_begin)
        if _expression_in_region(start, end, arg_region):
            return ReasonCode.SINK_BASH_C

    for match in _SH_C_PATTERN.finditer(run_value):
        arg_start = match.end()
        whitespace = re.match(r"\s*", run_value[arg_start:])
        arg_begin = arg_start + (whitespace.end() if whitespace else 0)
        arg_region = _argument_region_after(run_value, arg_begin)
        if _expression_in_region(start, end, arg_region):
            return ReasonCode.SINK_SH_C

    return None


def is_inside_single_quotes(run_value: str, start: int, end: int) -> bool:
    """Return True when the expression span lies inside a single-quoted region."""
    in_single = False
    in_double = False
    region_start = 0
    cursor = 0
    while cursor < len(run_value):
        char = run_value[cursor]
        if char == "\\" and (in_single or in_double) and cursor + 1 < len(run_value):
            cursor += 2
            continue
        if char == "'" and not in_double:
            if not in_single:
                region_start = cursor
                in_single = True
            else:
                if _expression_in_region(start, end, (region_start, cursor + 1)):
                    return True
                in_single = False
        elif char == '"' and not in_single:
            in_double = not in_double
        cursor += 1
    return False


def _existing_env_keys(step: CommentedMap) -> set[str]:
    env = step.get("env")
    if not isinstance(env, CommentedMap):
        return set()
    return {str(key).upper() for key in env.keys()}


def env_var_for_expression(step: CommentedMap, expression_text: str) -> str | None:
    """Return the env key whose value equals *expression_text*, if any."""
    env = step.get("env")
    if not isinstance(env, CommentedMap):
        return None
    for key, value in env.items():
        if str(value).strip() == expression_text.strip():
            return str(key)
    return None


def run_references_env_var(run_value: str, env_var_name: str) -> bool:
    """Return True when *run_value* references ``$env_var_name`` as a shell variable."""
    return f"${env_var_name}" in run_value


def is_step_already_remediated(step: CommentedMap, env_site: ExpressionSite) -> bool:
    """
    True when *env_site* binds an UNTRUSTED expression in env: and run: uses ``$VAR``
    without embedding the same ``${{ ... }}`` expression text.
    """
    if "run" not in step:
        return False
    run_text = str(step["run"])
    if env_site.expression_text in run_text:
        return False
    bound_name = env_var_for_expression(step, env_site.expression_text)
    if bound_name is None:
        return False
    return run_references_env_var(run_text, bound_name)


def validate_site(
    site: ExpressionSite,
    step: CommentedMap,
    pending_env_names: dict[tuple[str, int], set[str]],
    job_steps: list[CommentedMap] | None = None,
) -> ValidationResult:
    """Apply the Stage 3/4 rule chain to a single expression site."""
    step_key = (site.job_id, site.step_index)

    if site.scalar_type is ScalarType.BLOCK:
        return ValidationResult(
            action=Action.SKIPPED,
            reason=ReasonCode.BLOCK_SCALAR_OUT_OF_SCOPE,
        )

    if site.classification is Classification.TRUSTED:
        return ValidationResult(action=Action.SKIPPED, reason=ReasonCode.TRUSTED)

    if site.classification is Classification.AMBIGUOUS:
        return ValidationResult(
            action=Action.SKIPPED,
            reason=ReasonCode.AMBIGUOUS_EXPRESSION,
        )

    sink = detect_sink(site.run_value, site.start_offset, site.end_offset)
    if sink is not None:
        return ValidationResult(action=Action.BAILED, reason=sink)

    if is_inside_single_quotes(site.run_value, site.start_offset, site.end_offset):
        return ValidationResult(
            action=Action.SKIPPED,
            reason=ReasonCode.SINGLE_QUOTED_EXPRESSION,
        )

    existing_binding = env_var_for_expression(step, site.expression_text)
    if existing_binding is not None:
        return ValidationResult(
            action=Action.PATCHED,
            env_var_name=existing_binding,
            insert_env=False,
        )

    env_name = generate_env_var_name(site.expression_body)
    
    # Check for name collisions across all steps in the job if job_steps is available
    existing = set()
    if job_steps is not None:
        for s in job_steps:
            if isinstance(s, CommentedMap):
                env = s.get("env")
                if isinstance(env, CommentedMap):
                    for key in env.keys():
                        existing.add(str(key).upper())
    else:
        existing = _existing_env_keys(step)

    if env_name.upper() in existing:
        return ValidationResult(
            action=Action.BAILED,
            reason=ReasonCode.ENV_NAME_COLLISION,
        )

    used = pending_env_names.setdefault(step_key, set())
    if env_name.upper() in used:
        return ValidationResult(
            action=Action.BAILED,
            reason=ReasonCode.GENERATED_NAME_COLLISION,
        )

    used.add(env_name.upper())
    return ValidationResult(action=Action.PATCHED, env_var_name=env_name, insert_env=True)
