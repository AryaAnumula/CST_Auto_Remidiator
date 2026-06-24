"""Stage 3 — CST-aware mutation and round-trip serialization."""

from __future__ import annotations

from io import StringIO

from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.scalarstring import (
    DoubleQuotedScalarString,
    FoldedScalarString,
    LiteralScalarString,
    PlainScalarString,
    SingleQuotedScalarString,
)

from cst_auto_remediator.ingest import create_yaml_dumper
from cst_auto_remediator.models import PlannedPatch


def _preserve_scalar_type(original: object, new_text: str) -> object:
    if isinstance(original, DoubleQuotedScalarString):
        return DoubleQuotedScalarString(new_text)
    if isinstance(original, SingleQuotedScalarString):
        return SingleQuotedScalarString(new_text)
    if isinstance(original, PlainScalarString):
        return PlainScalarString(new_text)
    if isinstance(original, LiteralScalarString):
        return LiteralScalarString(new_text)
    if isinstance(original, FoldedScalarString):
        return FoldedScalarString(new_text)
    return new_text


def _get_step(document: CommentedMap, site) -> CommentedMap | None:
    jobs = document.get("jobs")
    if not isinstance(jobs, CommentedMap):
        return None
    job = jobs.get(site.job_id)
    if not isinstance(job, CommentedMap):
        return None
    steps = job.get("steps")
    if not isinstance(steps, list):
        return None
    if site.step_index >= len(steps):
        return None
    step = steps[site.step_index]
    if not isinstance(step, CommentedMap):
        return None
    return step


def apply_patches(document: CommentedMap, patches: list[PlannedPatch]) -> None:
    """Apply env insertions and run-value replacements in-place on the CST."""
    by_step: dict[tuple[str, int], list[PlannedPatch]] = {}
    for patch in patches:
        key = (patch.site.job_id, patch.site.step_index)
        by_step.setdefault(key, []).append(patch)

    for _step_key, step_patches in by_step.items():
        site = step_patches[0].site
        step = _get_step(document, site)
        if step is None:
            continue

        env = step.get("env")
        if not isinstance(env, CommentedMap):
            env = CommentedMap()

        keys = list(step.keys())
        if "run" in keys:
            run_index = keys.index("run")
            if "env" not in step:
                step.insert(run_index, "env", env)
        elif "env" not in step:
            step["env"] = env

        env = step["env"]
        for patch in step_patches:
            env[patch.env_var_name] = patch.site.expression_text

        run_original = step["run"]
        run_text = str(run_original)
        for patch in sorted(
            step_patches,
            key=lambda p: p.site.start_offset,
            reverse=True,
        ):
            replacement = f"${patch.env_var_name}"
            run_text = (
                run_text[: patch.site.start_offset]
                + replacement
                + run_text[patch.site.end_offset :]
            )
        step["run"] = _preserve_scalar_type(run_original, run_text)


def serialize_document(document: CommentedMap) -> str:
    """Round-trip serialize the CST via ruamel (used to validate dumpability)."""
    yaml = create_yaml_dumper()
    stream = StringIO()
    yaml.dump(document, stream)
    return stream.getvalue()


def find_run_line_indices(text: str, expression_text: str) -> set[int]:
    """Locate 0-based line indices whose ``run:`` line contains *expression_text*."""
    indices: set[int] = set()
    for index, line in enumerate(text.splitlines()):
        if "run:" in line and expression_text in line:
            indices.add(index)
    return indices


def build_patched_text(
    original_text: str,
    patches: list[PlannedPatch],
    line_ending: str,
) -> tuple[str, set[int], set[int]]:
    """
    Apply patches to *original_text* while preserving untouched bytes.

    Inserts ``env:`` immediately before the patched ``run:`` line and replaces
    only each ``${{ ... }}`` span on that line. New lines use *line_ending*.
    """
    lines = original_text.splitlines(keepends=True)
    if not lines and original_text:
        lines = [original_text]

    by_run_line: dict[int, list[PlannedPatch]] = {}
    for patch in patches:
        indices = find_run_line_indices(original_text, patch.site.expression_text)
        if not indices:
            continue
        by_run_line.setdefault(min(indices), []).append(patch)

    input_run_indices = set(by_run_line.keys())
    output_excluded: set[int] = set()

    for run_idx in sorted(by_run_line.keys(), reverse=True):
        step_patches = by_run_line[run_idx]
        run_line = lines[run_idx]
        indent = run_line[: len(run_line) - len(run_line.lstrip())]

        new_run_line = run_line
        for patch in sorted(
            step_patches,
            key=lambda p: new_run_line.index(p.site.expression_text),
            reverse=True,
        ):
            expr = patch.site.expression_text
            position = new_run_line.index(expr)
            new_run_line = (
                new_run_line[:position]
                + f"${patch.env_var_name}"
                + new_run_line[position + len(expr) :]
            )

        env_lines = [f"{indent}env:{line_ending}"]
        for patch in step_patches:
            env_lines.append(
                f"{indent}  {patch.env_var_name}: {patch.site.expression_text}{line_ending}"
            )

        lines[run_idx : run_idx + 1] = env_lines + [new_run_line]

        env_start = run_idx
        env_end = run_idx + len(env_lines)
        run_line_idx = env_end

        output_excluded.update(range(env_start, env_end))
        output_excluded.add(run_line_idx)

    output_text = "".join(lines)
    return output_text, input_run_indices, output_excluded


def assert_byte_preservation(
    original_text: str,
    output_text: str,
    input_run_line_indices: set[int],
    output_excluded_line_indices: set[int],
) -> None:
    """
    Assert every line not intentionally edited remains byte-identical.

    Lines excluded from the original are those whose ``run:`` values are
    patched. Lines excluded from the output are modified ``run:`` lines and
    newly inserted ``env:`` block lines.
    """
    original_lines = original_text.splitlines()
    output_lines = output_text.splitlines()

    original_kept = [
        line for index, line in enumerate(original_lines) if index not in input_run_line_indices
    ]
    output_kept = [
        line
        for index, line in enumerate(output_lines)
        if index not in output_excluded_line_indices
    ]

    if original_kept != output_kept:
        diff_index = next(
            (i for i, (a, b) in enumerate(zip(original_kept, output_kept)) if a != b),
            min(len(original_kept), len(output_kept)),
        )
        raise AssertionError(
            "Byte-preservation check failed: "
            f"unchanged lines differ at kept-line index {diff_index}"
        )

    if len(original_kept) != len(output_kept):
        raise AssertionError(
            "Byte-preservation check failed: "
            f"kept line count differs ({len(original_kept)} vs {len(output_kept)})"
        )
