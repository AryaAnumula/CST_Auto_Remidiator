"""Pipeline orchestration for Stages 1–3."""

from __future__ import annotations

from pathlib import Path

from ruamel.yaml.comments import CommentedMap

from cst_auto_remediator.ingest import ingest
from cst_auto_remediator.models import (
    Action,
    ExpressionSite,
    IngestFailure,
    PlannedPatch,
    ReportEntry,
    ValidationResult,
)
from cst_auto_remediator.mutate import (
    apply_patches,
    assert_byte_preservation,
    build_patched_text,
    find_run_line_indices,
    serialize_document,
)
from cst_auto_remediator.traverse import traverse_jobs
from cst_auto_remediator.validate import validate_site


def remediate_file(path: str | Path) -> tuple[str | None, list[dict]]:
    """
    Run Stages 1–3 on a workflow file.

    Returns ``(yaml_output, report)`` where *yaml_output* is ``None`` on
    Stage 1 ingest failure, and *report* is a list of JSON-serializable dicts.
    """
    file_path = Path(path)
    ingest_result = ingest(file_path)

    if isinstance(ingest_result, IngestFailure):
        return None, [
            ReportEntry(
                file=_report_file_path(file_path),
                action=Action.BAILED,
                reason=ingest_result.reason,
            ).to_dict()
        ]

    document = ingest_result.document
    metadata = ingest_result.metadata
    original_text = ingest_result.source_text

    sites = traverse_jobs(document)
    if not sites:
        return original_text, []

    report_entries: list[ReportEntry] = []
    patches: list[PlannedPatch] = []
    pending_env_names: dict[tuple[str, int], set[str]] = {}
    input_run_lines: set[int] = set()

    for site in sites:
        step = _get_step(document, site)
        if step is None:
            continue

        result = validate_site(site, step, pending_env_names)
        report_entries.append(_report_entry(file_path, site, result))

        if result.action is Action.PATCHED and result.env_var_name is not None:
            patches.append(PlannedPatch(site=site, env_var_name=result.env_var_name))
            input_run_lines |= find_run_line_indices(original_text, site.expression_text)

    if not patches:
        return original_text, [entry.to_dict() for entry in report_entries]

    apply_patches(document, patches)
    _ = serialize_document(document)

    output_text, input_run_lines, output_excluded = build_patched_text(
        original_text,
        patches,
        metadata.line_ending,
    )
    assert_byte_preservation(original_text, output_text, input_run_lines, output_excluded)

    return output_text, [entry.to_dict() for entry in report_entries]


def _report_file_path(file_path: Path) -> str:
    try:
        return file_path.relative_to(Path.cwd()).as_posix()
    except ValueError:
        return file_path.as_posix()


def _get_step(document: CommentedMap, site: ExpressionSite) -> CommentedMap | None:
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


def _report_entry(
    file_path: Path,
    site: ExpressionSite,
    result: ValidationResult,
) -> ReportEntry:
    return ReportEntry(
        file=_report_file_path(file_path),
        job_id=site.job_id,
        step=site.step_index,
        step_id=site.step_id,
        action=result.action,
        reason=result.reason,
        env_var_added=result.env_var_name,
        expression_text=site.expression_text,
        classification=site.classification,
        scalar_type=site.scalar_type,
        start_offset=site.start_offset,
        end_offset=site.end_offset,
    )
