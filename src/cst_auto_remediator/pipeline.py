"""
Pipeline orchestration for Stages 1–3.

Entry point: remediate_file(path) -> (yaml_string | None, report[]).

MAINTAINER NOTE: When you change this file, update explanation.md at the project root.
"""

from __future__ import annotations

from pathlib import Path

from ruamel.yaml.comments import CommentedMap

from cst_auto_remediator.ingest import ingest
from cst_auto_remediator.models import (
    Action,
    ExpressionSite,
    IngestFailure,
    PlannedPatch,
    ReasonCode,
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
from cst_auto_remediator.traverse import traverse_env_bindings, traverse_jobs
from cst_auto_remediator.validate import is_step_already_remediated, validate_site


def semantic_verify(patched_yaml: str, patched_steps: set[tuple[str, int]]) -> bool:
    """
    Stage 5 Semantic Verification.
    Parses the patched YAML, extracts and classifies all ${{ }} expressions
    in the run blocks of patched steps, and ensures no UNTRUSTED expressions remain.
    """
    from ruamel.yaml import YAML
    from ruamel.yaml.error import YAMLError
    from io import StringIO
    from cst_auto_remediator.classify import classify_expression, extract_expression_body, find_expressions
    from cst_auto_remediator.models import Classification

    try:
        yaml = YAML(typ="rt")
        doc = yaml.load(StringIO(patched_yaml))
        if not isinstance(doc, CommentedMap):
            return False

        jobs = doc.get("jobs")
        if not isinstance(jobs, CommentedMap):
            return True # Syntactically valid GHA without jobs (empty or metadata only)

        for job_id, job in jobs.items():
            if not isinstance(job, CommentedMap):
                continue
            steps = job.get("steps")
            if not isinstance(steps, list):
                continue
            for idx, step in enumerate(steps):
                if not isinstance(step, CommentedMap):
                    continue
                step_key = (str(job_id), idx)
                if step_key in patched_steps:
                    if "run" in step:
                        run_val = str(step["run"])
                        for expr_text, _, _ in find_expressions(run_val):
                            body = extract_expression_body(expr_text)
                            if classify_expression(body) is Classification.UNTRUSTED:
                                return False
        return True
    except YAMLError:
        return False
    except Exception:
        return False


def remediate_file(
    path: str | Path,
    *,
    write_back: bool = False,
) -> tuple[str | None, list[dict]]:
    """
    Run Stages 1–5 on a workflow file.

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

    run_sites = traverse_jobs(document)
    env_sites = traverse_env_bindings(document)

    report_entries: list[ReportEntry] = []
    patches: list[PlannedPatch] = []
    pending_env_names: dict[tuple[str, int], set[str]] = {}
    input_run_lines: set[int] = set()

    run_site_keys = {
        (site.job_id, site.step_index, site.expression_text) for site in run_sites
    }

    for env_site in env_sites:
        step = _get_step(document, env_site)
        if step is None:
            continue
        key = (env_site.job_id, env_site.step_index, env_site.expression_text)
        if key in run_site_keys:
            continue
        if is_step_already_remediated(step, env_site):
            report_entries.append(
                _report_entry(
                    file_path,
                    env_site,
                    ValidationResult(
                        action=Action.SKIPPED,
                        reason=ReasonCode.ALREADY_REMEDIATED,
                    ),
                )
            )

    if not run_sites:
        return original_text, [entry.to_dict() for entry in report_entries]

    # Validate each site in run_sites with job context
    site_results: dict[ExpressionSite, ValidationResult] = {}
    for site in run_sites:
        step = _get_step(document, site)
        if step is None:
            continue

        jobs = document.get("jobs", {})
        job = jobs.get(site.job_id) if isinstance(jobs, CommentedMap) else None
        job_steps = list(job.get("steps")) if isinstance(job, CommentedMap) and isinstance(job.get("steps"), list) else None

        result = validate_site(site, step, pending_env_names, job_steps)
        site_results[site] = result

    # Step-level bailing check: if any expression in a step is BAILED, we bail on the entire step
    by_step_sites: dict[tuple[str, int], list[ExpressionSite]] = {}
    for site in run_sites:
        if site in site_results:
            by_step_sites.setdefault((site.job_id, site.step_index), []).append(site)

    for _step_key, step_sites in by_step_sites.items():
        bailed_site_res = next((site_results[s] for s in step_sites if site_results[s].action is Action.BAILED), None)
        if bailed_site_res is not None:
            for s in step_sites:
                if site_results[s].action is Action.PATCHED:
                    site_results[s] = ValidationResult(
                        action=Action.BAILED,
                        reason=bailed_site_res.reason,
                    )

    # Process validated results
    for site in run_sites:
        if site not in site_results:
            continue
        result = site_results[site]
        report_entries.append(_report_entry(file_path, site, result))

        if result.action is Action.PATCHED and result.env_var_name is not None:
            patches.append(
                PlannedPatch(
                    site=site,
                    env_var_name=result.env_var_name,
                    insert_env=result.insert_env,
                )
            )
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

    # Perform Stage 5 Semantic Verification on memory string first
    patched_steps = {(p.site.job_id, p.site.step_index) for p in patches}
    if not semantic_verify(output_text, patched_steps):
        raise AssertionError("Semantic verification failed: untrusted expressions remain or invalid YAML structure")

    # Perform Stage 5 Atomic Write back if requested
    if write_back:
        import tempfile
        import os

        # Write to temporary file first
        temp_fd, temp_path = tempfile.mkstemp(
            dir=file_path.parent,
            prefix=file_path.name + ".tmp",
        )
        try:
            with os.fdopen(temp_fd, "w", encoding="utf-8", newline="") as f:
                f.write(output_text)
                f.flush()
                os.fsync(f.fileno())

            # Verify temp file contents semantics
            with open(temp_path, "r", encoding="utf-8", newline="") as f:
                temp_content = f.read()
            if not semantic_verify(temp_content, patched_steps):
                raise AssertionError("Semantic verification failed for temp file content")

            # Rename/Replace atomically
            os.replace(temp_path, file_path)
        except Exception as e:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
            raise e

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
        env_var_added=result.env_var_name if result.action is Action.PATCHED else None,
        expression_text=site.expression_text,
        classification=site.classification,
        scalar_type=site.scalar_type,
        start_offset=site.start_offset,
        end_offset=site.end_offset,
    )
