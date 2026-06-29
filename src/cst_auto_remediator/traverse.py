"""
Stage 2 — depth-first traversal to locate expression sites.

Walks jobs.<job_id>.steps[].run and builds ExpressionSite objects by delegating
scan/classify work to classify.py. Also scans step env: values for audit reporting
of already-remediated workflows.

MAINTAINER NOTE: When you change this file, update explanation.md at the project root.
"""

import warnings

warnings.warn(
    "Module cst_auto_remediator.traverse is deprecated and will be removed in a future release.",
    DeprecationWarning,
    stacklevel=2,
)

from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.scalarstring import FoldedScalarString, LiteralScalarString

from cst_auto_remediator.classify import (
    classify_expression,
    extract_expression_body,
    find_expressions,
)
from cst_auto_remediator.models import Classification, ExpressionSite, ScalarType


def _scalar_type(value: object) -> ScalarType:
    if isinstance(value, (LiteralScalarString, FoldedScalarString)):
        return ScalarType.BLOCK
    return ScalarType.PLAIN


def _string_value(value: object) -> str:
    return str(value)


def _collect_sites_from_text(
    *,
    job_id: str,
    step_index: int,
    step_id: str | None,
    text: str,
    scalar: ScalarType,
) -> list[ExpressionSite]:
    sites: list[ExpressionSite] = []
    for expr_text, start, end in find_expressions(text):
        body = extract_expression_body(expr_text)
        sites.append(
            ExpressionSite(
                job_id=job_id,
                step_index=step_index,
                step_id=step_id,
                expression_text=expr_text,
                expression_body=body,
                classification=classify_expression(body),
                scalar_type=scalar,
                start_offset=start,
                end_offset=end,
                run_value=text,
            )
        )
    return sites


def traverse_jobs(document: object) -> list[ExpressionSite]:
    """Walk ``jobs.<job_id>.steps[].run`` and collect expression sites in run scalars."""
    if not isinstance(document, CommentedMap):
        return []

    jobs = document.get("jobs")
    if not isinstance(jobs, CommentedMap):
        return []

    sites: list[ExpressionSite] = []
    for job_id, job in jobs.items():
        if not isinstance(job, CommentedMap):
            continue
        steps = job.get("steps")
        if not isinstance(steps, CommentedSeq):
            continue
        for step_index, step in enumerate(steps):
            if not isinstance(step, CommentedMap):
                continue
            if "run" not in step:
                continue
            run_value = step["run"]
            scalar = _scalar_type(run_value)
            run_text = _string_value(run_value)
            step_id = step.get("id")
            step_id_str = str(step_id) if step_id is not None else None

            sites.extend(
                _collect_sites_from_text(
                    job_id=str(job_id),
                    step_index=step_index,
                    step_id=step_id_str,
                    text=run_text,
                    scalar=scalar,
                )
            )

    return sites


def traverse_env_bindings(document: object) -> list[ExpressionSite]:
    """
    Walk ``jobs.<job_id>.steps[].env`` values and collect UNTRUSTED expression sites.

    Used to detect workflows that already bind untrusted data in env: and reference
    it from run: via ``$VAR`` (no mutation — audit/report only).
    """
    if not isinstance(document, CommentedMap):
        return []

    jobs = document.get("jobs")
    if not isinstance(jobs, CommentedMap):
        return []

    sites: list[ExpressionSite] = []
    for job_id, job in jobs.items():
        if not isinstance(job, CommentedMap):
            continue
        steps = job.get("steps")
        if not isinstance(steps, CommentedSeq):
            continue
        for step_index, step in enumerate(steps):
            if not isinstance(step, CommentedMap):
                continue
            env = step.get("env")
            if not isinstance(env, CommentedMap):
                continue
            step_id = step.get("id")
            step_id_str = str(step_id) if step_id is not None else None

            for _env_key, env_value in env.items():
                env_text = _string_value(env_value)
                for site in _collect_sites_from_text(
                    job_id=str(job_id),
                    step_index=step_index,
                    step_id=step_id_str,
                    text=env_text,
                    scalar=ScalarType.PLAIN,
                ):
                    if site.classification is Classification.UNTRUSTED:
                        sites.append(site)

    return sites
