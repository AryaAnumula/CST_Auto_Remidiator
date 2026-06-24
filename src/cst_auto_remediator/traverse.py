"""Stage 2 — depth-first traversal to locate expression sites."""

from __future__ import annotations

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


def traverse_jobs(document: object) -> list[ExpressionSite]:
    """Walk ``jobs.<job_id>.steps[].run`` and collect expression sites."""
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

            for expr_text, start, end in find_expressions(run_text):
                body = extract_expression_body(expr_text)
                sites.append(
                    ExpressionSite(
                        job_id=str(job_id),
                        step_index=step_index,
                        step_id=step_id_str,
                        expression_text=expr_text,
                        expression_body=body,
                        classification=classify_expression(body),
                        scalar_type=scalar,
                        start_offset=start,
                        end_offset=end,
                        run_value=run_text,
                    )
                )

    return sites
