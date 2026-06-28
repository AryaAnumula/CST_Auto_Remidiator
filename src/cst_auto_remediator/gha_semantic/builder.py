"""
Stage 3 — GitHub Actions Semantic Builder.

Traverses the immutable Green CST to build the semantic Workflow hierarchy
and populate stable error/warning diagnostics.
"""

from __future__ import annotations

from typing import Any
from cst_auto_remediator.yaml_cst.nodes import YamlDocument, YamlMapping, YamlSequence, YamlKeyValue, YamlScalar
from cst_auto_remediator.gha_semantic.nodes import (
    Diagnostic,
    EnvBinding,
    RunCommand,
    Step,
    Job,
    Workflow,
    SemanticBuildResult,
)
from cst_auto_remediator.gha_semantic.scanner import extract_expression_sites


def _find_entry(mapping: YamlMapping, key_name: str) -> YamlKeyValue | None:
    """Helper to locate a key-value entry in a YamlMapping by key string value."""
    for entry in mapping.entries:
        if isinstance(entry.key, YamlScalar) and entry.key.value == key_name:
            return entry
    return None


def build_semantic_model(cst: YamlDocument) -> SemanticBuildResult:
    """
    Traverses the Green CST to reconstruct GHA concepts and identify structural errors.
    """
    diagnostics: list[Diagnostic] = []

    # GHA001: Workflow root must be a mapping
    if cst.root is None or not isinstance(cst.root, YamlMapping):
        span = cst.span if cst.root is None else cst.root.span
        diagnostics.append(
            Diagnostic(
                code="GHA001",
                message="Workflow root must be a mapping",
                span=span,
                level="error",
            )
        )
        return SemanticBuildResult(workflow=None, diagnostics=diagnostics)

    # GHA002/GHA003: Check jobs section
    jobs_entry = _find_entry(cst.root, "jobs")
    if jobs_entry is None:
        diagnostics.append(
            Diagnostic(
                code="GHA002",
                message="Missing 'jobs' section in workflow",
                span=cst.root.span,
                level="error",
            )
        )
        return SemanticBuildResult(
            workflow=Workflow(node=cst, jobs={}),
            diagnostics=diagnostics,
        )

    if not isinstance(jobs_entry.value, YamlMapping):
        diagnostics.append(
            Diagnostic(
                code="GHA003",
                message="Jobs section must be a mapping",
                span=jobs_entry.value.span if jobs_entry.value else jobs_entry.span,
                level="error",
            )
        )
        return SemanticBuildResult(
            workflow=Workflow(node=cst, jobs={}),
            diagnostics=diagnostics,
        )

    workflow_jobs: dict[str, Job] = {}

    # Traverse job entries
    for job_entry in jobs_entry.value.entries:
        job_id = str(job_entry.key.value) if isinstance(job_entry.key, YamlScalar) else ""
        if not isinstance(job_entry.value, YamlMapping):
            diagnostics.append(
                Diagnostic(
                    code="GHA004",
                    message=f"Job '{job_id}' must be a mapping",
                    span=job_entry.value.span if job_entry.value else job_entry.span,
                    level="error",
                )
            )
            continue

        job_steps: list[Step] = []
        steps_entry = _find_entry(job_entry.value, "steps")
        
        if steps_entry is not None:
            if not isinstance(steps_entry.value, YamlSequence):
                diagnostics.append(
                    Diagnostic(
                        code="GHA005",
                        message=f"Steps in job '{job_id}' must be a sequence",
                        span=steps_entry.value.span if steps_entry.value else steps_entry.span,
                        level="error",
                    )
                )
            else:
                # Traverse step sequence
                for step_idx, step_item in enumerate(steps_entry.value.items):
                    if not isinstance(step_item, YamlMapping):
                        diagnostics.append(
                            Diagnostic(
                                code="GHA006",
                                message=f"Step at index {step_idx} in job '{job_id}' must be a mapping",
                                span=step_item.span,
                                level="error",
                            )
                        )
                        continue

                    # step_id extraction
                    step_id = None
                    id_entry = _find_entry(step_item, "id")
                    if id_entry is not None:
                        if not isinstance(id_entry.value, YamlScalar):
                            diagnostics.append(
                                Diagnostic(
                                    code="GHA007",
                                    message=f"Id in step {step_idx} of job '{job_id}' must be a scalar",
                                    span=id_entry.value.span if id_entry.value else id_entry.span,
                                    level="error",
                                )
                            )
                        else:
                            step_id = str(id_entry.value.value)

                    # run command extraction
                    run_command = None
                    run_entry = _find_entry(step_item, "run")
                    if run_entry is not None:
                        if not isinstance(run_entry.value, YamlScalar):
                            diagnostics.append(
                                Diagnostic(
                                    code="GHA008",
                                    message=f"Run command in step {step_idx} of job '{job_id}' must be a scalar",
                                    span=run_entry.value.span if run_entry.value else run_entry.span,
                                    level="error",
                                )
                            )
                        else:
                            expr_sites = extract_expression_sites(run_entry.value)
                            run_command = RunCommand(
                                node=run_entry,
                                command=run_entry.value,
                                expression_sites=expr_sites,
                            )

                    # env bindings extraction
                    env_bindings: list[EnvBinding] = []
                    env_entry = _find_entry(step_item, "env")
                    if env_entry is not None:
                        if not isinstance(env_entry.value, YamlMapping):
                            diagnostics.append(
                                Diagnostic(
                                    code="GHA009",
                                    message=f"Env block in step {step_idx} of job '{job_id}' must be a mapping",
                                    span=env_entry.value.span if env_entry.value else env_entry.span,
                                    level="error",
                                )
                            )
                        else:
                            for binding_entry in env_entry.value.entries:
                                if (
                                    not isinstance(binding_entry.key, YamlScalar)
                                    or not isinstance(binding_entry.value, YamlScalar)
                                ):
                                    diagnostics.append(
                                        Diagnostic(
                                            code="GHA010",
                                            message=f"Env binding in step {step_idx} of job '{job_id}' must have a scalar key and value",
                                            span=binding_entry.span,
                                            level="error",
                                        )
                                    )
                                else:
                                    expr_sites = extract_expression_sites(binding_entry.value)
                                    env_bindings.append(
                                        EnvBinding(
                                            node=binding_entry,
                                            key=binding_entry.key,
                                            value=binding_entry.value,
                                            expression_sites=expr_sites,
                                        )
                                    )

                    job_steps.append(
                        Step(
                            node=step_item,
                            step_index=step_idx,
                            step_id=step_id,
                            run_command=run_command,
                            env_bindings=env_bindings,
                        )
                    )

        workflow_jobs[job_id] = Job(
            node=job_entry.value,
            job_id=job_id,
            steps=job_steps,
        )

    workflow = Workflow(node=cst, jobs=workflow_jobs)
    return SemanticBuildResult(workflow=workflow, diagnostics=diagnostics)
