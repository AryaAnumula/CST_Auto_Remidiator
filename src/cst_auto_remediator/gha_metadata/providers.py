"""
Stage 4 — GitHub Actions Metadata Providers.

Contains specific MetadataProvider implementations for Position, Scope, Shell,
and Expression metadata categories.
"""

from __future__ import annotations

from typing import Any
from cst_auto_remediator.yaml_cst.nodes import YamlMapping, YamlSequence, YamlKeyValue, YamlScalar
from cst_auto_remediator.gha_semantic.nodes import Workflow, Job, Step, RunCommand, EnvBinding, ExpressionSite
from cst_auto_remediator.gha_metadata.engine import MetadataProvider
from cst_auto_remediator.gha_metadata.nodes import (
    PositionMetadata,
    ScopeMetadata,
    ShellMetadata,
    ShellCapabilities,
    ExpressionMetadata,
)


class PositionProvider(MetadataProvider):
    @classmethod
    def dependencies(cls) -> list[type[MetadataProvider]]:
        return []

    def resolve(self, workflow: Workflow) -> dict[Any, Any]:
        result: dict[Any, Any] = {}

        # 1. Workflow
        wf_meta = PositionMetadata(
            span=workflow.node.span,
            parent=None,
            node_path="workflow",
            path_segments=("workflow",),
            step_index=None,
            job_id=None,
        )
        result[id(workflow)] = wf_meta

        # Traverse jobs
        for job_id, job in workflow.jobs.items():
            job_meta = PositionMetadata(
                span=job.node.span,
                parent=workflow,
                node_path=f"jobs.{job_id}",
                path_segments=("jobs", job_id),
                step_index=None,
                job_id=job_id,
            )
            result[id(job)] = job_meta

            # Traverse steps
            for step_idx, step in enumerate(job.steps):
                step_path = f"jobs.{job_id}.steps.{step_idx}"
                step_segs = ("jobs", job_id, "steps", str(step_idx))
                step_meta = PositionMetadata(
                    span=step.node.span,
                    parent=job,
                    node_path=step_path,
                    path_segments=step_segs,
                    step_index=step_idx,
                    job_id=job_id,
                )
                result[id(step)] = step_meta

                # Run command
                if step.run_command is not None:
                    run_cmd = step.run_command
                    run_path = f"{step_path}.run"
                    run_segs = step_segs + ("run",)
                    run_meta = PositionMetadata(
                        span=run_cmd.node.span,
                        parent=step,
                        node_path=run_path,
                        path_segments=run_segs,
                        step_index=step_idx,
                        job_id=job_id,
                    )
                    result[id(run_cmd)] = run_meta

                    # Run command expression sites
                    for expr_idx, expr in enumerate(run_cmd.expression_sites):
                        expr_path = f"{run_path}.exprs.{expr_idx}"
                        expr_segs = run_segs + ("exprs", str(expr_idx))
                        result[id(expr)] = PositionMetadata(
                            span=expr.node.span,
                            parent=run_cmd,
                            node_path=expr_path,
                            path_segments=expr_segs,
                            step_index=step_idx,
                            job_id=job_id,
                        )

                # Env bindings
                for binding in step.env_bindings:
                    key_val = str(binding.key.value)
                    binding_path = f"{step_path}.env.{key_val}"
                    binding_segs = step_segs + ("env", key_val)
                    binding_meta = PositionMetadata(
                        span=binding.node.span,
                        parent=step,
                        node_path=binding_path,
                        path_segments=binding_segs,
                        step_index=step_idx,
                        job_id=job_id,
                    )
                    result[id(binding)] = binding_meta

                    # Env binding expression sites
                    for expr_idx, expr in enumerate(binding.expression_sites):
                        expr_path = f"{binding_path}.exprs.{expr_idx}"
                        expr_segs = binding_segs + ("exprs", str(expr_idx))
                        result[id(expr)] = PositionMetadata(
                            span=expr.node.span,
                            parent=binding,
                            node_path=expr_path,
                            path_segments=expr_segs,
                            step_index=step_idx,
                            job_id=job_id,
                        )

        return result


def _extract_env_map(mapping_node: Any) -> dict[str, YamlScalar]:
    """Generic helper to parse 'env' map from any CST mapping node."""
    if not isinstance(mapping_node, YamlMapping):
        return {}
    for entry in mapping_node.entries:
        if isinstance(entry.key, YamlScalar) and entry.key.value == "env":
            if isinstance(entry.value, YamlMapping):
                res = {}
                for binding in entry.value.entries:
                    if isinstance(binding.key, YamlScalar) and isinstance(binding.value, YamlScalar):
                        res[str(binding.key.value)] = binding.value
                return res
    return {}


class ScopeProvider(MetadataProvider):
    @classmethod
    def dependencies(cls) -> list[type[MetadataProvider]]:
        return []

    def resolve(self, workflow: Workflow) -> dict[Any, Any]:
        result: dict[Any, Any] = {}

        # 1. Workflow Scope
        wf_env = _extract_env_map(workflow.node.root)
        wf_scope = ScopeMetadata(
            scope_type="workflow",
            env=wf_env,
            parent_scope=None,
        )
        result[id(workflow)] = wf_scope

        # 2. Job Scope
        for job_id, job in workflow.jobs.items():
            job_env = wf_scope.env.copy()
            job_env.update(_extract_env_map(job.node))
            job_scope = ScopeMetadata(
                scope_type="job",
                env=job_env,
                parent_scope=wf_scope,
            )
            result[id(job)] = job_scope

            # 3. Step Scope
            for step in job.steps:
                step_env = job_scope.env.copy()
                step_level_env = {binding.key.value: binding.value for binding in step.env_bindings}
                step_env.update(step_level_env)
                step_scope = ScopeMetadata(
                    scope_type="step",
                    env=step_env,
                    parent_scope=job_scope,
                )
                result[id(step)] = step_scope

                # Map sub-nodes of step to the same StepScope
                if step.run_command is not None:
                    result[id(step.run_command)] = step_scope
                    for expr in step.run_command.expression_sites:
                        result[id(expr)] = step_scope

                for binding in step.env_bindings:
                    result[id(binding)] = step_scope
                    for expr in binding.expression_sites:
                        result[id(expr)] = step_scope

        return result


def _get_default_shell(mapping_node: Any) -> str | None:
    """Recursively search for defaults.run.shell in a CST mapping node."""
    if not isinstance(mapping_node, YamlMapping):
        return None
    for entry in mapping_node.entries:
        if isinstance(entry.key, YamlScalar) and entry.key.value == "defaults":
            if isinstance(entry.value, YamlMapping):
                for d_entry in entry.value.entries:
                    if isinstance(d_entry.key, YamlScalar) and d_entry.key.value == "run":
                        if isinstance(d_entry.value, YamlMapping):
                            for r_entry in d_entry.value.entries:
                                if isinstance(r_entry.key, YamlScalar) and r_entry.key.value == "shell":
                                    if isinstance(r_entry.value, YamlScalar):
                                        return str(r_entry.value.value)
    return None


class ShellProvider(MetadataProvider):
    @classmethod
    def dependencies(cls) -> list[type[MetadataProvider]]:
        return [PositionProvider, ScopeProvider]

    def resolve(self, workflow: Workflow) -> dict[Any, Any]:
        result: dict[Any, Any] = {}

        wf_default_shell = _get_default_shell(workflow.node.root)

        for job_id, job in workflow.jobs.items():
            # Determine runner default shell by inspecting runs-on
            runner_default = "bash"
            runs_on_entry = None
            if isinstance(job.node, YamlMapping):
                for entry in job.node.entries:
                    if isinstance(entry.key, YamlScalar) and entry.key.value == "runs-on":
                        runs_on_entry = entry
                        break
            
            if runs_on_entry is not None and isinstance(runs_on_entry.value, YamlScalar):
                val_str = str(runs_on_entry.value.value).lower()
                if "windows" in val_str:
                    runner_default = "pwsh"

            job_default_shell = _get_default_shell(job.node)

            for step in job.steps:
                # 1. Declared shell search
                declared_shell = None
                for entry in step.node.entries:
                    if isinstance(entry.key, YamlScalar) and entry.key.value == "shell":
                        if isinstance(entry.value, YamlScalar):
                            declared_shell = str(entry.value.value)
                            break

                is_default = False
                if declared_shell is not None:
                    effective_shell = declared_shell
                elif job_default_shell is not None:
                    effective_shell = job_default_shell
                    declared_shell = job_default_shell
                elif wf_default_shell is not None:
                    effective_shell = wf_default_shell
                    declared_shell = wf_default_shell
                else:
                    effective_shell = runner_default
                    is_default = True

                # 2. Build capabilities
                capabilities = ShellCapabilities(
                    supports_env_assignment=effective_shell in ("bash", "sh"),
                    supports_export=effective_shell in ("bash", "sh"),
                    supports_double_quotes=effective_shell in ("bash", "sh", "pwsh", "powershell"),
                    supports_single_quotes=effective_shell in ("bash", "sh", "pwsh", "powershell"),
                    supports_command_substitution=effective_shell in ("bash", "sh"),
                    supports_variable_reference=effective_shell in ("bash", "sh", "pwsh", "powershell"),
                )

                shell_meta = ShellMetadata(
                    declared_shell=declared_shell,
                    effective_shell=effective_shell,
                    runner_default=runner_default,
                    is_default=is_default,
                    capabilities=capabilities,
                )

                result[id(step)] = shell_meta
                if step.run_command is not None:
                    result[id(step.run_command)] = shell_meta
                    for expr in step.run_command.expression_sites:
                        result[id(expr)] = shell_meta

                for binding in step.env_bindings:
                    result[id(binding)] = shell_meta
                    for expr in binding.expression_sites:
                        result[id(expr)] = shell_meta

        return result


class ExpressionProvider(MetadataProvider):
    @classmethod
    def dependencies(cls) -> list[type[MetadataProvider]]:
        return [PositionProvider, ScopeProvider]

    def resolve(self, workflow: Workflow) -> dict[Any, Any]:
        result: dict[Any, Any] = {}

        # 1. Collect all ExpressionSites sequentially
        expr_list: list[ExpressionSite] = []
        for job in workflow.jobs.values():
            for step in job.steps:
                if step.run_command is not None:
                    expr_list.extend(step.run_command.expression_sites)
                for binding in step.env_bindings:
                    expr_list.extend(binding.expression_sites)

        # 2. Process duplicates and IDs
        dup_tracker: dict[str, list[ExpressionSite]] = {}
        for order_idx, expr in enumerate(expr_list):
            txt = expr.expression_text
            dup_tracker.setdefault(txt, []).append(expr)

            # Retrieve position mapping to construct stable path-based ID
            pos_meta = self.get_metadata(PositionProvider, expr)
            stable_id = pos_meta.node_path if pos_meta else f"expr.{order_idx}"

            is_duplicate = len(dup_tracker[txt]) > 1
            duplicate_index = None
            if is_duplicate:
                # Retrieve order index of the first occurrence
                first_expr = dup_tracker[txt][0]
                # Walk expr_list to find first_expr order
                duplicate_index = expr_list.index(first_expr)

            expr_meta = ExpressionMetadata(
                stable_id=stable_id,
                expression_order=order_idx,
                is_duplicate=is_duplicate,
                duplicate_index=duplicate_index,
            )
            result[id(expr)] = expr_meta

        return result
