"""
Stage 6 - Copy-on-write CST transformation.

This stage owns MUTATION ONLY. It does not rebuild or re-parse the semantic
model — that is the responsibility of whichever stage consumes this result
next (Stage 7 / orchestrator). TransformationResult.workflow is always None
after this stage; callers must call build_semantic_model(result.cst) themselves
if they need the post-transform semantic view.
"""

from __future__ import annotations

from cst_auto_remediator.gha_transform.nodes import (
    EnvVarEntry,
    MutationPlan,
    StepMutation,
    TransformationResult,
)
from cst_auto_remediator.gha_transform.planner import Stage6InvariantError
from cst_auto_remediator.gha_transform.rtl import apply_rtl_substitutions
from cst_auto_remediator.yaml_cst.nodes import (
    YamlDocument,
    YamlKeyValue,
    YamlMapping,
    YamlNode,
    YamlScalar,
    YamlSequence,
)


def _find_entry(mapping: YamlMapping, key_name: str) -> YamlKeyValue | None:
    for entry in mapping.entries:
        if isinstance(entry.key, YamlScalar) and entry.key.value == key_name:
            return entry
    return None


def _make_plain_scalar(value: str) -> YamlScalar:
    return YamlScalar(value=value, raw_text=value, style="PLAIN")


def _make_env_entry(entry: EnvVarEntry) -> YamlKeyValue:
    return YamlKeyValue(
        key=_make_plain_scalar(entry.name),
        value=_make_plain_scalar(entry.expression_text),
    )


class CSTTransformer:
    def transform(self, plan: MutationPlan) -> TransformationResult:
        if plan.workflow is None:
            return TransformationResult(
                original_workflow=None,
                workflow=None,
                cst=None,
                plan=plan,
            )

        if not plan.step_mutations:
            # No mutations needed — return original CST unchanged.
            # workflow=None: semantic rebuild is not Stage 6's responsibility.
            return TransformationResult(
                original_workflow=plan.workflow,
                workflow=None,
                cst=plan.workflow.node,
                plan=plan,
            )

        new_step_nodes = {
            (mutation.job_id, mutation.step_index): self._transform_step(mutation)
            for mutation in plan.step_mutations
        }
        new_cst = self._replace_steps(plan.workflow.node, new_step_nodes)

        # Stage 6 returns the mutated CST only.
        # The semantic model for the new CST is NOT rebuilt here — that belongs to
        # Stage 7 (Verification) or the pipeline orchestrator.
        return TransformationResult(
            original_workflow=plan.workflow,
            workflow=None,
            cst=new_cst,
            plan=plan,
            applied_step_mutations=plan.step_mutations,
        )


    def _transform_step(self, mutation: StepMutation) -> YamlMapping:
        step_node = mutation.step.node
        run_entry = mutation.run_command.node
        command = mutation.run_command.command
        if not isinstance(command.value, str):
            raise Stage6InvariantError("run command value must be a string for transformation")

        new_script = apply_rtl_substitutions(command.value, mutation.replacements)
        new_command = command.with_value(new_script, new_script)
        new_run_entry = run_entry.with_value(new_command)

        entries: list[YamlKeyValue] = []
        env_inserted = False
        run_seen = False

        for entry in step_node.entries:
            if entry is run_entry:
                if not env_inserted:
                    existing_env = _find_entry(step_node, "env")
                    if existing_env is None:
                        entries.append(
                            YamlKeyValue(
                                key=_make_plain_scalar("env"),
                                value=YamlMapping(
                                    entries=[_make_env_entry(env) for env in mutation.env_entries]
                                ),
                            )
                        )
                        env_inserted = True
                entries.append(new_run_entry)
                run_seen = True
                continue

            if isinstance(entry.key, YamlScalar) and entry.key.value == "env":
                if not isinstance(entry.value, YamlMapping):
                    raise Stage6InvariantError("step env entry must be a mapping for transformation")
                new_env_entries = list(entry.value.entries)
                new_env_entries.extend(_make_env_entry(env) for env in mutation.env_entries)
                entries.append(entry.with_value(entry.value.with_entries(new_env_entries)))
                env_inserted = True
                continue

            entries.append(entry)

        if not run_seen:
            raise Stage6InvariantError("step mutation did not find its run entry")

        return step_node.with_entries(entries)

    def _replace_steps(
        self,
        document: YamlDocument,
        new_step_nodes: dict[tuple[str, int], YamlMapping],
    ) -> YamlDocument:
        if not isinstance(document.root, YamlMapping):
            raise Stage6InvariantError("workflow root must be a mapping")

        jobs_entry = _find_entry(document.root, "jobs")
        if jobs_entry is None or not isinstance(jobs_entry.value, YamlMapping):
            raise Stage6InvariantError("workflow jobs entry must be a mapping")

        mutated_jobs = {job_id for job_id, _ in new_step_nodes}
        new_job_entries: list[YamlKeyValue] = []

        for job_entry in jobs_entry.value.entries:
            job_id = str(job_entry.key.value) if isinstance(job_entry.key, YamlScalar) else ""
            if job_id not in mutated_jobs:
                new_job_entries.append(job_entry)
                continue

            if not isinstance(job_entry.value, YamlMapping):
                raise Stage6InvariantError(f"job {job_id!r} must be a mapping")
            new_job_entries.append(job_entry.with_value(self._replace_job_steps(job_id, job_entry.value, new_step_nodes)))

        new_jobs_mapping = jobs_entry.value.with_entries(new_job_entries)
        new_root_entries = [
            entry.with_value(new_jobs_mapping) if entry is jobs_entry else entry
            for entry in document.root.entries
        ]
        return document.with_root(document.root.with_entries(new_root_entries))

    def _replace_job_steps(
        self,
        job_id: str,
        job_mapping: YamlMapping,
        new_step_nodes: dict[tuple[str, int], YamlMapping],
    ) -> YamlMapping:
        steps_entry = _find_entry(job_mapping, "steps")
        if steps_entry is None or not isinstance(steps_entry.value, YamlSequence):
            raise Stage6InvariantError(f"job {job_id!r} steps entry must be a sequence")

        new_items: list[YamlNode] = []
        for index, item in enumerate(steps_entry.value.items):
            new_items.append(new_step_nodes.get((job_id, index), item))

        new_steps_entry = steps_entry.with_value(steps_entry.value.with_items(new_items))
        new_job_entries = [
            new_steps_entry if entry is steps_entry else entry
            for entry in job_mapping.entries
        ]
        return job_mapping.with_entries(new_job_entries)
