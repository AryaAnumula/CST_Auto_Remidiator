"""
Stage 6 - Mutation planning.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cst_auto_remediator.gha_analysis.nodes import (
    AnalysisDecision,
    SecurityAnalysisResult,
    SinkKind,
)
from cst_auto_remediator.gha_metadata.engine import MetadataWrapper
from cst_auto_remediator.gha_metadata.providers import PositionProvider
from cst_auto_remediator.gha_semantic.nodes import RunCommand, Step
from cst_auto_remediator.gha_transform.namer import gen_safe_var_name
from cst_auto_remediator.gha_transform.nodes import (
    EnvVarEntry,
    MutationPlan,
    SiteReplacement,
    StepMutation,
)


class Stage6InvariantError(RuntimeError):
    """Raised when Stage 4/5 contracts required by transformation are missing."""


@dataclass
class _StepMutationBuilder:
    job_id: str
    step_index: int
    step: Step
    run_command: RunCommand
    env_entries: list[EnvVarEntry] = field(default_factory=list)
    replacements: list[SiteReplacement] = field(default_factory=list)
    reserved_names: set[str] = field(default_factory=set)


class MutationPlanner:
    def __init__(self, metadata: MetadataWrapper):
        self.metadata = metadata

    def build_plan(self, result: SecurityAnalysisResult) -> MutationPlan:
        if result.workflow is None:
            return MutationPlan(workflow=None)

        builders: dict[int, _StepMutationBuilder] = {}

        for stable_id, classification in sorted(result.expression_classifications.items()):
            if classification.decision is not AnalysisDecision.REMEDIATE:
                continue

            if classification.scope is None:
                raise Stage6InvariantError(
                    f"REMEDIATE classification {stable_id!r} has no ScopeMetadata"
                )
            if classification.sink_kind is not SinkKind.RUN_COMMAND:
                raise Stage6InvariantError(
                    f"REMEDIATE classification {stable_id!r} is not in a run command"
                )

            expr = classification.expression_site
            expr_pos = self.metadata.get(PositionProvider, expr)
            if expr_pos is None or not isinstance(expr_pos.parent, RunCommand):
                raise Stage6InvariantError(
                    f"REMEDIATE classification {stable_id!r} is missing RunCommand position metadata"
                )

            run_command = expr_pos.parent
            run_pos = self.metadata.get(PositionProvider, run_command)
            if run_pos is None or not isinstance(run_pos.parent, Step):
                raise Stage6InvariantError(
                    f"REMEDIATE classification {stable_id!r} is missing Step position metadata"
                )

            step = run_pos.parent
            if run_pos.job_id is None or run_pos.step_index is None:
                raise Stage6InvariantError(
                    f"REMEDIATE classification {stable_id!r} is missing job or step metadata"
                )

            builder = builders.get(id(step))
            if builder is None:
                builder = _StepMutationBuilder(
                    job_id=run_pos.job_id,
                    step_index=run_pos.step_index,
                    step=step,
                    run_command=run_command,
                )
                builders[id(step)] = builder

            env_var_name = gen_safe_var_name(
                expr.expression_text,
                classification.scope,
                reserved_names=builder.reserved_names,
            )
            builder.reserved_names.add(env_var_name)
            builder.env_entries.append(
                EnvVarEntry(
                    expression_id=stable_id,
                    name=env_var_name,
                    expression_text=expr.expression_text,
                )
            )
            builder.replacements.append(
                SiteReplacement(
                    expression_id=stable_id,
                    start_offset=expr.start_offset,
                    end_offset=expr.end_offset,
                    original_text=expr.expression_text,
                    replacement_text=f"${env_var_name}",
                    env_var_name=env_var_name,
                )
            )

        step_mutations = tuple(
            StepMutation(
                job_id=builder.job_id,
                step_index=builder.step_index,
                step=builder.step,
                run_command=builder.run_command,
                env_entries=tuple(
                    sorted(builder.env_entries, key=lambda item: item.expression_id)
                ),
                replacements=tuple(
                    sorted(builder.replacements, key=lambda item: item.start_offset)
                ),
            )
            for builder in sorted(builders.values(), key=lambda item: (item.job_id, item.step_index))
        )
        return MutationPlan(workflow=result.workflow, step_mutations=step_mutations)
