"""
Stage 6 - Transformation models.

These dataclasses describe intended and applied changes. They do not mutate CST,
semantic, metadata, or analysis objects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cst_auto_remediator.gha_semantic.nodes import RunCommand, Step, Workflow
    from cst_auto_remediator.yaml_cst.nodes import YamlDocument


@dataclass(frozen=True)
class EnvVarEntry:
    expression_id: str
    name: str
    expression_text: str


@dataclass(frozen=True)
class SiteReplacement:
    expression_id: str
    start_offset: int
    end_offset: int
    original_text: str
    replacement_text: str
    env_var_name: str


@dataclass(frozen=True)
class StepMutation:
    job_id: str
    step_index: int
    step: Step
    run_command: RunCommand
    env_entries: tuple[EnvVarEntry, ...] = field(default_factory=tuple)
    replacements: tuple[SiteReplacement, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class MutationPlan:
    workflow: Workflow | None
    step_mutations: tuple[StepMutation, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class TransformationResult:
    original_workflow: Workflow | None
    workflow: Workflow | None
    cst: YamlDocument | None
    plan: MutationPlan
    applied_step_mutations: tuple[StepMutation, ...] = field(default_factory=tuple)
