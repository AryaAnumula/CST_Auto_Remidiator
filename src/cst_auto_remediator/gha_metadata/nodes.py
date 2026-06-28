"""
Stage 4 — GitHub Actions Metadata Models.

Immutable, typed metadata datatypes computed over the semantic GHA tree.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cst_auto_remediator.yaml_cst.nodes import SourceSpan, YamlScalar
    from cst_auto_remediator.gha_semantic.nodes import Workflow, Job, Step, RunCommand, EnvBinding


@dataclass(frozen=True)
class ShellCapabilities:
    supports_env_assignment: bool
    supports_export: bool
    supports_double_quotes: bool
    supports_single_quotes: bool
    supports_command_substitution: bool
    supports_variable_reference: bool


@dataclass(frozen=True)
class PositionMetadata:
    span: SourceSpan | None
    parent: Workflow | Job | Step | RunCommand | EnvBinding | None
    node_path: str
    path_segments: tuple[str, ...]
    step_index: int | None
    job_id: str | None


@dataclass(frozen=True)
class ScopeMetadata:
    scope_type: str  # "workflow", "job", "step"
    env: dict[str, YamlScalar]
    parent_scope: ScopeMetadata | None


@dataclass(frozen=True)
class ShellMetadata:
    declared_shell: str | None
    effective_shell: str
    runner_default: str
    is_default: bool
    capabilities: ShellCapabilities


@dataclass(frozen=True)
class ExpressionMetadata:
    stable_id: str
    expression_order: int
    is_duplicate: bool
    duplicate_index: int | None


@dataclass(frozen=True)
class MetadataBundle:
    position: PositionMetadata | None = None
    scope: ScopeMetadata | None = None
    shell: ShellMetadata | None = None
    expression: ExpressionMetadata | None = None
