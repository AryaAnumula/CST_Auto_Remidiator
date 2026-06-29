"""
Stage 3 — GitHub Actions Semantic Model.

Immutable semantic representation of a parsed GitHub Actions workflow.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from cst_auto_remediator.yaml_cst.nodes import SourceSpan, YamlDocument, YamlMapping, YamlScalar, YamlKeyValue, YamlNode


@dataclass(frozen=True)
class Diagnostic:
    code: str
    message: str
    span: SourceSpan | None = None
    level: str = "error"  # "error", "warning"


@dataclass(frozen=True)
class ExpressionSite:
    node: YamlScalar
    expression_text: str
    expression_body: str
    start_offset: int
    end_offset: int


@dataclass(frozen=True)
class EnvBinding:
    node: YamlKeyValue
    key: YamlScalar
    value: YamlScalar
    expression_sites: list[ExpressionSite] = field(default_factory=list)


@dataclass(frozen=True)
class RunCommand:
    node: YamlKeyValue
    command: YamlScalar
    expression_sites: list[ExpressionSite] = field(default_factory=list)


@dataclass(frozen=True)
class Step:
    node: YamlMapping
    step_index: int
    step_id: str | None = None
    run_command: RunCommand | None = None
    env_bindings: list[EnvBinding] = field(default_factory=list)


@dataclass(frozen=True)
class Job:
    node: YamlMapping
    job_id: str
    steps: list[Step] = field(default_factory=list)


@dataclass(frozen=True)
class Workflow:
    node: YamlDocument
    jobs: dict[str, Job] = field(default_factory=dict)


@dataclass(frozen=True)
class SemanticBuildResult:
    workflow: Workflow | None
    diagnostics: list[Diagnostic] = field(default_factory=list)
