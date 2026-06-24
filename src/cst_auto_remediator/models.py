"""Shared data types and reason-code enums."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ReasonCode(str, Enum):
    """Fixed set of structured failure / skip reasons."""

    # Stage 1
    YAML_BOMB = "YAML_BOMB"
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    PARSE_ERROR = "PARSE_ERROR"
    INVALID_ENCODING = "INVALID_ENCODING"

    # Stage 3 — sinks
    SINK_EVAL = "SINK_EVAL"
    SINK_BASH_C = "SINK_BASH_C"
    SINK_SH_C = "SINK_SH_C"
    SINK_COMMAND_SUBSTITUTION = "SINK_COMMAND_SUBSTITUTION"

    # Stage 3 — env / naming
    ENV_NAME_COLLISION = "ENV_NAME_COLLISION"
    GENERATED_NAME_COLLISION = "GENERATED_NAME_COLLISION"

    # Stage 3 — scope / classification
    BLOCK_SCALAR_OUT_OF_SCOPE = "BLOCK_SCALAR_OUT_OF_SCOPE"
    TRUSTED = "TRUSTED"
    AMBIGUOUS_EXPRESSION = "AMBIGUOUS_EXPRESSION"
    SINGLE_QUOTED_EXPRESSION = "SINGLE_QUOTED_EXPRESSION"


class Classification(str, Enum):
    UNTRUSTED = "UNTRUSTED"
    TRUSTED = "TRUSTED"
    AMBIGUOUS = "AMBIGUOUS"


class ScalarType(str, Enum):
    PLAIN = "plain"
    BLOCK = "block"


class Action(str, Enum):
    PATCHED = "PATCHED"
    SKIPPED = "SKIPPED"
    BAILED = "BAILED"


@dataclass(frozen=True)
class FileMetadata:
    path: str
    size: int
    sha256: str
    encoding: str
    line_ending: str


@dataclass(frozen=True)
class ExpressionSite:
    job_id: str
    step_index: int
    step_id: str | None
    expression_text: str
    expression_body: str
    classification: Classification
    scalar_type: ScalarType
    start_offset: int
    end_offset: int
    run_value: str


@dataclass
class IngestSuccess:
    document: Any
    metadata: FileMetadata
    source_text: str


@dataclass
class IngestFailure:
    metadata: FileMetadata | None
    reason: ReasonCode


IngestResult = IngestSuccess | IngestFailure


@dataclass
class ReportEntry:
    file: str
    job_id: str | None = None
    step: int | None = None
    step_id: str | None = None
    action: Action = Action.SKIPPED
    reason: ReasonCode | None = None
    env_var_added: str | None = None
    expression_text: str | None = None
    classification: Classification | None = None
    scalar_type: ScalarType | None = None
    start_offset: int | None = None
    end_offset: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "job_id": self.job_id,
            "step": self.step,
            "step_id": self.step_id,
            "action": self.action.value,
            "reason": self.reason.value if self.reason else None,
            "env_var_added": self.env_var_added,
            "expression_text": self.expression_text,
            "classification": self.classification.value if self.classification else None,
            "scalar_type": self.scalar_type.value if self.scalar_type else None,
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
        }


@dataclass
class ValidationResult:
    action: Action
    reason: ReasonCode | None = None
    env_var_name: str | None = None


@dataclass
class PlannedPatch:
    site: ExpressionSite
    env_var_name: str


@dataclass
class MutationPlan:
    patches: list[PlannedPatch] = field(default_factory=list)
    report_entries: list[ReportEntry] = field(default_factory=list)
    touched_run_lines: set[int] = field(default_factory=set)
    inserted_env_lines: set[int] = field(default_factory=set)
