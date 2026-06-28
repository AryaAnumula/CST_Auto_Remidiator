"""
Stage 5 — GitHub Actions Security Analysis Models.

Defines immutable data types and classification enums computed during Stage 5.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from cst_auto_remediator.gha_semantic.nodes import ExpressionSite, Diagnostic, Workflow
    from cst_auto_remediator.gha_metadata.nodes import ScopeMetadata


class TrustLevel(str, Enum):
    UNKNOWN = "UNKNOWN"
    TRUSTED = "TRUSTED"  # Trusted according to the V1 security model
    UNTRUSTED = "UNTRUSTED"
    MIXED = "MIXED"


class SourceKind(str, Enum):
    GITHUB_CONTEXT = "GitHub Context"
    ENVIRONMENT = "Environment"
    SECRET = "Secret"
    MATRIX = "Matrix"
    NEEDS = "Needs"
    INPUTS = "Inputs"
    VARS = "Vars"
    LITERAL = "Literal"
    UNKNOWN = "Unknown"


class SinkKind(str, Enum):
    RUN_COMMAND = "RUN_COMMAND"
    ENV_ASSIGNMENT = "ENV_ASSIGNMENT"
    NONE = "NONE"


class BailoutReason(str, Enum):
    NONE = "NONE"
    BLOCK_SCALAR = "BLOCK_SCALAR"
    UNSUPPORTED_SHELL = "UNSUPPORTED_SHELL"
    UNSUPPORTED_RUNNER = "UNSUPPORTED_RUNNER"
    INVALID_STRUCTURE = "INVALID_STRUCTURE"
    NO_EXPRESSION = "NO_EXPRESSION"
    UNKNOWN_CONTEXT = "UNKNOWN_CONTEXT"
    UNSUPPORTED_FEATURE = "UNSUPPORTED_FEATURE"
    SAFE_ALREADY = "SAFE_ALREADY"


class AnalysisDecision(str, Enum):
    SAFE = "SAFE"
    REMEDIATE = "REMEDIATE"
    BAILOUT = "BAILOUT"
    SKIP = "SKIP"


@dataclass(frozen=True)
class ExpressionClassification:
    expression_site: ExpressionSite
    stable_expression_id: str
    trust_level: TrustLevel
    source_kind: SourceKind
    sink_kind: SinkKind
    decision: AnalysisDecision
    bailout_reason: BailoutReason
    shell_kind: str
    scope: ScopeMetadata | None
    diagnostics: list[Diagnostic] = field(default_factory=list)


@dataclass(frozen=True)
class AnalysisStatistics:
    total_expressions: int = 0
    trusted_expressions: int = 0
    untrusted_expressions: int = 0
    unknown_expressions: int = 0
    bailouts: int = 0
    needs_remediation: int = 0
    skipped: int = 0
    safe: int = 0


@dataclass(frozen=True)
class SecurityAnalysisResult:
    workflow: Workflow | None
    expression_classifications: dict[str, ExpressionClassification] = field(default_factory=dict)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    statistics: AnalysisStatistics = field(default_factory=AnalysisStatistics)
    summary: dict[str, Any] = field(default_factory=dict)
