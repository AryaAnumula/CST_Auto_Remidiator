"""
Verification and Certification immutable data models.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from cst_auto_remediator.yaml_cst.nodes import YamlDocument


class VerificationDecision(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    SKIP = "SKIP"


class InvariantCode(Enum):
    INV_IDEM = "INV-IDEM"
    INV_DET = "INV-DET"
    INV_BYTE = "INV-BYTE"
    INV_NODE = "INV-NODE"
    INV_COW = "INV-COW"
    INV_LINE = "INV-LINE"
    INV_COMM = "INV-COMM"
    INV_SECR = "INV-SECR"
    INV_SEME = "INV-SEME"


@dataclass(frozen=True)
class VerificationContext:
    original_yaml: str
    remediated_yaml: str
    original_cst: YamlDocument
    remediated_cst: YamlDocument
    original_ruamel: Any
    remediated_ruamel: Any
    original_semantic: Any = None
    remediated_semantic: Any = None
    original_metadata: Any = None
    remediated_metadata: Any = None


@dataclass(frozen=True)
class InvariantResult:
    code: InvariantCode
    name: str
    decision: VerificationDecision
    details: str | None = None


@dataclass(frozen=True)
class VerificationFinding:
    code: str  # "VER001" - "VER012"
    severity: VerificationDecision
    message: str
    path: str | None = None


@dataclass(frozen=True)
class VerificationStatistics:
    total_invariants_checked: int
    passed_invariants: int
    failed_invariants: int
    findings_by_severity: dict[VerificationDecision, int]
    execution_time_ms: float


@dataclass(frozen=True)
class VerificationReport:
    decision: VerificationDecision
    findings: list[VerificationFinding]
    invariant_results: list[InvariantResult]
    stats: VerificationStatistics
    summary: str
    compiler_version: str = "1.0.0"
    verifier_version: str = "1.0.0"
    timestamp: str = ""
