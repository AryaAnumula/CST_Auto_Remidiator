"""
Stage 8: Compiler Verification & Certification Framework.
"""

from __future__ import annotations

from cst_auto_remediator.gha_verify.report import (
    VerificationContext,
    VerificationReport,
    VerificationDecision,
    InvariantCode,
    InvariantResult,
    VerificationFinding,
    VerificationStatistics,
)
from cst_auto_remediator.gha_verify.verify import verify_output

__all__ = [
    "verify_output",
    "VerificationContext",
    "VerificationReport",
    "VerificationDecision",
    "InvariantCode",
    "InvariantResult",
    "VerificationFinding",
    "VerificationStatistics",
]
