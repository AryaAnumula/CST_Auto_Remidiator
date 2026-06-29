"""
Stage 5 — GitHub Actions Security Analysis Phase.
"""

from cst_auto_remediator.gha_analysis.analyzer import analyze_workflow
from cst_auto_remediator.gha_analysis.nodes import (
    TrustLevel,
    SourceKind,
    SinkKind,
    BailoutReason,
    AnalysisDecision,
    ExpressionClassification,
    AnalysisStatistics,
    SecurityAnalysisResult,
)

__all__ = [
    "analyze_workflow",
    "TrustLevel",
    "SourceKind",
    "SinkKind",
    "BailoutReason",
    "AnalysisDecision",
    "ExpressionClassification",
    "AnalysisStatistics",
    "SecurityAnalysisResult",
]
