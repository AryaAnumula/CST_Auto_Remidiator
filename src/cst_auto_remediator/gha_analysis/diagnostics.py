"""
Stage 5 — GitHub Actions Security Analysis Diagnostics.

Defines compiler-style diagnostic builders for Stage 5.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from cst_auto_remediator.gha_semantic.nodes import Diagnostic

if TYPE_CHECKING:
    from cst_auto_remediator.yaml_cst.nodes import SourceSpan


def make_ana001(span: SourceSpan | None, expression_text: str) -> Diagnostic:
    """Unknown source context (Warning)."""
    return Diagnostic(
        code="ANA001",
        message=f"Unknown expression source context: '{expression_text}'",
        span=span,
        level="warning",
    )


def make_ana002(span: SourceSpan | None, shell_name: str) -> Diagnostic:
    """Unsupported shell environment (Error)."""
    return Diagnostic(
        code="ANA002",
        message=f"Unsupported step shell environment: '{shell_name}'",
        span=span,
        level="error",
    )


def make_ana003(span: SourceSpan | None, style: str) -> Diagnostic:
    """Unsupported block scalar format (Warning)."""
    return Diagnostic(
        code="ANA003",
        message=f"Unsupported block scalar format: '{style}'",
        span=span,
        level="warning",
    )


def make_ana004(span: SourceSpan | None, expression_text: str) -> Diagnostic:
    """Unsafe expression reaches shell command sink (Error)."""
    return Diagnostic(
        code="ANA004",
        message=f"Unsafe expression reaches shell command execution sink: '{expression_text}'",
        span=span,
        level="error",
    )


def make_ana005(span: SourceSpan | None, expression_text: str) -> Diagnostic:
    """Safe expression (Warning/Info)."""
    return Diagnostic(
        code="ANA005",
        message=f"Safe expression: '{expression_text}'",
        span=span,
        level="warning",  # info/warning level
    )
