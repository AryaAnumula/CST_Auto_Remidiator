"""
Stage 5 — GitHub Actions Security Analysis Analyzer.

Implements the analyze_workflow() orchestration pipeline.
"""

from __future__ import annotations

from typing import Any
from cst_auto_remediator.gha_semantic.builder import build_semantic_model
from cst_auto_remediator.gha_metadata.providers import (
    PositionProvider,
    ScopeProvider,
    ShellProvider,
    ExpressionProvider,
)
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
from cst_auto_remediator.gha_analysis.classifier import classify_expression
from cst_auto_remediator.gha_analysis.validator import (
    is_shell_supported,
    is_runner_supported,
    is_style_supported,
    is_expression_single_quoted,
)
from cst_auto_remediator.gha_analysis.diagnostics import (
    make_ana001,
    make_ana002,
    make_ana003,
    make_ana004,
    make_ana005,
)


def analyze_workflow(workflow: Any, metadata: Any) -> SecurityAnalysisResult:
    """
    Perform a complete Stage 5 Security Analysis on a parsed workflow.
    Returns an immutable SecurityAnalysisResult object.
    """
    if workflow is None:
        return SecurityAnalysisResult(
            workflow=None,
            diagnostics=[],
            statistics=AnalysisStatistics(),
            summary={"status": "invalid_workflow"},
        )

    # 1. Structural Schema Validation Check
    semantic_res = build_semantic_model(workflow.node)
    errors = [d for d in semantic_res.diagnostics if d.level == "error"]
    if errors:
        # Bailout early on invalid structure
        return SecurityAnalysisResult(
            workflow=workflow,
            diagnostics=errors,
            statistics=AnalysisStatistics(bailouts=1),
            summary={"status": "invalid_structure", "bailout_reason": BailoutReason.INVALID_STRUCTURE},
        )

    expression_classifications: dict[str, ExpressionClassification] = {}
    collected_diagnostics = list(semantic_res.diagnostics)  # Carry structural warnings/infos if any

    stats = {
        "total_expressions": 0,
        "trusted_expressions": 0,
        "untrusted_expressions": 0,
        "unknown_expressions": 0,
        "bailouts": 0,
        "needs_remediation": 0,
        "skipped": 0,
        "safe": 0,
    }

    # Iterate jobs and steps
    for job_id, job in workflow.jobs.items():
        for step in job.steps:
            # Resolve Stage 4 metadata facts
            shell_meta = metadata.get(ShellProvider, step)
            scope_meta = metadata.get(ScopeProvider, step)

            is_shell_ok = is_shell_supported(shell_meta.effective_shell) if shell_meta else True
            is_runner_ok = is_runner_supported(shell_meta.runner_default) if shell_meta else True

            # Extract step expressions
            run_exprs = step.run_command.expression_sites if step.run_command is not None else []
            env_exprs = []
            for binding in step.env_bindings:
                env_exprs.extend(binding.expression_sites)

            for expr in run_exprs:
                stats["total_expressions"] += 1
                expr_meta = metadata.get(ExpressionProvider, expr)
                stable_id = expr_meta.stable_id if expr_meta else f"expr.run.{stats['total_expressions']}"

                trust, source = classify_expression(expr.expression_body, scope_meta)
                if trust is TrustLevel.TRUSTED:
                    stats["trusted_expressions"] += 1
                elif trust in (TrustLevel.UNTRUSTED, TrustLevel.MIXED):
                    stats["untrusted_expressions"] += 1
                else:
                    stats["unknown_expressions"] += 1

                bailout = BailoutReason.NONE
                decision = AnalysisDecision.SAFE
                expr_diags = []

                # Block Scalar check
                style = step.run_command.command.style if step.run_command else "PLAIN"
                if not is_style_supported(style):
                    bailout = BailoutReason.BLOCK_SCALAR
                    decision = AnalysisDecision.BAILOUT
                    expr_diags.append(make_ana003(expr.node.span, style))

                # Unsupported Runner check
                elif not is_runner_ok:
                    bailout = BailoutReason.UNSUPPORTED_RUNNER
                    decision = AnalysisDecision.BAILOUT
                    expr_diags.append(make_ana002(expr.node.span, shell_meta.runner_default))

                # Unsupported Shell check
                elif not is_shell_ok:
                    bailout = BailoutReason.UNSUPPORTED_SHELL
                    decision = AnalysisDecision.BAILOUT
                    expr_diags.append(make_ana002(expr.node.span, shell_meta.effective_shell))

                # Single Quoted expression check
                elif is_expression_single_quoted(step.run_command.command.value, expr.start_offset, expr.end_offset):
                    decision = AnalysisDecision.SKIP
                    # Quoting prevents shell expansion of variables, rendering it safe in its current form but skipped
                    expr_diags.append(make_ana005(expr.node.span, expr.expression_text))

                # Risk and Trust assessment for active execution sink
                else:
                    if trust in (TrustLevel.UNTRUSTED, TrustLevel.MIXED):
                        decision = AnalysisDecision.REMEDIATE
                        expr_diags.append(make_ana004(expr.node.span, expr.expression_text))
                    elif trust is TrustLevel.UNKNOWN:
                        bailout = BailoutReason.UNKNOWN_SOURCE
                        decision = AnalysisDecision.BAILOUT
                        expr_diags.append(make_ana001(expr.node.span, expr.expression_text))
                    else:
                        decision = AnalysisDecision.SAFE
                        expr_diags.append(make_ana005(expr.node.span, expr.expression_text))

                # Update Decision Statistics
                if decision is AnalysisDecision.SAFE:
                    stats["safe"] += 1
                elif decision is AnalysisDecision.REMEDIATE:
                    stats["needs_remediation"] += 1
                elif decision is AnalysisDecision.BAILOUT:
                    stats["bailouts"] += 1
                elif decision is AnalysisDecision.SKIP:
                    stats["skipped"] += 1

                classification = ExpressionClassification(
                    expression_site=expr,
                    stable_expression_id=stable_id,
                    trust_level=trust,
                    source_kind=source,
                    sink_kind=SinkKind.RUN_COMMAND,
                    decision=decision,
                    bailout_reason=bailout,
                    shell=shell_meta,
                    scope=scope_meta,
                    diagnostics=expr_diags,
                )
                expression_classifications[stable_id] = classification
                collected_diagnostics.extend(expr_diags)

            for expr in env_exprs:
                stats["total_expressions"] += 1
                expr_meta = metadata.get(ExpressionProvider, expr)
                stable_id = expr_meta.stable_id if expr_meta else f"expr.env.{stats['total_expressions']}"

                trust, source = classify_expression(expr.expression_body, scope_meta)
                if trust is TrustLevel.TRUSTED:
                    stats["trusted_expressions"] += 1
                elif trust in (TrustLevel.UNTRUSTED, TrustLevel.MIXED):
                    stats["untrusted_expressions"] += 1
                else:
                    stats["unknown_expressions"] += 1

                # Environment assignment is a safe sink; skip remediation
                decision = AnalysisDecision.SKIP
                bailout = BailoutReason.DEFERRED_ENV_REMEDIATION
                stats["skipped"] += 1

                classification = ExpressionClassification(
                    expression_site=expr,
                    stable_expression_id=stable_id,
                    trust_level=trust,
                    source_kind=source,
                    sink_kind=SinkKind.ENV_ASSIGNMENT,
                    decision=decision,
                    bailout_reason=bailout,
                    shell=shell_meta,
                    scope=scope_meta,
                    diagnostics=[],
                )
                expression_classifications[stable_id] = classification

    # Consolidate statistics dataclass
    statistics = AnalysisStatistics(
        total_expressions=stats["total_expressions"],
        trusted_expressions=stats["trusted_expressions"],
        untrusted_expressions=stats["untrusted_expressions"],
        unknown_expressions=stats["unknown_expressions"],
        bailouts=stats["bailouts"],
        needs_remediation=stats["needs_remediation"],
        skipped=stats["skipped"],
        safe=stats["safe"],
    )

    summary = {
        "status": "success",
        "total_expressions": stats["total_expressions"],
        "needs_remediation": stats["needs_remediation"],
        "bailouts": stats["bailouts"],
    }

    return SecurityAnalysisResult(
        workflow=workflow,
        expression_classifications=expression_classifications,
        diagnostics=collected_diagnostics,
        statistics=statistics,
        summary=summary,
    )
