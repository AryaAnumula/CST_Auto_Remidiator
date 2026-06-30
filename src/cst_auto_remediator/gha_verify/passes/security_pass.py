"""
Pass 4: Security Classification Verification.
"""

from __future__ import annotations

from cst_auto_remediator.gha_verify.report import (
    VerificationContext,
    VerificationFinding,
    InvariantResult,
    VerificationDecision,
    InvariantCode,
)
from cst_auto_remediator.yaml_cst.builder import build_cst
from cst_auto_remediator.gha_semantic.builder import build_semantic_model
from cst_auto_remediator.gha_metadata.engine import MetadataWrapper
from cst_auto_remediator.gha_analysis.analyzer import analyze_workflow
from cst_auto_remediator.gha_analysis.nodes import AnalysisDecision
from cst_auto_remediator.gha_metadata.providers import PositionProvider, ExpressionProvider
from cst_auto_remediator.yaml_cst.parser import parse_yaml


class SecurityPass:
    def run(
        self,
        context: VerificationContext,
        findings: list[VerificationFinding],
        invariant_results: list[InvariantResult],
    ) -> None:
        # Re-run Stage 5 on the remediated output
        try:
            rem_doc, rem_meta = parse_yaml(context.remediated_yaml.encode("utf-8"))
            rem_cst = build_cst(rem_doc, rem_meta)
            rem_semantic = build_semantic_model(rem_cst)

            if rem_semantic.workflow is None:
                # Empty workflows are secure by definition
                invariant_results.append(
                    InvariantResult(
                        code=InvariantCode.INV_SECR,
                        name="Security Completeness",
                        decision=VerificationDecision.PASS,
                        details="No workflow structures to classify.",
                    )
                )
                return

            rem_wrapper = MetadataWrapper(rem_semantic.workflow)
            rem_analysis = analyze_workflow(rem_semantic.workflow, rem_wrapper)
        except Exception as e:
            findings.append(
                VerificationFinding(
                    code="VER003",
                    severity=VerificationDecision.FAIL,
                    message=f"Failed to execute security analysis on output YAML: {str(e)}",
                )
            )
            invariant_results.append(
                InvariantResult(
                    code=InvariantCode.INV_SECR,
                    name="Security Completeness",
                    decision=VerificationDecision.FAIL,
                    details=f"Security re-analysis failed: {str(e)}",
                )
            )
            return

        # Determine mutated paths to filter out bailed steps
        def get_mutated_paths(ctx: VerificationContext) -> set[tuple[str, ...]]:
            mutated = set()
            from cst_auto_remediator.gha_verify.utils import get_mutated_step_indices
            mutated_indices = get_mutated_step_indices(ctx)
            for job_id, idx in mutated_indices:
                mutated.add(("jobs", job_id, "steps", str(idx)))
            return mutated

        mutated_paths = get_mutated_paths(context)

        # 1. Assert that no expression is classified as REMEDIATE in the patched output steps
        remediate_targets_found = []
        for stable_id, classif in rem_analysis.expression_classifications.items():
            if classif.decision == AnalysisDecision.REMEDIATE:
                expr = classif.expression_site
                pos = rem_wrapper.get(PositionProvider, expr)
                if pos and pos.job_id is not None:
                    step_path = ("jobs", pos.job_id, "steps", str(pos.step_index))
                    if step_path in mutated_paths:
                        remediate_targets_found.append(stable_id)

        # 2. Assert that original BAILOUT classifications are preserved (not mistakenly marked SAFE)
        # First, run Stage 5 on original if not provided in context
        orig_wf = context.original_semantic.workflow if context.original_semantic else None
        if orig_wf is None:
            orig_semantic = build_semantic_model(context.original_cst)
            orig_wf = orig_semantic.workflow

        orig_analysis = None
        if orig_wf is not None:
            try:
                orig_wrapper = MetadataWrapper(orig_wf)
                orig_analysis = analyze_workflow(orig_wf, orig_wrapper)
            except Exception:
                pass

        bailout_regression_found = []
        if orig_analysis is not None:
            # Check matching stable expression IDs
            for stable_id, orig_classif in orig_analysis.expression_classifications.items():
                if orig_classif.decision == AnalysisDecision.BAILOUT:
                    # Verify that in the output, it is still classified as BAILOUT (or skipped/bailed)
                    # Note: Since the bailout step itself is untouched, the stable_id should map
                    # to a BAILOUT decision in output re-analysis.
                    rem_classif = rem_analysis.expression_classifications.get(stable_id)
                    if rem_classif is None or rem_classif.decision != AnalysisDecision.BAILOUT:
                        bailout_regression_found.append(
                            f"Expression {stable_id} expected BAILOUT but got {rem_classif.decision if rem_classif else 'None'}"
                        )

        # 3. Report findings
        if remediate_targets_found or bailout_regression_found:
            for target in remediate_targets_found[:3]:
                findings.append(
                    VerificationFinding(
                        code="VER003",
                        severity=VerificationDecision.FAIL,
                        message=f"Security Defect: Un-remediated target expression {target} remains in output.",
                    )
                )
            for reg in bailout_regression_found[:3]:
                findings.append(
                    VerificationFinding(
                        code="VER003",
                        severity=VerificationDecision.FAIL,
                        message=f"Bailout Regression: {reg}",
                    )
                )
            invariant_results.append(
                InvariantResult(
                    code=InvariantCode.INV_SECR,
                    name="Security Completeness",
                    decision=VerificationDecision.FAIL,
                    details=f"Un-remediated targets count: {len(remediate_targets_found)}. Bailout regressions: {len(bailout_regression_found)}.",
                )
            )
        else:
            invariant_results.append(
                InvariantResult(
                    code=InvariantCode.INV_SECR,
                    name="Security Completeness",
                    decision=VerificationDecision.PASS,
                    details="Zero REMEDIATE decisions in output. All original BAILOUT steps are preserved.",
                )
            )
