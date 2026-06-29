"""
Pass 1: Syntax and Parse Integrity.
"""

from __future__ import annotations

from cst_auto_remediator.gha_verify.report import (
    VerificationContext,
    VerificationFinding,
    InvariantResult,
    VerificationDecision,
    InvariantCode,
)
from cst_auto_remediator.yaml_cst.parser import parse_yaml, ParsingError


class SyntaxPass:
    def run(
        self,
        context: VerificationContext,
        findings: list[VerificationFinding],
        invariant_results: list[InvariantResult],
    ) -> None:
        try:
            # Parse the remediated YAML bytes
            doc, meta = parse_yaml(context.remediated_yaml.encode("utf-8"))
            invariant_results.append(
                InvariantResult(
                    code=InvariantCode.INV_LINE,
                    name="Syntax Parse Integrity",
                    decision=VerificationDecision.PASS,
                    details="Output parsed successfully under Stage 1 constraints.",
                )
            )
        except ParsingError as e:
            findings.append(
                VerificationFinding(
                    code="VER001",
                    severity=VerificationDecision.FAIL,
                    message=f"Parse failure on output YAML: {str(e)}",
                )
            )
            invariant_results.append(
                InvariantResult(
                    code=InvariantCode.INV_LINE,
                    name="Syntax Parse Integrity",
                    decision=VerificationDecision.FAIL,
                    details=f"Parse error: {str(e)}",
                )
            )
