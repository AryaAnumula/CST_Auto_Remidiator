"""
Stage 8 orchestrator for verification and certification.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from cst_auto_remediator.gha_verify.report import (
    VerificationContext,
    VerificationReport,
    VerificationDecision,
    VerificationStatistics,
)
from cst_auto_remediator.gha_verify.passes.syntax_pass import SyntaxPass
from cst_auto_remediator.gha_verify.passes.semantic_pass import SemanticPass
from cst_auto_remediator.gha_verify.passes.format_pass import FormatPass
from cst_auto_remediator.gha_verify.passes.security_pass import SecurityPass
from cst_auto_remediator.gha_verify.passes.invariant_pass import InvariantPass


def verify_output(context: VerificationContext) -> VerificationReport:
    """
    Execute Pass 1 to Pass 5 post-remediation checks and produce a Certification Report.
    """
    start_time = time.perf_counter()

    findings = []
    invariant_results = []

    # Instantiate and run passes
    passes = [
        SyntaxPass(),
        SemanticPass(),
        FormatPass(),
        SecurityPass(),
        InvariantPass(),
    ]

    for p in passes:
        try:
            p.run(context, findings, invariant_results)
        except Exception as e:
            # Trap any internal verifier exceptions
            from cst_auto_remediator.gha_verify.report import VerificationFinding
            findings.append(
                VerificationFinding(
                    code="VER012",
                    severity=VerificationDecision.FAIL,
                    message=f"Internal verifier error in pass {p.__class__.__name__}: {str(e)}",
                )
            )

    # Determine overall decision
    has_fail = any(f.severity == VerificationDecision.FAIL for f in findings)
    has_warn = any(f.severity == VerificationDecision.WARNING for f in findings)

    if has_fail:
        decision = VerificationDecision.FAIL
    elif has_warn:
        decision = VerificationDecision.WARNING
    else:
        decision = VerificationDecision.PASS

    # Statistics assembly
    total_invariants = len(invariant_results)
    passed_invariants = sum(1 for r in invariant_results if r.decision == VerificationDecision.PASS)
    failed_invariants = total_invariants - passed_invariants

    findings_by_severity = {
        VerificationDecision.FAIL: sum(1 for f in findings if f.severity == VerificationDecision.FAIL),
        VerificationDecision.WARNING: sum(1 for f in findings if f.severity == VerificationDecision.WARNING),
        VerificationDecision.SKIP: sum(1 for f in findings if f.severity == VerificationDecision.SKIP),
        VerificationDecision.PASS: sum(1 for f in findings if f.severity == VerificationDecision.PASS),
    }

    execution_time_ms = (time.perf_counter() - start_time) * 1000.0

    stats = VerificationStatistics(
        total_invariants_checked=total_invariants,
        passed_invariants=passed_invariants,
        failed_invariants=failed_invariants,
        findings_by_severity=findings_by_severity,
        execution_time_ms=execution_time_ms,
    )

    summary = (
        f"Verification completed with decision {decision.value}. "
        f"Checked {total_invariants} invariants. "
        f"Passed: {passed_invariants}, Failed: {failed_invariants}. "
        f"Total findings: {len(findings)}."
    )

    return VerificationReport(
        decision=decision,
        findings=findings,
        invariant_results=invariant_results,
        stats=stats,
        summary=summary,
        compiler_version="1.0.0",
        verifier_version="1.0.0",
        timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    )
