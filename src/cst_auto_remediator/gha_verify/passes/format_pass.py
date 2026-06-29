"""
Pass 3: Layout and Spacing Preservation.
"""

from __future__ import annotations

import re

from cst_auto_remediator.gha_verify.report import (
    VerificationContext,
    VerificationFinding,
    InvariantResult,
    VerificationDecision,
    InvariantCode,
)


def extract_comments(text: str) -> list[str]:
    """Extract comment contents ignoring '#' inside quotes."""
    comments = []
    for line in text.splitlines():
        in_quote = None
        for idx, char in enumerate(line):
            if char in ("'", '"'):
                if in_quote is None:
                    in_quote = char
                elif in_quote == char:
                    in_quote = None
            elif char == '#' and in_quote is None:
                comments.append(line[idx:].strip())
                break
    return comments


class FormatPass:
    def run(
        self,
        context: VerificationContext,
        findings: list[VerificationFinding],
        invariant_results: list[InvariantResult],
    ) -> None:
        # 1. Verify CRLF/LF Line Endings
        orig_crlf = "\r\n" in context.original_yaml
        rem_crlf = "\r\n" in context.remediated_yaml

        if orig_crlf != rem_crlf:
            findings.append(
                VerificationFinding(
                    code="VER006",
                    severity=VerificationDecision.WARNING,
                    message=f"Line endings not preserved. Original CRLF: {orig_crlf}, Output CRLF: {rem_crlf}",
                )
            )
            invariant_results.append(
                InvariantResult(
                    code=InvariantCode.INV_LINE,
                    name="Line Endings Preservation",
                    decision=VerificationDecision.WARNING,
                    details=f"Line endings mismatch (CRLF vs LF).",
                )
            )
        else:
            invariant_results.append(
                InvariantResult(
                    code=InvariantCode.INV_LINE,
                    name="Line Endings Preservation",
                    decision=VerificationDecision.PASS,
                    details="Line ending structure is fully preserved.",
                )
            )

        # 2. Verify Comments Preservation
        orig_comments = extract_comments(context.original_yaml)
        rem_comments = extract_comments(context.remediated_yaml)

        if orig_comments != rem_comments:
            findings.append(
                VerificationFinding(
                    code="VER005",
                    severity=VerificationDecision.WARNING,
                    message=f"Comments drift/loss detected. Original comment count: {len(orig_comments)}, Output count: {len(rem_comments)}",
                )
            )
            invariant_results.append(
                InvariantResult(
                    code=InvariantCode.INV_COMM,
                    name="Comments Preservation",
                    decision=VerificationDecision.WARNING,
                    details=f"Original comments count: {len(orig_comments)}, Output comments count: {len(rem_comments)}",
                )
            )
        else:
            invariant_results.append(
                InvariantResult(
                    code=InvariantCode.INV_COMM,
                    name="Comments Preservation",
                    decision=VerificationDecision.PASS,
                    details="All comments and inline documentation are preserved exactly.",
                )
            )

        # 3. Verify Anchors, Aliases, and Merge Keys
        format_checks = []
        for symbol, name in (("&", "Anchor"), ("*", "Alias"), ("<<", "Merge Key")):
            orig_has = symbol in context.original_yaml
            rem_has = symbol in context.remediated_yaml
            if orig_has != rem_has:
                format_checks.append(f"{name} presence mismatch")

        if format_checks:
            for check in format_checks:
                findings.append(
                    VerificationFinding(
                        code="VER004",
                        severity=VerificationDecision.FAIL,
                        message=f"Formatting defect: {check}",
                    )
                )
            # Layout/Formatting invariant result
            invariant_results.append(
                InvariantResult(
                    code=InvariantCode.INV_BYTE,
                    name="Formatting Preservation",
                    decision=VerificationDecision.FAIL,
                    details="Anchors, aliases, or merge keys presence was altered.",
                )
            )
        else:
            # Check trailing newline preservation
            orig_trailing = context.original_yaml.endswith("\n") or context.original_yaml.endswith("\r")
            rem_trailing = context.remediated_yaml.endswith("\n") or context.remediated_yaml.endswith("\r")
            if orig_trailing != rem_trailing:
                findings.append(
                    VerificationFinding(
                        code="VER004",
                        severity=VerificationDecision.WARNING,
                        message="Trailing newline presence was altered.",
                    )
                )
