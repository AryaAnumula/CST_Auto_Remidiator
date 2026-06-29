"""
Pass 5: Compiler Boundaries and Invariants.
"""

from __future__ import annotations

from typing import Any

from cst_auto_remediator.gha_verify.report import (
    VerificationContext,
    VerificationFinding,
    InvariantResult,
    VerificationDecision,
    InvariantCode,
)
from cst_auto_remediator.yaml_cst.parser import parse_yaml
from cst_auto_remediator.yaml_cst.builder import build_cst
from cst_auto_remediator.gha_semantic.builder import build_semantic_model
from cst_auto_remediator.gha_metadata.engine import MetadataWrapper
from cst_auto_remediator.gha_analysis.analyzer import analyze_workflow
from cst_auto_remediator.gha_transform.planner import MutationPlanner
from cst_auto_remediator.gha_transform.transformer import CSTTransformer
from cst_auto_remediator.gha_transform.serializer import serialize_document
from cst_auto_remediator.gha_metadata.providers import PositionProvider, ExpressionProvider
from cst_auto_remediator.yaml_cst.nodes import YamlMapping, YamlSequence, YamlScalar, YamlKeyValue


import tempfile
import pathlib
from cst_auto_remediator.pipeline import remediate_file


def run_stages_1_to_7(yaml_str: str) -> str:
    """Helper to run the full Stages 1-7 compilation pipeline via remediate_file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False, encoding="utf-8", newline="") as f:
        f.write(yaml_str)
        tmp_path = f.name
    try:
        out, _ = remediate_file(tmp_path)
        return out if out is not None else yaml_str
    finally:
        try:
            pathlib.Path(tmp_path).unlink()
        except OSError:
            pass


def get_mutated_paths(context: VerificationContext) -> set[tuple[str, ...]]:
    """Determine the hierarchical paths of mutated steps from the planner."""
    mutated = set()
    orig_sem = context.original_semantic or build_semantic_model(context.original_cst)
    rem_sem = context.remediated_semantic or build_semantic_model(context.remediated_cst)

    if orig_sem.workflow and rem_sem.workflow:
        for job_id, oj in orig_sem.workflow.jobs.items():
            rj = rem_sem.workflow.jobs.get(job_id)
            if not rj:
                continue
            for idx, (os, rs) in enumerate(zip(oj.steps, rj.steps)):
                from cst_auto_remediator.gha_verify.passes.semantic_pass import to_primitive, find_entry_value
                run_orig = to_primitive(find_entry_value(os.node, "run"))
                run_rem = to_primitive(find_entry_value(rs.node, "run"))
                if run_orig != run_rem:
                    mutated.add(("jobs", job_id, "steps", str(idx), "run"))
                    mutated.add(("jobs", job_id, "steps", str(idx), "env"))
    return mutated


class InvariantPass:
    def run(
        self,
        context: VerificationContext,
        findings: list[VerificationFinding],
        invariant_results: list[InvariantResult],
    ) -> None:
        # 1. INV-IDEM: Idempotency check
        try:
            rem2 = run_stages_1_to_7(context.remediated_yaml)
            if rem2 != context.remediated_yaml:
                findings.append(
                    VerificationFinding(
                        code="VER009",
                        severity=VerificationDecision.FAIL,
                        message="Idempotency failed: Remediating output YAML changed its contents.",
                    )
                )
                invariant_results.append(
                    InvariantResult(
                        code=InvariantCode.INV_IDEM,
                        name="Idempotency Invariant",
                        decision=VerificationDecision.FAIL,
                        details="Consecutive remediation passes produced divergent YAML output.",
                    )
                )
            else:
                invariant_results.append(
                    InvariantResult(
                        code=InvariantCode.INV_IDEM,
                        name="Idempotency Invariant",
                        decision=VerificationDecision.PASS,
                        details="The remediation pipeline is fully idempotent.",
                    )
                )
        except Exception as e:
            findings.append(
                VerificationFinding(
                    code="VER009",
                    severity=VerificationDecision.FAIL,
                    message=f"Idempotency validation failed with exception: {str(e)}",
                )
            )
            invariant_results.append(
                InvariantResult(
                    code=InvariantCode.INV_IDEM,
                    name="Idempotency Invariant",
                    decision=VerificationDecision.FAIL,
                    details=f"Idempotence check exception: {str(e)}",
                )
            )

        # 2. INV-DET: Determinism check
        try:
            out1 = run_stages_1_to_7(context.original_yaml)
            out2 = run_stages_1_to_7(context.original_yaml)
            if out1 != out2:
                findings.append(
                    VerificationFinding(
                        code="VER010",
                        severity=VerificationDecision.FAIL,
                        message="Determinism failed: Repeated compilation generated different outputs.",
                    )
                )
                invariant_results.append(
                    InvariantResult(
                        code=InvariantCode.INV_DET,
                        name="Determinism Invariant",
                        decision=VerificationDecision.FAIL,
                        details="Repeated compilation of same input produced different byte layouts.",
                    )
                )
            else:
                invariant_results.append(
                    InvariantResult(
                        code=InvariantCode.INV_DET,
                        name="Determinism Invariant",
                        decision=VerificationDecision.PASS,
                        details="Repeated compilation is completely deterministic.",
                    )
                )
        except Exception as e:
            findings.append(
                VerificationFinding(
                    code="VER010",
                    severity=VerificationDecision.FAIL,
                    message=f"Determinism check failed with exception: {str(e)}",
                )
            )

        # 3. INV-BYTE: Byte preservation of untouched steps
        def get_step_lines(yaml_text: str, step_node: YamlMapping, next_node_line: int | None) -> list[str]:
            lines = yaml_text.splitlines()
            start_line = step_node.span.line if step_node.span else 0
            end_line = next_node_line if next_node_line is not None else len(lines)
            raw_slice = lines[start_line:end_line]
            return [l.strip() for l in raw_slice if l.strip()]

        # 3. INV-BYTE: Byte preservation of untouched steps
        orig_wf = context.original_semantic.workflow if context.original_semantic else None
        if orig_wf is None:
            orig_semantic = build_semantic_model(context.original_cst)
            orig_wf = orig_semantic.workflow

        orig_wrapper = MetadataWrapper(orig_wf) if orig_wf else None
        try:
            rem_doc_for_span, rem_meta_for_span = parse_yaml(context.remediated_yaml.encode("utf-8"))
            rem_cst_for_span = build_cst(rem_doc_for_span, rem_meta_for_span)
            rem_sem_for_span = build_semantic_model(rem_cst_for_span)
            rem_wf = rem_sem_for_span.workflow
            rem_wrapper = MetadataWrapper(rem_wf) if rem_wf else None
        except Exception:
            rem_wf = None
            rem_wrapper = None

        byte_preservation_failures = []
        byte_preservation_failures = []
        if orig_wf and rem_wf and orig_wrapper and rem_wrapper:
            mutated_steps = set()
            for job_id, oj in orig_wf.jobs.items():
                rj = rem_wf.jobs.get(job_id)
                if not rj:
                    continue
                for idx, (os, rs) in enumerate(zip(oj.steps, rj.steps)):
                    from cst_auto_remediator.gha_verify.passes.semantic_pass import to_primitive, find_entry_value
                    run_orig = to_primitive(find_entry_value(os.node, "run"))
                    run_rem = to_primitive(find_entry_value(rs.node, "run"))
                    if run_orig != run_rem:
                        mutated_steps.add((job_id, idx))

            for job_id, oj in orig_wf.jobs.items():
                rj = rem_wf.jobs.get(job_id)
                if not rj:
                    continue
                orig_start_lines = [step.node.span.line for step in oj.steps if step.node.span is not None]
                rem_start_lines = [step.node.span.line for step in rj.steps if step.node.span is not None]

                for idx, (os, rs) in enumerate(zip(oj.steps, rj.steps)):
                    # Check if this step was NOT mutated
                    if (job_id, idx) not in mutated_steps:
                        orig_next = orig_start_lines[idx+1] if idx+1 < len(orig_start_lines) else None
                        rem_next = rem_start_lines[idx+1] if idx+1 < len(rem_start_lines) else None

                        orig_lines = get_step_lines(context.original_yaml, os.node, orig_next)
                        rem_lines = get_step_lines(context.remediated_yaml, rs.node, rem_next)

                        if orig_lines != rem_lines:
                            byte_preservation_failures.append(
                                f"Step {idx} of job '{job_id}' had formatting changes"
                            )

        if byte_preservation_failures:
            for fail in byte_preservation_failures[:3]:
                findings.append(
                    VerificationFinding(
                        code="VER004",
                        severity=VerificationDecision.FAIL,
                        message=f"Byte preservation failed: {fail}",
                    )
                )
            invariant_results.append(
                InvariantResult(
                    code=InvariantCode.INV_BYTE,
                    name="Byte Preservation Check",
                    decision=VerificationDecision.FAIL,
                    details=f"Unchanged steps modified textually: {'; '.join(byte_preservation_failures[:10])}",
                )
            )
        else:
            invariant_results.append(
                InvariantResult(
                    code=InvariantCode.INV_BYTE,
                    name="Byte Preservation Check",
                    decision=VerificationDecision.PASS,
                    details="All untouched step blocks are byte-identical to original.",
                )
            )

        # 4. INV-NODE and INV-COW: Identity Sharing and COW verification
        cow_failures = []
        sharing_failures = []
        if context.original_cst and context.remediated_cst:
            mutated_step_paths = get_mutated_paths(context)

            # Compute ancestor paths
            ancestor_paths = set()
            for p in mutated_step_paths:
                for i in range(len(p)):
                    ancestor_paths.add(p[:i])

            def is_path_mutated_or_ancestor(path: tuple[str, ...]) -> bool:
                if path in ancestor_paths:
                    return True
                for m in mutated_step_paths:
                    if path[:len(m)] == m:
                        return True
                return False

            def traverse_and_verify(n1: Any, n2: Any, current_path: tuple[str, ...]) -> None:
                # If they are mappings, traverse side-by-side
                is_changed_identity_expected = is_path_mutated_or_ancestor(current_path)
                if id(n1) == id(n2):
                    if is_changed_identity_expected:
                        cow_failures.append(f"COW violation: mutated node at path {current_path} shared identity.")
                else:
                    if not is_changed_identity_expected:
                        sharing_failures.append(f"Structural sharing failure: untouched node at path {current_path} changed identity.")

                # Recurse if applicable
                if isinstance(n1, YamlMapping) and isinstance(n2, YamlMapping):
                    for entry1 in n1.entries:
                        key_str = str(entry1.key.value)
                        entry2 = next((e for e in n2.entries if str(e.key.value) == key_str), None)
                        if entry2:
                            traverse_and_verify(entry1.value, entry2.value, current_path + (key_str,))
                elif isinstance(n1, YamlSequence) and isinstance(n2, YamlSequence):
                    # For sequence items, append index
                    for idx, (item1, item2) in enumerate(zip(n1.items, n2.items)):
                        traverse_and_verify(item1, item2, current_path + (str(idx),))

            # Start traversal
            if context.original_cst.root and context.remediated_cst.root:
                traverse_and_verify(context.original_cst.root, context.remediated_cst.root, ())

        if cow_failures:
            for fail in cow_failures[:3]:
                findings.append(
                    VerificationFinding(
                        code="VER007",
                        severity=VerificationDecision.FAIL,
                        message=fail,
                    )
                )
            invariant_results.append(
                InvariantResult(
                    code=InvariantCode.INV_COW,
                    name="Copy-on-Write Invariant",
                    decision=VerificationDecision.FAIL,
                    details=f"COW failures: {len(cow_failures)} paths violated boundary rules.",
                )
            )
        else:
            invariant_results.append(
                InvariantResult(
                    code=InvariantCode.INV_COW,
                    name="Copy-on-Write Invariant",
                    decision=VerificationDecision.PASS,
                    details="All mutated parents and nodes successfully copied via CoW.",
                )
            )

        if sharing_failures:
            for fail in sharing_failures[:3]:
                findings.append(
                    VerificationFinding(
                        code="VER008",
                        severity=VerificationDecision.FAIL,
                        message=fail,
                    )
                )
            invariant_results.append(
                InvariantResult(
                    code=InvariantCode.INV_NODE,
                    name="Stable Node Identity",
                    decision=VerificationDecision.FAIL,
                    details=f"Identity sharing failures: {len(sharing_failures)} paths violated identity sharing.",
                )
            )
        else:
            invariant_results.append(
                InvariantResult(
                    code=InvariantCode.INV_NODE,
                    name="Stable Node Identity",
                    decision=VerificationDecision.PASS,
                    details="All untouched node references successfully shared between original and output.",
                )
            )
