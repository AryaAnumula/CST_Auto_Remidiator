"""
Stage 8 Verification shared helper utilities.
"""

from __future__ import annotations

from typing import Any
from cst_auto_remediator.yaml_cst.nodes import YamlMapping, YamlSequence, YamlScalar
from cst_auto_remediator.gha_verify.report import VerificationFinding, VerificationDecision
from cst_auto_remediator.gha_semantic.builder import build_semantic_model


def to_primitive(node: Any) -> Any:
    """Recursively convert any YAML representation (ruamel, CST, standard) to python primitives."""
    if node is None:
        return None
    if hasattr(node, "value") and not isinstance(node, YamlScalar):
        return to_primitive(node.value)
    if isinstance(node, dict):
        return {str(k): to_primitive(v) for k, v in node.items()}
    if isinstance(node, (list, tuple)):
        return [to_primitive(x) for x in node]
    if isinstance(node, YamlMapping):
        return {str(entry.key.value): to_primitive(entry.value) for entry in node.entries}
    if isinstance(node, YamlSequence):
        return [to_primitive(item) for item in node.items]
    if isinstance(node, YamlScalar):
        return node.value
    # Support mapping-like/sequence-like properties of ruamel custom types
    if hasattr(node, "keys") and hasattr(node, "values"):
        return {str(k): to_primitive(node[k]) for k in node.keys()}
    return node


def find_entry_value(mapping: Any, key: str) -> Any | None:
    """Locate a key's value in a YamlMapping node."""
    if not isinstance(mapping, YamlMapping):
        return None
    for entry in mapping.entries:
        if isinstance(entry.key, YamlScalar) and entry.key.value == key:
            return entry.value
    return None


def get_mutated_step_indices(context: Any) -> set[tuple[str, int]]:
    """Determine the job ID and step indices of mutated steps by comparing original and remediated runs."""
    mutated = set()
    orig_sem = context.original_semantic or build_semantic_model(context.original_cst)
    
    # Safely rebuild remediated semantic model if not present or fails
    rem_sem = context.remediated_semantic
    if rem_sem is None:
        try:
            from cst_auto_remediator.yaml_cst.parser import parse_yaml
            from cst_auto_remediator.yaml_cst.builder import build_cst
            doc, meta = parse_yaml(context.remediated_yaml.encode("utf-8"))
            rem_cst = build_cst(doc, meta)
            rem_sem = build_semantic_model(rem_cst)
        except Exception:
            pass

    if orig_sem and rem_sem and orig_sem.workflow and rem_sem.workflow:
        for job_id, oj in orig_sem.workflow.jobs.items():
            rj = rem_sem.workflow.jobs.get(job_id)
            if not rj:
                continue
            for idx, (os, rs) in enumerate(zip(oj.steps, rj.steps)):
                run_orig = to_primitive(find_entry_value(os.node, "run"))
                run_rem = to_primitive(find_entry_value(rs.node, "run"))
                if run_orig != run_rem:
                    mutated.add((job_id, idx))
    return mutated


def compare_property(
    expected_node: Any,
    actual_node: Any,
    property_name: str,
    location: dict[str, Any],
    workflow_path: str = "unknown",
    suggestion: str | None = None
) -> VerificationFinding | None:
    """Compare two nodes, normalize to primitives, and generate consistent diagnostics if different."""
    expected_val = to_primitive(expected_node)
    actual_val = to_primitive(actual_node)
    if expected_val != actual_val:
        job_id = location.get("job_id")
        step_index = location.get("step_index")
        
        msg_parts = [f"Semantic mismatch in property '{property_name}'"]
        if job_id:
            msg_parts.append(f"job ID: '{job_id}'")
        if step_index is not None:
            msg_parts.append(f"step index: {step_index}")
        msg_parts.append(f"expected: {expected_val!r}")
        msg_parts.append(f"actual: {actual_val!r}")
        if suggestion:
            msg_parts.append(f"suggestion: {suggestion}")
        
        msg = " - ".join(msg_parts)
        return VerificationFinding(
            code="VER002",
            severity=VerificationDecision.FAIL,
            message=msg,
            path=workflow_path,
        )
    return None
