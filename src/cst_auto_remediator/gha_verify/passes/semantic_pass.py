"""
Pass 2: Complete Semantic Isomorphism.
"""

from __future__ import annotations

from typing import Any

from cst_auto_remediator.yaml_cst.nodes import YamlMapping, YamlSequence, YamlScalar
from cst_auto_remediator.gha_verify.report import (
    VerificationContext,
    VerificationFinding,
    InvariantResult,
    VerificationDecision,
    InvariantCode,
)
from cst_auto_remediator.yaml_cst.builder import build_cst
from cst_auto_remediator.gha_semantic.builder import build_semantic_model
from cst_auto_remediator.yaml_cst.parser import parse_yaml


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
    if not isinstance(mapping, YamlMapping):
        return None
    for entry in mapping.entries:
        if isinstance(entry.key, YamlScalar) and entry.key.value == key:
            return entry.value
    return None


class SemanticPass:
    def run(
        self,
        context: VerificationContext,
        findings: list[VerificationFinding],
        invariant_results: list[InvariantResult],
    ) -> None:
        # Re-build semantic models if not present in context
        orig_semantic = context.original_semantic
        if orig_semantic is None:
            orig_semantic = build_semantic_model(context.original_cst)

        rem_semantic = context.remediated_semantic
        if rem_semantic is None:
            try:
                doc, meta = parse_yaml(context.remediated_yaml.encode("utf-8"))
                rem_cst = build_cst(doc, meta)
                rem_semantic = build_semantic_model(rem_cst)
            except Exception as e:
                findings.append(
                    VerificationFinding(
                        code="VER002",
                        severity=VerificationDecision.FAIL,
                        message=f"Failed to rebuild semantic model for output: {str(e)}",
                    )
                )
                invariant_results.append(
                    InvariantResult(
                        code=InvariantCode.INV_SEME,
                        name="Semantic Equivalence Check",
                        decision=VerificationDecision.FAIL,
                        details="Rebuild of output semantic model failed.",
                    )
                )
                return

        orig_wf = orig_semantic.workflow
        rem_wf = rem_semantic.workflow

        if orig_wf is None or rem_wf is None:
            if (orig_wf is None) == (rem_wf is None):
                invariant_results.append(
                    InvariantResult(
                        code=InvariantCode.INV_SEME,
                        name="Semantic Equivalence Check",
                        decision=VerificationDecision.PASS,
                        details="Both original and output workflows are empty/null.",
                    )
                )
            else:
                findings.append(
                    VerificationFinding(
                        code="VER002",
                        severity=VerificationDecision.FAIL,
                        message="Workflow presence mismatch: one workflow is empty/null, the other is not.",
                    )
                )
                invariant_results.append(
                    InvariantResult(
                        code=InvariantCode.INV_SEME,
                        name="Semantic Equivalence Check",
                        decision=VerificationDecision.FAIL,
                        details="Workflow presence mismatch.",
                    )
                )
            return

        # 1. Compare global attributes
        global_mismatches = []
        name_orig = to_primitive(find_entry_value(orig_wf.node.root, "name"))
        name_rem = to_primitive(find_entry_value(rem_wf.node.root, "name"))
        if name_orig != name_rem:
            global_mismatches.append(f"workflow name mismatch: {name_orig} vs {name_rem}")

        trigger_orig = to_primitive(find_entry_value(orig_wf.node.root, "on"))
        trigger_rem = to_primitive(find_entry_value(rem_wf.node.root, "on"))
        if trigger_orig != trigger_rem:
            global_mismatches.append("workflow triggers mismatch")

        env_orig = to_primitive(find_entry_value(orig_wf.node.root, "env"))
        env_rem = to_primitive(find_entry_value(rem_wf.node.root, "env"))
        if env_orig != env_rem:
            global_mismatches.append("workflow global env mismatch")

        # 2. Compare jobs list
        orig_jobs = orig_wf.jobs
        rem_jobs = rem_wf.jobs

        if set(orig_jobs.keys()) != set(rem_jobs.keys()):
            global_mismatches.append(f"job keys mismatch: {list(orig_jobs.keys())} vs {list(rem_jobs.keys())}")

        for job_id in orig_jobs:
            if job_id not in rem_jobs:
                continue
            oj = orig_jobs[job_id]
            rj = rem_jobs[job_id]

            # Compare job structural settings
            if to_primitive(find_entry_value(oj.node, "needs")) != to_primitive(find_entry_value(rj.node, "needs")):
                global_mismatches.append(f"job '{job_id}' needs mismatch")
            if to_primitive(find_entry_value(oj.node, "runs-on")) != to_primitive(find_entry_value(rj.node, "runs-on")):
                global_mismatches.append(f"job '{job_id}' runs-on mismatch")
            if to_primitive(find_entry_value(oj.node, "env")) != to_primitive(find_entry_value(rj.node, "env")):
                global_mismatches.append(f"job '{job_id}' env mismatch")
            if to_primitive(find_entry_value(oj.node, "permissions")) != to_primitive(find_entry_value(rj.node, "permissions")):
                global_mismatches.append(f"job '{job_id}' permissions mismatch")
            if to_primitive(find_entry_value(oj.node, "strategy")) != to_primitive(find_entry_value(rj.node, "strategy")):
                global_mismatches.append(f"job '{job_id}' matrix/strategy mismatch")

            # Compare steps length
            if len(oj.steps) != len(rj.steps):
                global_mismatches.append(f"job '{job_id}' steps length mismatch: {len(oj.steps)} vs {len(rj.steps)}")
                continue

            # Compare steps structural attributes
            for idx, (os, rs) in enumerate(zip(oj.steps, rj.steps)):
                # Step structural items comparison
                for attr in ("id", "name", "uses", "with", "if", "continue-on-error", "timeout-minutes", "working-directory", "shell"):
                    val_orig = to_primitive(find_entry_value(os.node, attr))
                    val_rem = to_primitive(find_entry_value(rs.node, attr))
                    if val_orig != val_rem:
                        global_mismatches.append(f"job '{job_id}' step {idx} attribute '{attr}' mismatch: {val_orig} vs {val_rem}")

                # Compare step environment bindings (original must be subset of remediated)
                orig_env = {b.key.value: to_primitive(b.value) for b in os.env_bindings}
                rem_env = {b.key.value: to_primitive(b.value) for b in rs.env_bindings}
                for k, v in orig_env.items():
                    if k not in rem_env or rem_env[k] != v:
                        global_mismatches.append(f"job '{job_id}' step {idx} env binding '{k}' modified or missing in remediated")

                # If step is not mutated, run must be equal
                run_orig = to_primitive(find_entry_value(os.node, "run"))
                run_rem = to_primitive(find_entry_value(rs.node, "run"))
                if run_orig != run_rem:
                    # It was changed. If rs has extra variables in env, it was a remediation change.
                    extra_keys = set(rem_env.keys()) - set(orig_env.keys())
                    if not extra_keys:
                        # Modified run line without adding env vars! That's a semantic mismatch!
                        global_mismatches.append(f"job '{job_id}' step {idx} run command was modified but no remediation env var was added")

        if global_mismatches:
            for mismatch in global_mismatches[:5]:  # report first 5 mismatches
                findings.append(
                    VerificationFinding(
                        code="VER002",
                        severity=VerificationDecision.FAIL,
                        message=f"Semantic mismatch: {mismatch}",
                    )
                )
            invariant_results.append(
                InvariantResult(
                    code=InvariantCode.INV_SEME,
                    name="Semantic Equivalence Check",
                    decision=VerificationDecision.FAIL,
                    details=f"Semantic mismatches found: {'; '.join(global_mismatches[:10])}",
                )
            )
        else:
            invariant_results.append(
                InvariantResult(
                    code=InvariantCode.INV_SEME,
                    name="Semantic Equivalence Check",
                    decision=VerificationDecision.PASS,
                    details="All triggers, jobs, steps, matrices, and settings are isomorphic.",
                )
            )
