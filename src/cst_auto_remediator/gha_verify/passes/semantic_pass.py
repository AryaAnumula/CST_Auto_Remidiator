"""
Pass 2: Complete Semantic Isomorphism with Structural Run Verification.
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
from cst_auto_remediator.yaml_cst.builder import build_cst
from cst_auto_remediator.gha_semantic.builder import build_semantic_model
from cst_auto_remediator.yaml_cst.parser import parse_yaml

from cst_auto_remediator.gha_verify.utils import (
    to_primitive,
    find_entry_value,
    compare_property,
)


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

        # Extract workflow path for diagnostics
        workflow_path = "unknown"
        if context.original_metadata and hasattr(context.original_metadata, "path"):
            workflow_path = context.original_metadata.path

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
                        path=workflow_path,
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

        mismatches: list[VerificationFinding] = []

        # 1. Compare global workflow-level properties
        wf_suggestion = "Restore original workflow configuration (e.g. name, on, env, permissions, defaults, concurrency) unchanged."
        for prop in ("name", "on", "env", "permissions", "defaults", "concurrency"):
            finding = compare_property(
                expected_node=find_entry_value(orig_wf.node.root, prop),
                actual_node=find_entry_value(rem_wf.node.root, prop),
                property_name=prop,
                location={},
                workflow_path=workflow_path,
                suggestion=wf_suggestion,
            )
            if finding:
                mismatches.append(finding)

        # 2. Compare jobs list and order
        orig_jobs = orig_wf.jobs
        rem_jobs = rem_wf.jobs

        orig_job_keys = list(orig_jobs.keys())
        rem_job_keys = list(rem_jobs.keys())

        if orig_job_keys != rem_job_keys:
            mismatches.append(
                VerificationFinding(
                    code="VER002",
                    severity=VerificationDecision.FAIL,
                    message=(
                        f"Job keys or order mismatch. Expected jobs (in order): {orig_job_keys}, "
                        f"Actual jobs (in order): {rem_job_keys}."
                    ),
                    path=workflow_path,
                )
            )

        # 3. Deep compare each job
        for job_id in orig_job_keys:
            if job_id not in rem_jobs:
                continue
            oj = orig_jobs[job_id]
            rj = rem_jobs[job_id]

            job_location = {"job_id": job_id}
            job_suggestion = (
                "Ensure job attributes (needs, runs-on, env, permissions, strategy, timeout-minutes, "
                "defaults, outputs, container, services, concurrency, uses, if, environment, continue-on-error) "
                "are not altered."
            )

            # Job structural settings comparison
            job_properties = (
                "needs",
                "runs-on",
                "env",
                "permissions",
                "strategy",
                "timeout-minutes",
                "defaults",
                "outputs",
                "container",
                "services",
                "concurrency",
                "uses",
                "if",
                "environment",
                "continue-on-error",
            )
            for prop in job_properties:
                finding = compare_property(
                    expected_node=find_entry_value(oj.node, prop),
                    actual_node=find_entry_value(rj.node, prop),
                    property_name=prop,
                    location=job_location,
                    workflow_path=workflow_path,
                    suggestion=job_suggestion,
                )
                if finding:
                    mismatches.append(finding)

            # Compare steps length
            if len(oj.steps) != len(rj.steps):
                mismatches.append(
                    VerificationFinding(
                        code="VER002",
                        severity=VerificationDecision.FAIL,
                        message=(
                            f"job '{job_id}' steps length mismatch. Expected: {len(oj.steps)}, "
                            f"Actual: {len(rj.steps)}."
                        ),
                        path=workflow_path,
                    )
                )
                continue

            # Compare steps deep
            for idx, (os, rs) in enumerate(zip(oj.steps, rj.steps)):
                step_location = {"job_id": job_id, "step_index": idx}
                step_suggestion = (
                    "Ensure step attributes (id, name, uses, with, if, continue-on-error, "
                    "timeout-minutes, shell, working-directory) are not altered."
                )

                # Step structural items comparison
                step_properties = (
                    "id",
                    "name",
                    "uses",
                    "with",
                    "if",
                    "continue-on-error",
                    "timeout-minutes",
                    "shell",
                    "working-directory",
                )
                for attr in step_properties:
                    finding = compare_property(
                        expected_node=find_entry_value(os.node, attr),
                        actual_node=find_entry_value(rs.node, attr),
                        property_name=attr,
                        location=step_location,
                        workflow_path=workflow_path,
                        suggestion=step_suggestion,
                    )
                    if finding:
                        mismatches.append(finding)

                # Step environment bindings comparison
                orig_env = {b.key.value: to_primitive(b.value) for b in os.env_bindings}
                rem_env = {b.key.value: to_primitive(b.value) for b in rs.env_bindings}

                # Ensure original env variables are completely preserved and unmodified
                for k, v in orig_env.items():
                    if k not in rem_env:
                        mismatches.append(
                            VerificationFinding(
                                code="VER002",
                                severity=VerificationDecision.FAIL,
                                message=f"job '{job_id}' step {idx} env binding '{k}' was deleted.",
                                path=workflow_path,
                            )
                        )
                    elif rem_env[k] != v:
                        mismatches.append(
                            VerificationFinding(
                                code="VER002",
                                severity=VerificationDecision.FAIL,
                                message=(
                                    f"job '{job_id}' step {idx} env binding '{k}' was modified. "
                                    f"Expected: {v!r}, Actual: {rem_env[k]!r}."
                                ),
                                path=workflow_path,
                            )
                        )

                # Identify added env variables
                added_env_keys = set(rem_env.keys()) - set(orig_env.keys())

                # Run command verification
                run_orig = to_primitive(find_entry_value(os.node, "run"))
                run_rem = to_primitive(find_entry_value(rs.node, "run"))

                if run_orig == run_rem:
                    # If run command did not change, there must be NO added env variables
                    if added_env_keys:
                        mismatches.append(
                            VerificationFinding(
                                code="VER002",
                                severity=VerificationDecision.FAIL,
                                message=(
                                    f"job '{job_id}' step {idx} run command was not modified but "
                                    f"unrelated env variables {list(added_env_keys)} were added."
                                ),
                                path=workflow_path,
                            )
                        )
                else:
                    # Run command was modified. Validate structural transition:
                    # Original expression -> planner output -> env binding -> run replacement
                    if not isinstance(run_orig, str) or not isinstance(run_rem, str):
                        mismatches.append(
                            VerificationFinding(
                                code="VER002",
                                severity=VerificationDecision.FAIL,
                                message=f"job '{job_id}' step {idx} run command value is not a string.",
                                path=workflow_path,
                            )
                        )
                        continue

                    # Extract expression sites from original run command
                    sites = os.run_command.expression_sites if os.run_command else []
                    
                    # Track which added env variables are actually used in run command replacement
                    used_vars = set()
                    
                    # We will reconstruct run_rem from run_orig step-by-step
                    i = 0  # index in run_orig
                    j = 0  # index in run_rem
                    reconstruction_failed = False
                    reason = ""
                    
                    combined_env = {**orig_env, **{k: rem_env[k] for k in added_env_keys}}

                    for site in sorted(sites, key=lambda s: s.start_offset):
                        # Text before expression site must match
                        len_before = site.start_offset - i
                        if len_before > 0:
                            expected_chunk = run_orig[i:site.start_offset]
                            actual_chunk = run_rem[j:j+len_before]
                            if expected_chunk != actual_chunk:
                                reconstruction_failed = True
                                reason = f"text mismatch before site: expected {expected_chunk!r}, got {actual_chunk!r}"
                                break
                            
                        i = site.start_offset
                        j += len_before

                        # Check if site was replaced by a safe environment variable
                        replaced = False
                        for var_name, env_val in combined_env.items():
                            replacement_str = f"${var_name}"
                            if run_rem[j:].startswith(replacement_str):
                                # Env value must match the original expression text or expression body
                                val_str = str(env_val)
                                if val_str.strip() in (site.expression_text.strip(), site.expression_body.strip()):
                                    if var_name in added_env_keys:
                                        used_vars.add(var_name)
                                    i = site.end_offset
                                    j += len(replacement_str)
                                    replaced = True
                                    break
                        
                        if not replaced:
                            # If not replaced, the original expression must be preserved exactly
                            if run_rem[j:].startswith(site.expression_text):
                                i = site.end_offset
                                j += len(site.expression_text)
                            else:
                                reconstruction_failed = True
                                reason = f"expression site {site.expression_text!r} was modified or deleted incorrectly"
                                break

                    if not reconstruction_failed:
                        # Check remaining trailing text
                        if run_orig[i:] != run_rem[j:]:
                            reconstruction_failed = True
                            reason = f"trailing text mismatch: expected {run_orig[i:]!r}, got {run_rem[j:]!r}"

                    if reconstruction_failed:
                        mismatches.append(
                            VerificationFinding(
                                code="VER002",
                                severity=VerificationDecision.FAIL,
                                message=(
                                    f"job '{job_id}' step {idx} run command was modified invalidly. "
                                    f"Reason: {reason}. Original: {run_orig!r}, Actual: {run_rem!r}."
                                ),
                                path=workflow_path,
                            )
                        )
                    else:
                        # Check for unrelated env insertions
                        unused_vars = added_env_keys - used_vars
                        if unused_vars:
                            mismatches.append(
                                VerificationFinding(
                                    code="VER002",
                                    severity=VerificationDecision.FAIL,
                                    message=(
                                        f"job '{job_id}' step {idx} has unrelated env variables "
                                        f"inserted: {list(unused_vars)}."
                                    ),
                                    path=workflow_path,
                                )
                            )

        if mismatches:
            limit = 10
            for mismatch in mismatches[:limit]:
                findings.append(mismatch)
            if len(mismatches) > limit:
                findings.append(
                    VerificationFinding(
                        code="VER002",
                        severity=VerificationDecision.FAIL,
                        message=f"Additional {len(mismatches) - limit} semantic mismatches were omitted from the report.",
                        path=workflow_path,
                    )
                )

            invariant_results.append(
                InvariantResult(
                    code=InvariantCode.INV_SEME,
                    name="Semantic Equivalence Check",
                    decision=VerificationDecision.FAIL,
                    details=f"Semantic mismatches found: {'; '.join(f.message for f in mismatches[:5])}",
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
