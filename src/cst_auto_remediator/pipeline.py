"""
Pipeline orchestration for Stages 1–3.

Entry point: remediate_file(path) -> (yaml_string | None, report[]).

MAINTAINER NOTE: When you change this file, update explanation.md at the project root.
"""

from __future__ import annotations

from pathlib import Path

from ruamel.yaml.comments import CommentedMap

from cst_auto_remediator.ingest import ingest
from cst_auto_remediator.models import (
    Action,
    IngestFailure,
    ReasonCode,
    ReportEntry,
)
from cst_auto_remediator.traverse import traverse_env_bindings
from cst_auto_remediator.validate import is_step_already_remediated


def semantic_verify(patched_yaml: str, patched_steps: set[tuple[str, int]]) -> bool:
    """
    Stage 5 Semantic Verification.
    Parses the patched YAML, extracts and classifies all ${{ }} expressions
    in the run blocks of patched steps, and ensures no UNTRUSTED expressions remain.
    """
    from cst_auto_remediator.yaml_cst.parser import parse_yaml, ParsingError
    from cst_auto_remediator.yaml_cst.builder import build_cst
    from cst_auto_remediator.gha_semantic.builder import build_semantic_model
    from cst_auto_remediator.gha_metadata.engine import MetadataWrapper
    from cst_auto_remediator.gha_analysis.analyzer import analyze_workflow
    from cst_auto_remediator.gha_analysis.nodes import AnalysisDecision
    from cst_auto_remediator.gha_metadata.providers import PositionProvider

    try:
        doc, meta = parse_yaml(patched_yaml.encode("utf-8"))
        cst = build_cst(doc, meta)
        semantic = build_semantic_model(cst)
        if semantic.workflow is None:
            return False

        wrapper = MetadataWrapper(semantic.workflow)
        analysis = analyze_workflow(semantic.workflow, wrapper)

        for classif in analysis.expression_classifications.values():
            expr = classif.expression_site
            pos = wrapper.get(PositionProvider, expr)
            if pos is not None and pos.job_id is not None:
                step_key = (pos.job_id, pos.step_index)
                if step_key in patched_steps:
                    if classif.decision == AnalysisDecision.REMEDIATE:
                        return False
        return True
    except ParsingError:
        return False
    except Exception:
        return False


def remediate_file(
    path: str | Path,
    *,
    write_back: bool = False,
    return_context: bool = False,
) -> Any:
    """
    Run Stages 1–7 on a workflow file.

    Returns ``(yaml_output, report)`` or ``(yaml_output, report, context)`` based on return_context.
    """
    file_path = Path(path)
    ingest_result = ingest(file_path)

    if isinstance(ingest_result, IngestFailure):
        return None, [
            ReportEntry(
                file=_report_file_path(file_path),
                action=Action.BAILED,
                reason=ingest_result.reason,
            ).to_dict()
        ]

    document = ingest_result.document
    metadata = ingest_result.metadata
    original_text = ingest_result.source_text

    # Run Stages 2-5
    from cst_auto_remediator.yaml_cst.builder import build_cst
    from cst_auto_remediator.gha_semantic.builder import build_semantic_model
    from cst_auto_remediator.gha_metadata.engine import MetadataWrapper
    from cst_auto_remediator.gha_analysis.analyzer import analyze_workflow
    from cst_auto_remediator.gha_analysis.nodes import AnalysisDecision
    from cst_auto_remediator.gha_metadata.providers import PositionProvider, ExpressionProvider
    from cst_auto_remediator.validate import detect_sink, env_var_for_expression, is_step_already_remediated, _existing_env_keys

    cst = build_cst(document, metadata)
    semantic = build_semantic_model(cst)
    if semantic.workflow is None:
        return original_text, []

    wrapper = MetadataWrapper(semantic.workflow)
    analysis = analyze_workflow(semantic.workflow, wrapper)

    # Replicate legacy overrides for backward compatibility in the public API
    pending_env_names: dict[tuple[str, int], set[str]] = {}
    jobs = document.get("jobs", {})

    for job_id, job_node in semantic.workflow.jobs.items():
        job_map = jobs.get(job_id) if isinstance(jobs, CommentedMap) else None
        job_steps = list(job_map.get("steps")) if isinstance(job_map, CommentedMap) and isinstance(job_map.get("steps"), list) else None

        for step in job_node.steps:
            step_key = (job_id, step.step_index)
            step_map = job_steps[step.step_index] if job_steps and step.step_index < len(job_steps) else None

            existing_env = set()
            if job_steps is not None:
                for s in job_steps:
                    if isinstance(s, CommentedMap):
                        env = s.get("env")
                        if isinstance(env, CommentedMap):
                            for key in env.keys():
                                existing_env.add(str(key).upper())
            elif step_map is not None:
                existing_env = _existing_env_keys(step_map)

            run_exprs = step.run_command.expression_sites if step.run_command is not None else []
            for expr in run_exprs:
                expr_meta = wrapper.get(ExpressionProvider, expr)
                stable_id = expr_meta.stable_id if expr_meta else None
                if not stable_id or stable_id not in analysis.expression_classifications:
                    continue

                classif = analysis.expression_classifications[stable_id]
                if classif.decision == AnalysisDecision.REMEDIATE:
                    # 1. Eval / Command Substitution Sink detection
                    sink = detect_sink(expr.node.value, expr.start_offset, expr.end_offset)
                    if sink is not None:
                        object.__setattr__(classif, "decision", AnalysisDecision.BAILOUT)
                        object.__setattr__(classif, "bailout_reason", sink)
                        continue

                    # If the expression is already bound in the step env, reuse it and skip name collision check
                    existing_binding = env_var_for_expression(step_map, expr.expression_text) if step_map is not None else None
                    if existing_binding is not None:
                        continue

                    # 2. Env Name Collision detection
                    from cst_auto_remediator.validate import generate_env_var_name
                    env_name = generate_env_var_name(expr.expression_body)
                    if env_name.upper() in existing_env:
                        object.__setattr__(classif, "decision", AnalysisDecision.BAILOUT)
                        object.__setattr__(classif, "bailout_reason", ReasonCode.ENV_NAME_COLLISION)
                        continue

                    # 3. Generated Name Collision detection
                    used = pending_env_names.setdefault(step_key, set())
                    if env_name.upper() in used:
                        object.__setattr__(classif, "decision", AnalysisDecision.BAILOUT)
                        object.__setattr__(classif, "bailout_reason", ReasonCode.GENERATED_NAME_COLLISION)
                        continue

                    used.add(env_name.upper())

    # Step-level bailing check: if any expression in a step is BAILED, we bail on the entire step
    for job_id, job_node in semantic.workflow.jobs.items():
        for step in job_node.steps:
            run_exprs = step.run_command.expression_sites if step.run_command is not None else []
            
            bailed_reason = None
            for expr in run_exprs:
                expr_meta = wrapper.get(ExpressionProvider, expr)
                if expr_meta and expr_meta.stable_id in analysis.expression_classifications:
                    classif = analysis.expression_classifications[expr_meta.stable_id]
                    if classif.decision == AnalysisDecision.BAILOUT:
                        bailed_reason = classif.bailout_reason
                        break
            
            if bailed_reason is not None:
                for expr in run_exprs:
                    expr_meta = wrapper.get(ExpressionProvider, expr)
                    if expr_meta and expr_meta.stable_id in analysis.expression_classifications:
                        classif = analysis.expression_classifications[expr_meta.stable_id]
                        if classif.decision == AnalysisDecision.REMEDIATE:
                            object.__setattr__(classif, "decision", AnalysisDecision.BAILOUT)
                            object.__setattr__(classif, "bailout_reason", bailed_reason)

    # Run Stage 6 Planner and Transformer
    from cst_auto_remediator.gha_transform.planner import MutationPlanner
    from cst_auto_remediator.gha_transform.transformer import CSTTransformer
    
    plan = MutationPlanner(wrapper).build_plan(analysis)
    transform_res = CSTTransformer().transform(plan)

    # Run Stage 7 Serializer if mutated
    if transform_res.applied_step_mutations:
        from cst_auto_remediator.gha_transform.serializer import serialize_document
        output_bytes = serialize_document(transform_res.cst, document, cst, original_text)
        output_text = output_bytes.decode("utf-8")
    else:
        output_text = original_text

    # Perform Stage 5 Semantic Verification on memory string first
    patched_steps = {(m.job_id, m.step_index) for m in transform_res.applied_step_mutations}
    if patched_steps:
        if not semantic_verify(output_text, patched_steps):
            raise AssertionError("Semantic verification failed: untrusted expressions remain or invalid YAML structure")

    # Perform Stage 5 Atomic Write back if requested
    if write_back:
        import tempfile
        import os

        # Write to temporary file first
        temp_fd, temp_path = tempfile.mkstemp(
            dir=file_path.parent,
            prefix=file_path.name + ".tmp",
        )
        try:
            with os.fdopen(temp_fd, "w", encoding="utf-8", newline="") as f:
                f.write(output_text)
                f.flush()
                os.fsync(f.fileno())

            # Verify temp file contents semantics
            with open(temp_path, "r", encoding="utf-8", newline="") as f:
                temp_content = f.read()
            if not semantic_verify(temp_content, patched_steps):
                raise AssertionError("Semantic verification failed for temp file content")

            # Rename/Replace atomically
            os.replace(temp_path, file_path)
        except Exception as e:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
            raise e

    # Build report entries
    report_entries: list[dict] = []
    
    # 1. Add already-remediated env sites to the report
    env_sites = traverse_env_bindings(document)
    for env_site in env_sites:
        step_map = _get_step(document, env_site)
        if step_map is None:
            continue
        if is_step_already_remediated(step_map, env_site):
            report_entries.append({
                "file": _report_file_path(file_path),
                "job_id": env_site.job_id,
                "step": env_site.step_index,
                "step_id": env_site.step_id,
                "action": "SKIPPED",
                "reason": "ALREADY_REMEDIATED",
                "env_var_added": None,
                "expression_text": env_site.expression_text,
                "classification": "UNTRUSTED",
                "scalar_type": env_site.scalar_type.value,
                "start_offset": env_site.start_offset,
                "end_offset": env_site.end_offset,
            })

    # 2. Add run expressions to the report
    remediated_names = {}
    for mutation in transform_res.applied_step_mutations:
        for replacement in mutation.replacements:
            remediated_names[replacement.expression_id] = replacement.env_var_name

    for job_id, job_node in semantic.workflow.jobs.items():
        job_map = jobs.get(job_id) if isinstance(jobs, CommentedMap) else None
        job_steps = list(job_map.get("steps")) if isinstance(job_map, CommentedMap) and isinstance(job_map.get("steps"), list) else None

        for step in job_node.steps:
            run_exprs = step.run_command.expression_sites if step.run_command is not None else []
            for expr in run_exprs:
                expr_meta = wrapper.get(ExpressionProvider, expr)
                stable_id = expr_meta.stable_id if expr_meta else None
                if not stable_id or stable_id not in analysis.expression_classifications:
                    continue

                classif = analysis.expression_classifications[stable_id]
                
                if classif.decision == AnalysisDecision.REMEDIATE:
                    action = "PATCHED"
                    reason = None
                    env_var_added = remediated_names.get(stable_id)
                elif classif.decision == AnalysisDecision.BAILOUT:
                    action = "BAILED"
                    reason = classif.bailout_reason.value if hasattr(classif.bailout_reason, "value") else str(classif.bailout_reason)
                    if reason == "BLOCK_SCALAR":
                        action = "SKIPPED"
                        reason = "BLOCK_SCALAR_OUT_OF_SCOPE"
                    env_var_added = None
                elif classif.decision == AnalysisDecision.SKIP:
                    action = "SKIPPED"
                    reason = classif.bailout_reason.value if hasattr(classif.bailout_reason, "value") else str(classif.bailout_reason)
                    if reason == "NONE" or not reason:
                        reason = "SINGLE_QUOTED_EXPRESSION"
                    env_var_added = None
                else: # SAFE
                    action = "SKIPPED"
                    reason = "TRUSTED" if classif.trust_level.value == "TRUSTED" else "AMBIGUOUS_EXPRESSION"
                    env_var_added = None

                if classif.trust_level.value == "TRUSTED":
                    class_label = "TRUSTED"
                elif classif.trust_level.value in ("UNTRUSTED", "MIXED"):
                    class_label = "UNTRUSTED"
                else:
                    class_label = "AMBIGUOUS"

                style = step.run_command.command.style if step.run_command else "PLAIN"
                scalar_type = "block" if style in ("LITERAL", "FOLDED") else "plain"

                report_entries.append({
                    "file": _report_file_path(file_path),
                    "job_id": job_id,
                    "step": step.step_index,
                    "step_id": step.step_id,
                    "action": action,
                    "reason": reason,
                    "env_var_added": env_var_added,
                    "expression_text": expr.expression_text,
                    "classification": class_label,
                    "scalar_type": scalar_type,
                    "start_offset": expr.start_offset,
                    "end_offset": expr.end_offset,
                })

    if return_context:
        try:
            rem_doc, rem_meta = parse_yaml(output_text.encode("utf-8"))
            rem_cst = build_cst(rem_doc, rem_meta)
            rem_semantic = build_semantic_model(rem_cst)
        except Exception:
            rem_doc = document
            rem_semantic = None

        from cst_auto_remediator.gha_verify.report import VerificationContext
        context = VerificationContext(
            original_yaml=original_text,
            remediated_yaml=output_text,
            original_cst=cst,
            remediated_cst=transform_res.cst,
            original_ruamel=document,
            remediated_ruamel=rem_doc,
            original_semantic=semantic,
            remediated_semantic=rem_semantic,
            original_metadata=metadata,
        )
        return output_text, report_entries, context

    return output_text, report_entries


def _report_file_path(file_path: Path) -> str:
    try:
        return file_path.relative_to(Path.cwd()).as_posix()
    except ValueError:
        return file_path.as_posix()


def _get_step(document: CommentedMap, site: ExpressionSite) -> CommentedMap | None:
    jobs = document.get("jobs")
    if not isinstance(jobs, CommentedMap):
        return None
    job = jobs.get(site.job_id)
    if not isinstance(job, CommentedMap):
        return None
    steps = job.get("steps")
    if not isinstance(steps, list):
        return None
    if site.step_index >= len(steps):
        return None
    step = steps[site.step_index]
    if not isinstance(step, CommentedMap):
        return None
    return step


def _report_entry(
    file_path: Path,
    site: ExpressionSite,
    result: ValidationResult,
) -> ReportEntry:
    return ReportEntry(
        file=_report_file_path(file_path),
        job_id=site.job_id,
        step=site.step_index,
        step_id=site.step_id,
        action=result.action,
        reason=result.reason,
        env_var_added=result.env_var_name if result.action is Action.PATCHED else None,
        expression_text=site.expression_text,
        classification=site.classification,
        scalar_type=site.scalar_type,
        start_offset=site.start_offset,
        end_offset=site.end_offset,
    )
