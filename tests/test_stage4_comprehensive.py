"""
Comprehensive unit tests for Stage 4: Metadata Providers.
Verifies position lookups, scopes, shells, expression stable IDs, caching,
dependency order resolution, deep override scopes, and scale stability.
"""

import pytest
from cst_auto_remediator.yaml_cst.parser import parse_yaml
from cst_auto_remediator.yaml_cst.builder import build_cst
from cst_auto_remediator.gha_semantic.builder import build_semantic_model
from cst_auto_remediator.gha_metadata.engine import MetadataWrapper
from cst_auto_remediator.gha_metadata.providers import (
    PositionProvider,
    ScopeProvider,
    ShellProvider,
    ExpressionProvider,
)
from cst_auto_remediator.gha_metadata.nodes import ShellCapabilities


def _get_wrapper(yaml_bytes: bytes) -> MetadataWrapper:
    doc, meta = parse_yaml(yaml_bytes)
    cst = build_cst(doc, meta)
    res = build_semantic_model(cst)
    return MetadataWrapper(res.workflow)


def test_standard_position_metadata() -> None:
    content = (
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - id: step0\n"
        b"        run: echo ${{ github.sha }}\n"
    )
    wrapper = _get_wrapper(content)
    workflow = wrapper.workflow
    job = workflow.jobs["build"]
    step = job.steps[0]
    run_cmd = step.run_command
    expr = run_cmd.expression_sites[0]

    # Verify positions
    wf_pos = wrapper.get(PositionProvider, workflow)
    assert wf_pos.parent is None
    assert wf_pos.node_path == "workflow"
    assert wf_pos.path_segments == ("workflow",)

    job_pos = wrapper.get(PositionProvider, job)
    assert job_pos.parent is workflow
    assert job_pos.node_path == "jobs.build"
    assert job_pos.path_segments == ("jobs", "build")
    assert job_pos.job_id == "build"

    step_pos = wrapper.get(PositionProvider, step)
    assert step_pos.parent is job
    assert step_pos.node_path == "jobs.build.steps.0"
    assert step_pos.path_segments == ("jobs", "build", "steps", "0")
    assert step_pos.step_index == 0
    assert step_pos.job_id == "build"

    run_pos = wrapper.get(PositionProvider, run_cmd)
    assert run_pos.parent is step
    assert run_pos.node_path == "jobs.build.steps.0.run"
    assert run_pos.path_segments == ("jobs", "build", "steps", "0", "run")

    expr_pos = wrapper.get(PositionProvider, expr)
    assert expr_pos.parent is run_cmd
    assert expr_pos.node_path == "jobs.build.steps.0.run.exprs.0"
    assert expr_pos.path_segments == ("jobs", "build", "steps", "0", "run", "exprs", "0")


def test_empty_workflows_and_diagnostics() -> None:
    # Empty sequence root
    wrapper = _get_wrapper(b"[]\n")
    assert wrapper.workflow is None
    
    # Missing jobs block
    wrapper = _get_wrapper(b"name: workflow-only\n")
    assert wrapper.workflow is not None
    assert len(wrapper.workflow.jobs) == 0
    wf_pos = wrapper.get(PositionProvider, wrapper.workflow)
    assert wf_pos is not None


def test_shell_resolution_explicit_and_defaults() -> None:
    content = (
        b"defaults:\n"
        b"  run:\n"
        b"    shell: sh\n"
        b"jobs:\n"
        b"  job_explicit:\n"
        b"    runs-on: ubuntu-latest\n"
        b"    steps:\n"
        b"      - run: echo\n"
        b"        shell: python\n"
        b"  job_default:\n"
        b"    runs-on: windows-latest\n"
        b"    steps:\n"
        b"      - run: echo\n"
        # will fallback to defaults.run.shell ("sh")
        b"  job_runner_fallback:\n"
        # Windows runner fallback
        b"    runs-on: windows-latest\n"
        b"    steps:\n"
        b"      - run: echo\n"
    )
    # Parse with job defaults removed to check runner fallbacks
    content_no_defaults = (
        b"jobs:\n"
        b"  job_linux:\n"
        b"    runs-on: ubuntu-latest\n"
        b"    steps:\n"
        b"      - run: echo\n"
        b"  job_windows:\n"
        b"    runs-on: windows-latest\n"
        b"    steps:\n"
        b"      - run: echo\n"
    )

    # 1. Check explicit and defaults
    wrapper = _get_wrapper(content)
    
    step_explicit = wrapper.workflow.jobs["job_explicit"].steps[0]
    sh_explicit = wrapper.get(ShellProvider, step_explicit)
    assert sh_explicit.declared_shell == "python"
    assert sh_explicit.effective_shell == "python"
    assert sh_explicit.is_default is False

    step_default = wrapper.workflow.jobs["job_default"].steps[0]
    sh_default = wrapper.get(ShellProvider, step_default)
    # defaults to workflow defaults.run.shell ("sh")
    assert sh_default.declared_shell == "sh"
    assert sh_default.effective_shell == "sh"
    assert sh_default.is_default is False

    # 2. Check runner fallbacks (no default shell config)
    wrapper_fallback = _get_wrapper(content_no_defaults)
    
    step_linux = wrapper_fallback.workflow.jobs["job_linux"].steps[0]
    sh_linux = wrapper_fallback.get(ShellProvider, step_linux)
    assert sh_linux.declared_shell is None
    assert sh_linux.effective_shell == "bash"
    assert sh_linux.runner_default == "bash"
    assert sh_linux.is_default is True
    assert sh_linux.capabilities.supports_env_assignment is True

    step_windows = wrapper_fallback.workflow.jobs["job_windows"].steps[0]
    sh_windows = wrapper_fallback.get(ShellProvider, step_windows)
    assert sh_windows.declared_shell is None
    assert sh_windows.effective_shell == "pwsh"
    assert sh_windows.runner_default == "pwsh"
    assert sh_windows.is_default is True
    assert sh_windows.capabilities.supports_env_assignment is False


def test_metadata_bundle_aggregation() -> None:
    content = (
        b"jobs:\n"
        b"  build:\n"
        b"    runs-on: ubuntu-latest\n"
        b"    steps:\n"
        b"      - run: echo ${{ github.sha }}\n"
    )
    wrapper = _get_wrapper(content)
    expr = wrapper.workflow.jobs["build"].steps[0].run_command.expression_sites[0]

    bundle = wrapper.get_bundle(expr)
    assert bundle.position is not None
    assert bundle.scope is not None
    assert bundle.shell is not None
    assert bundle.expression is not None

    assert bundle.position.node_path == "jobs.build.steps.0.run.exprs.0"
    assert bundle.shell.effective_shell == "bash"


# --- 5 Additional Verification Tests ---

def test_additional_1_expression_ids_deterministic() -> None:
    content = (
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - run: echo ${{ github.event.title }}\n"
    )
    # Parse and resolve twice
    w1 = _get_wrapper(content)
    w2 = _get_wrapper(content)

    expr1 = w1.workflow.jobs["build"].steps[0].run_command.expression_sites[0]
    expr2 = w2.workflow.jobs["build"].steps[0].run_command.expression_sites[0]

    meta1 = w1.get(ExpressionProvider, expr1)
    meta2 = w2.get(ExpressionProvider, expr2)

    # Identical deterministic IDs check
    assert meta1.stable_id == "jobs.build.steps.0.run.exprs.0"
    assert meta1.stable_id == meta2.stable_id


def test_additional_2_metadata_cache_reuse() -> None:
    content = (
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - run: echo hello\n"
    )
    wrapper = _get_wrapper(content)
    step = wrapper.workflow.jobs["build"].steps[0]

    meta_first = wrapper.get(PositionProvider, step)
    meta_second = wrapper.get(PositionProvider, step)

    # Assert cache reuse (exact same object reference)
    assert meta_first is meta_second


def test_additional_3_dependency_ordering() -> None:
    content = (
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - run: echo hello\n"
    )
    wrapper = _get_wrapper(content)
    step = wrapper.workflow.jobs["build"].steps[0]

    # Verify cache is empty initially
    assert len(wrapper.cache) == 0

    # Call ShellProvider (which depends on Position and Scope providers)
    wrapper.get(ShellProvider, step)

    # Assert dependencies were automatically resolved and cached in order
    assert PositionProvider in wrapper.cache
    assert ScopeProvider in wrapper.cache
    assert ShellProvider in wrapper.cache


def test_additional_4_deep_scopes() -> None:
    content = (
        b"env:\n"
        b"  GLOBAL_VAR: global_val\n"
        b"  OVERRIDDEN: global_val\n"
        b"jobs:\n"
        b"  build:\n"
        b"    env:\n"
        b"      JOB_VAR: job_val\n"
        b"      OVERRIDDEN: job_val\n"
        b"    steps:\n"
        b"      - env:\n"
        b"          STEP_VAR: step_val\n"
        b"          OVERRIDDEN: step_val\n"
        b"        run: echo hello\n"
    )
    wrapper = _get_wrapper(content)
    step = wrapper.workflow.jobs["build"].steps[0]

    step_scope = wrapper.get(ScopeProvider, step)
    assert step_scope.scope_type == "step"
    
    # Assert values and overrides
    env = step_scope.env
    assert env["GLOBAL_VAR"].value == "global_val"
    assert env["JOB_VAR"].value == "job_val"
    assert env["STEP_VAR"].value == "step_val"
    assert env["OVERRIDDEN"].value == "step_val"  # overridden by step


def test_additional_5_large_workflow() -> None:
    # Programmatically build a GHA workflow with 120 steps
    lines = [b"jobs:", b"  build:", b"    runs-on: ubuntu-latest", b"    steps:"]
    for i in range(120):
        lines.append(f"      - run: echo \"Step {i} with ${{{{ github.sha }}}}\"".encode("utf-8"))
    
    content = b"\n".join(lines)
    wrapper = _get_wrapper(content)
    
    assert len(wrapper.workflow.jobs["build"].steps) == 120

    # Retrieve and verify first and last step metadata
    steps = wrapper.workflow.jobs["build"].steps
    
    first_step_expr = steps[0].run_command.expression_sites[0]
    last_step_expr = steps[119].run_command.expression_sites[0]

    first_meta = wrapper.get(ExpressionProvider, first_step_expr)
    last_meta = wrapper.get(ExpressionProvider, last_step_expr)

    assert first_meta.stable_id == "jobs.build.steps.0.run.exprs.0"
    assert last_meta.stable_id == "jobs.build.steps.119.run.exprs.0"
    assert first_meta.expression_order == 0
    assert last_meta.expression_order == 119
