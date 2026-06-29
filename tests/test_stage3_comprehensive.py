"""
Comprehensive unit tests for Stage 3: GitHub Actions Semantic Layer.
Verifies semantic model mapping, deterministic scanning, error diagnostics,
adjacent/duplicate expressions, UTF-8 support, and empty step sequence scenarios.
"""

import pytest
from cst_auto_remediator.yaml_cst.parser import parse_yaml
from cst_auto_remediator.yaml_cst.builder import build_cst
from cst_auto_remediator.gha_semantic.builder import build_semantic_model
from cst_auto_remediator.gha_semantic.nodes import (
    Diagnostic,
    Workflow,
    Job,
    Step,
    RunCommand,
    EnvBinding,
    ExpressionSite,
    SemanticBuildResult,
)


def _build(yaml_bytes: bytes) -> SemanticBuildResult:
    doc, meta = parse_yaml(yaml_bytes)
    cst = build_cst(doc, meta)
    return build_semantic_model(cst)


def test_gha001_invalid_root() -> None:
    # Scalar root
    res = _build(b"simple_string\n")
    assert res.workflow is None
    assert len(res.diagnostics) == 1
    assert res.diagnostics[0].code == "GHA001"
    assert "Workflow root must be a mapping" in res.diagnostics[0].message


def test_gha002_missing_jobs() -> None:
    # Key-value root but no 'jobs'
    res = _build(b"name: test-workflow\non: push\n")
    assert res.workflow is not None
    assert len(res.workflow.jobs) == 0
    assert len(res.diagnostics) == 1
    assert res.diagnostics[0].code == "GHA002"
    assert "Missing 'jobs' section" in res.diagnostics[0].message


def test_gha003_jobs_not_mapping() -> None:
    # jobs is a sequence
    res = _build(b"jobs:\n  - build\n  - deploy\n")
    assert res.workflow is not None
    assert len(res.workflow.jobs) == 0
    assert len(res.diagnostics) == 1
    assert res.diagnostics[0].code == "GHA003"
    assert "Jobs section must be a mapping" in res.diagnostics[0].message


def test_gha004_job_not_mapping() -> None:
    # job definition is a string
    res = _build(
        b"jobs:\n"
        b"  build: string-def\n"
        b"  deploy:\n"
        b"    steps: []\n"
    )
    assert res.workflow is not None
    assert "build" not in res.workflow.jobs
    assert "deploy" in res.workflow.jobs
    assert len(res.diagnostics) == 1
    assert res.diagnostics[0].code == "GHA004"
    assert "Job 'build' must be a mapping" in res.diagnostics[0].message


def test_gha005_steps_not_sequence() -> None:
    # steps is a mapping
    res = _build(
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      name: step1\n"
    )
    assert res.workflow is not None
    assert "build" in res.workflow.jobs
    assert len(res.workflow.jobs["build"].steps) == 0
    assert len(res.diagnostics) == 1
    assert res.diagnostics[0].code == "GHA005"
    assert "Steps in job 'build' must be a sequence" in res.diagnostics[0].message


def test_gha006_step_not_mapping() -> None:
    # steps sequence contains a string
    res = _build(
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - string-step\n"
    )
    assert res.workflow is not None
    assert len(res.workflow.jobs["build"].steps) == 0
    assert len(res.diagnostics) == 1
    assert res.diagnostics[0].code == "GHA006"
    assert "Step at index 0 in job 'build' must be a mapping" in res.diagnostics[0].message


def test_gha007_step_id_not_scalar() -> None:
    # step id is a sequence
    res = _build(
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - id: [1, 2]\n"
        b"        run: echo\n"
    )
    assert res.workflow is not None
    step = res.workflow.jobs["build"].steps[0]
    assert step.step_id is None
    assert len(res.diagnostics) == 1
    assert res.diagnostics[0].code == "GHA007"
    assert "Id in step 0 of job 'build' must be a scalar" in res.diagnostics[0].message


def test_gha008_run_not_scalar() -> None:
    # run command is a mapping
    res = _build(
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - run:\n"
        b"          command: echo\n"
    )
    assert res.workflow is not None
    step = res.workflow.jobs["build"].steps[0]
    assert step.run_command is None
    assert len(res.diagnostics) == 1
    assert res.diagnostics[0].code == "GHA008"
    assert "Run command in step 0 of job 'build' must be a scalar" in res.diagnostics[0].message


def test_gha009_env_not_mapping() -> None:
    # env block is a sequence
    res = _build(
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - env: [a, b]\n"
        b"        run: echo\n"
    )
    assert res.workflow is not None
    step = res.workflow.jobs["build"].steps[0]
    assert len(step.env_bindings) == 0
    assert len(res.diagnostics) == 1
    assert res.diagnostics[0].code == "GHA009"
    assert "Env block in step 0 of job 'build' must be a mapping" in res.diagnostics[0].message


def test_gha010_env_binding_not_scalar() -> None:
    # env binding value is a sequence
    res = _build(
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - env:\n"
        b"          KEY: [val1, val2]\n"
        b"        run: echo\n"
    )
    assert res.workflow is not None
    step = res.workflow.jobs["build"].steps[0]
    assert len(step.env_bindings) == 0
    assert len(res.diagnostics) == 1
    assert res.diagnostics[0].code == "GHA010"
    assert "Env binding in step 0 of job 'build' must have a scalar key and value" in res.diagnostics[0].message


def test_multiple_jobs_and_steps() -> None:
    content = (
        b"jobs:\n"
        b"  job1:\n"
        b"    steps:\n"
        b"      - id: step_a\n"
        b"        run: echo A\n"
        b"      - run: echo B\n"
        b"  job2:\n"
        b"    steps:\n"
        b"      - uses: actions/checkout@v3\n"
    )
    res = _build(content)
    assert len(res.diagnostics) == 0
    assert res.workflow is not None
    assert len(res.workflow.jobs) == 2

    # Job 1
    job1 = res.workflow.jobs["job1"]
    assert len(job1.steps) == 2
    assert job1.steps[0].step_id == "step_a"
    assert job1.steps[0].run_command is not None
    assert job1.steps[0].run_command.command.value == "echo A"
    assert job1.steps[1].step_id is None
    assert job1.steps[1].run_command is not None
    assert job1.steps[1].run_command.command.value == "echo B"

    # Job 2
    job2 = res.workflow.jobs["job2"]
    assert len(job2.steps) == 1
    assert job2.steps[0].run_command is None  # uses: checkout


def test_step_only_env_and_no_run() -> None:
    content = (
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - env:\n"
        b"          VAR: value\n"
    )
    res = _build(content)
    assert len(res.diagnostics) == 0
    assert res.workflow is not None
    step = res.workflow.jobs["build"].steps[0]
    assert step.run_command is None
    assert len(step.env_bindings) == 1
    assert step.env_bindings[0].key.value == "VAR"
    assert step.env_bindings[0].value.value == "value"


def test_empty_steps_sequence() -> None:
    content = (
        b"jobs:\n"
        b"  build:\n"
        b"    steps: []\n"
    )
    res = _build(content)
    assert len(res.diagnostics) == 0
    assert res.workflow is not None
    assert len(res.workflow.jobs["build"].steps) == 0


def test_expressions_multi_adjacent_duplicate() -> None:
    content = (
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - run: echo ${{ github.event.title }} and ${{ github.event.title }}\n"
        b"      - run: ${{ github.head_ref }}${{ github.base_ref }}\n"
    )
    res = _build(content)
    assert len(res.diagnostics) == 0
    assert res.workflow is not None
    steps = res.workflow.jobs["build"].steps

    # Multi and duplicate expressions
    step1_run = steps[0].run_command
    assert step1_run is not None
    assert len(step1_run.expression_sites) == 2
    
    site1 = step1_run.expression_sites[0]
    site2 = step1_run.expression_sites[1]
    assert site1.expression_text == "${{ github.event.title }}"
    assert site1.expression_body == "github.event.title"
    assert site2.expression_text == "${{ github.event.title }}"
    assert site2.expression_body == "github.event.title"
    # Offsets must differ (duplicate expressions)
    assert site1.start_offset != site2.start_offset

    # Adjacent expressions
    step2_run = steps[1].run_command
    assert step2_run is not None
    assert len(step2_run.expression_sites) == 2
    assert step2_run.expression_sites[0].expression_text == "${{ github.head_ref }}"
    assert step2_run.expression_sites[1].expression_text == "${{ github.base_ref }}"
    assert step2_run.expression_sites[0].end_offset == step2_run.expression_sites[1].start_offset


def test_utf8_offset_correctness() -> None:
    content = "jobs:\n  build:\n    steps:\n      - run: echo \"🔥${{ github.event.title }}\"\n".encode("utf-8")
    res = _build(content)
    assert len(res.diagnostics) == 0
    assert res.workflow is not None
    run_cmd = res.workflow.jobs["build"].steps[0].run_command
    assert run_cmd is not None
    assert len(run_cmd.expression_sites) == 1
    site = run_cmd.expression_sites[0]
    
    # "echo \"🔥${{ github.event.title }}\""
    # 0123456  7 <- ${{ starts at character 7 (after e,c,h,o,space,quote,fire)
    assert site.start_offset == 7
    assert site.expression_text == "${{ github.event.title }}"


def test_deterministic_semantic_reconstruction() -> None:
    content = (
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - run: echo ${{ github.event.title }}\n"
    )
    # Reconstruct twice
    res1 = _build(content)
    res2 = _build(content)

    # Memory IDs must differ (dataclasses generated independently)
    assert res1 is not res2
    assert res1.workflow is not res2.workflow

    # Helper method to assert structure isomorphism recursively
    def assert_isomorphic(w1: Workflow | None, w2: Workflow | None) -> None:
        if w1 is None or w2 is None:
            assert w1 is w2
            return
        assert len(w1.jobs) == len(w2.jobs)
        for job_id in w1.jobs:
            assert job_id in w2.jobs
            j1, j2 = w1.jobs[job_id], w2.jobs[job_id]
            assert j1.job_id == j2.job_id
            assert len(j1.steps) == len(j2.steps)
            for s1, s2 in zip(j1.steps, j2.steps):
                assert s1.step_index == s2.step_index
                assert s1.step_id == s2.step_id
                
                # Check run commands
                if s1.run_command is None:
                    assert s2.run_command is None
                else:
                    assert s2.run_command is not None
                    assert s1.run_command.command.value == s2.run_command.command.value
                    assert len(s1.run_command.expression_sites) == len(s2.run_command.expression_sites)
                    for e1, e2 in zip(s1.run_command.expression_sites, s2.run_command.expression_sites):
                        assert e1.expression_text == e2.expression_text
                        assert e1.expression_body == e2.expression_body
                        assert e1.start_offset == e2.start_offset
                        assert e1.end_offset == e2.end_offset

                # Check env bindings
                assert len(s1.env_bindings) == len(s2.env_bindings)
                for b1, b2 in zip(s1.env_bindings, s2.env_bindings):
                    assert b1.key.value == b2.key.value
                    assert b1.value.value == b2.value.value
                    assert len(b1.expression_sites) == len(b2.expression_sites)

    assert_isomorphic(res1.workflow, res2.workflow)
    
    # Check diagnostics match
    assert len(res1.diagnostics) == len(res2.diagnostics)
    for d1, d2 in zip(res1.diagnostics, res2.diagnostics):
        assert d1.code == d2.code
        assert d1.message == d2.message
        assert d1.level == d2.level
