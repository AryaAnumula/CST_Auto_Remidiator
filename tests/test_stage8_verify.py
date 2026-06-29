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
