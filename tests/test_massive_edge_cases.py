"""
Automated edge-case suite verifying Stages 1-5 compiler invariants.
Covers 29 distinct GHA and YAML edge cases in 26 test definitions.
"""

from __future__ import annotations

import pytest
from cst_auto_remediator.yaml_cst.parser import parse_yaml, ParsingError, FileTooLargeError, InvalidEncodingError, YamlBombError
from cst_auto_remediator.yaml_cst.builder import build_cst
from cst_auto_remediator.gha_semantic.builder import build_semantic_model
from cst_auto_remediator.gha_metadata.engine import MetadataWrapper
from cst_auto_remediator.gha_metadata.providers import PositionProvider, ScopeProvider, ShellProvider, ExpressionProvider
from cst_auto_remediator.gha_analysis.analyzer import analyze_workflow
from cst_auto_remediator.gha_analysis.nodes import AnalysisDecision, BailoutReason

# Define test cases mapping name to (content, expected_parse_success, expected_decision, expected_diags)
TEST_CASES = {
    "comments": (
        b"""# Workflow comments header
name: Comments test
# Job comment
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Step 1
        # Run comment
        run: echo "Hello" # Inline comment
""",
        True, "success", []
    ),
    "anchors_aliases_merge": (
        b"""name: Anchor Alias Merge test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - &step_anchor
        name: Anchor Step
        run: echo "anchor"
      - <<: *step_anchor
""",
        True, "success", []
    ),
    "crlf_endings": (
        b"name: CRLF Test\r\non: push\r\njobs:\r\n  test:\r\n    runs-on: ubuntu-latest\r\n    steps:\r\n      - run: echo \"crlf\"\r\n",
        True, "success", []
    ),
    "lf_endings": (
        b"name: LF Test\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"lf\"\n",
        True, "success", []
    ),
    "unicode_emojis": (
        "name: Emojis 🔥\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Emojis 🚀\n        run: echo \"🔥 ${{ github.event.issue.title }} 🚀\"\n".encode("utf-8"),
        True, "success", ["ANA004"]
    ),
    "tabs": (
        b"name: Tabs Test\non:\tpush\njobs:\n  test:\n    runs-on:\tubuntu-latest\n    steps:\n      - run:\techo \"tabs\"\n",
        False, "N/A", []
    ),
    "quoted_scalars": (
        b"""name: Quoted Scalars
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Single quoted
        run: 'echo "single quoted: ${{ github.event.issue.title }}"'
      - name: Double quoted
        run: "echo \\"double quoted: ${{ github.event.issue.title }}\\""
""",
        True, "success", ["ANA004", "ANA004"]
    ),
    "folded_scalars": (
        b"""name: Folded Scalars
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: >
          echo "folded"
          ${{ github.event.issue.title }}
""",
        True, "success", ["ANA003"]
    ),
    "literal_scalars": (
        b"""name: Literal Scalars
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "literal"
          ${{ github.event.issue.title }}
""",
        True, "success", ["ANA003"]
    ),
    "nested_env": (
        b"""name: Nested Env
on: push
env:
  WF_VAR: "${{ github.event.issue.title }}"
jobs:
  test:
    runs-on: ubuntu-latest
    env:
      JOB_VAR: "${{ env.WF_VAR }}"
    steps:
      - env:
          STEP_VAR: "${{ env.JOB_VAR }}"
        run: 'echo "Env: $STEP_VAR"'
""",
        True, "success", []
    ),
    "defaults_run_shell": (
        b"""name: Defaults Run Shell
on: push
defaults:
  run:
    shell: sh
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "defaults"
""",
        True, "success", []
    ),
    "windows_runners": (
        b"""name: Windows runners
on: push
jobs:
  test:
    runs-on: windows-latest
    steps:
      - run: echo "windows"
""",
        True, "success", []
    ),
    "ubuntu_runners": (
        b"""name: Ubuntu runners
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "ubuntu"
""",
        True, "success", []
    ),
    "macos_runners": (
        b"""name: macOS runners
on: push
jobs:
  test:
    runs-on: macos-latest
    steps:
      - run: echo "macos"
""",
        True, "success", []
    ),
    "duplicate_expressions": (
        b"""name: Duplicate expressions
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}" and "${{ github.event.issue.title }}"
""",
        True, "success", ["ANA004", "ANA004"]
    ),
    "empty_workflows": (
        b"   \n   \n",
        False, "N/A", []
    ),
    "empty_jobs": (
        b"""name: Empty Jobs
on: push
jobs: {}
""",
        True, "success", []
    ),
    "empty_steps": (
        b"""name: Empty Steps
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps: []
""",
        True, "success", []
    ),
    "missing_runs_on": (
        b"""name: Missing runs-on
on: push
jobs:
  test:
    steps:
      - run: echo "missing"
""",
        True, "success", []
    ),
    "missing_shell": (
        b"""name: Missing shell
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "missing shell"
""",
        True, "success", []
    ),
    "multiple_jobs": (
        b"""name: Multiple jobs
on: push
jobs:
  job1:
    runs-on: ubuntu-latest
    steps:
      - run: echo "job1"
  job2:
    runs-on: ubuntu-latest
    steps:
      - run: echo "job2"
""",
        True, "success", []
    ),
    "five_hundred_steps": (
        b"\n".join([
            b"name: 500 Steps Test",
            b"on: push",
            b"jobs:",
            b"  test:",
            b"    runs-on: ubuntu-latest",
            b"    steps:"
        ] + [
            f"      - name: Step {i}\n        run: echo \"Step {i}\"".encode("utf-8") for i in range(505)
        ]),
        True, "success", []
    ),
    "malformed_yaml": (
        b"""name: Malformed
on: push
jobs:
  test:
    runs-on: [ubuntu-latest
""",
        False, "N/A", []
    ),
    "invalid_expressions": (
        b"""name: Invalid GHA expression
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title"
""",
        True, "success", []
    ),
    "unsupported_shells": (
        b"""name: Unsupported shell
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: print("unsupported shell")
        shell: python
""",
        True, "success", []
    ),
    "unsupported_runners": (
        b"""name: Unsupported runner
on: push
jobs:
  test:
    runs-on: windows-latest
    steps:
      - run: echo "unsupported runner"
""",
        True, "success", []
    )
}

@pytest.mark.parametrize("name", sorted(TEST_CASES.keys()))
def test_invariant_checks(name: str) -> None:
    yaml_bytes, should_parse, expected_decision, expected_diags = TEST_CASES[name]
    
    # Stage 1: Ingest & Parse
    if not should_parse:
        with pytest.raises((ParsingError, FileTooLargeError, InvalidEncodingError, YamlBombError)):
            parse_yaml(yaml_bytes)
        return
        
    doc, meta = parse_yaml(yaml_bytes)
    
    # Stage 2: CST Build
    cst = build_cst(doc, meta)
    
    # Verify CST Immutability
    with pytest.raises(AttributeError):
        cst.root.span = None
        
    # Stage 3: Semantic Layer
    res = build_semantic_model(cst)
    assert res.workflow is not None
    
    # Verify Semantic Immutability
    with pytest.raises(AttributeError):
        res.workflow.jobs = {}
        
    # Stage 4: Metadata Provider
    wrapper = MetadataWrapper(res.workflow)
    
    # Resolve all providers and verify caching
    pos = wrapper.get_metadata(PositionProvider)
    scope = wrapper.get_metadata(ScopeProvider)
    shell = wrapper.get_metadata(ShellProvider)
    expr = wrapper.get_metadata(ExpressionProvider)
    
    assert PositionProvider in wrapper.cache
    assert ScopeProvider in wrapper.cache
    assert ShellProvider in wrapper.cache
    assert ExpressionProvider in wrapper.cache
    
    # Stage 5: Security Analysis
    analysis = analyze_workflow(res.workflow, wrapper)
    assert analysis.summary.get("status") == expected_decision
    
    # Verify diagnostic code correctness
    diags = [d.code for d in analysis.diagnostics]
    for d_code in expected_diags:
        assert d_code in diags
        
    # Verify determinism: re-run analysis yields identical results
    wrapper2 = MetadataWrapper(res.workflow)
    analysis2 = analyze_workflow(res.workflow, wrapper2)
    assert analysis.statistics == analysis2.statistics
    assert analysis.summary == analysis2.summary
    assert len(analysis.expression_classifications) == len(analysis2.expression_classifications)
