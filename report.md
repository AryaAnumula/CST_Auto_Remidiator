# Stage 6 Audit — Problems & Fixes

**Date:** 2026-06-29  
**Auditor:** Independent AI session (Claude Sonnet 4.6 Thinking)  
**All findings are verified against the actual `.py` source.** Nothing here is taken from documentation at face value.

---

## The 3 Discrepancies ("warnings") — Status

These were the three items where the documentation/spec claimed something that the code did not match.

---

### DISC-1 — `transformer.py` calls `build_semantic_model()`: Stage 3 logic inside Stage 6

| | |
|---|---|
| **Status** | 🟢 **RESOLVED (2026-06-29).** `build_semantic_model` import and call removed from `transformer.py`. `TransformationResult.workflow` is now always `None`. Ownership matrix is now accurate. |
| **File** | [`transformer.py`](file:///d:/Cybersec/internship/CST_Auto_Remidiator-cst-engine-v1/src/cst_auto_remediator/gha_transform/transformer.py) |

**What the code does:**

```python
# transformer.py:7
from cst_auto_remediator.gha_semantic.builder import build_semantic_model

# transformer.py:67
semantic_result = build_semantic_model(new_cst)   # ← Stage 3 inside Stage 6
```

**Why it's a problem:**  
The Stage 6 spec says the output is "a new immutable tree plus a result object." It explicitly prohibits re-running analysis or verification. Rebuilding the semantic model is a Stage 3 operation. Having it inside the transformer means:
- Stage 6 has a hidden runtime dependency on Stage 3 being correct.
- A future contributor implementing Stage 7 could unknowingly rely on `TransformationResult.workflow` being "already rebuilt" and skip the semantic rebuild there — creating a silent double-rebuild or a dependency on Stage 6's internal timing.

**Suggested fix:**

Remove the `build_semantic_model` call from `transformer.py` entirely. Return only the new `YamlDocument` CST:

```python
# In CSTTransformer.transform() — replace lines 67-76 with:
return TransformationResult(
    original_workflow=plan.workflow,
    workflow=None,          # ← orchestrator / Stage 7 fills this
    cst=new_cst,
    plan=plan,
    applied_step_mutations=plan.step_mutations,
)
```

Then update the orchestrator (Stage 7 or the pipeline) to rebuild the semantic model from the new CST after Stage 6 returns. This keeps each stage responsible for exactly one thing.

> **Note:** The `explanation.md` now has a `⚠ Undocumented Stage 3 dependency` warning in the Stage 6 section. That warning is accurate and should stay regardless of whether the code is fixed, until Stage 7 owns the rebuild.

---

### DISC-2 — Architecture diagram uses undefined terms: "Synchronization Layer" / "ruamel Formatting Model"

| | |
|---|---|
| **Status** | 🟡 **Still unresolved.** The terms are still in `explanation.md` (Architecture Flow diagram), flagged as an open question. No human or AI has defined what they mean. |
| **File** | [`explanation.md`](file:///d:/Cybersec/internship/CST_Auto_Remidiator-cst-engine-v1/explanation.md) — Architecture Flow section |

**What's in the diagram:**

```
Transformation
↓
Synchronization Layer   ⚠ UNDEFINED
↓
ruamel Formatting Model ⚠ UNDEFINED
↓
Serializer
```

**Why it's a problem:**  
These terms appear nowhere in any source file, test, or spec document. They appear to be leftover planning artifacts. A contributor implementing Stage 7 or 8 might build against them thinking they are real, defined components.

**Suggested fix (requires a human decision):**  
Two options — pick one:

- **(a) Remove them:** Delete both lines from the diagram and add a note that they were planning artifacts that were never implemented. The architecture jumps from Stage 6 (Transformation) directly to Stage 7 (Verification) and Stage 8 (Serializer).
- **(b) Define them:** Assign "Synchronization Layer" to Stage 7 and "ruamel Formatting Model" to Stage 8, document what each actually means in terms of the CST/ruamel objects, and update the stage descriptions accordingly.

**Do not build Stage 7 or Stage 8 against these terms until option (a) or (b) is chosen.**

---

### DISC-3 — Stage ownership matrix says Stage 6 is "Mutation only" but it also rebuilds the semantic model

| | |
|---|---|
| **Status** | 🟢 **RESOLVED (2026-06-29).** The `build_semantic_model()` call has been removed from `transformer.py`. Stage 6 is now strictly "Mutation only," matching the matrix entry in `explanation.md`. |
| **File** | [`explanation.md`](file:///d:/Cybersec/internship/CST_Auto_Remidiator-cst-engine-v1/explanation.md) line 434 |

**What the matrix says:**

```markdown
| **Stage 6** | Mutation only |
```

**What the code actually does:**  
Mutation + `build_semantic_model()` (a Stage 3 operation).

**Suggested fix:**  
This resolves automatically as a side effect of fixing DISC-1. Once `build_semantic_model()` is removed from `transformer.py`, Stage 6 will genuinely be "Mutation only" and the matrix entry will be accurate. Until then, the matrix is misleading.

If the semantic rebuild is intentionally kept in Stage 6 (i.e. DISC-1 is not fixed), update the matrix entry:

```markdown
| **Stage 6** | Mutation + semantic rebuild (see ⚠ note in Stage 6 section) |
```

---

## The 5 Test Gaps — Status

These are not bugs in the current code — the existing tests all pass. These are paths that have no test at all, meaning a future regression could be introduced silently.

---

### GAP-1 — No test with 3+ expression sites in one `run:` command

| | |
|---|---|
| **Status** | 🟢 **RESOLVED (2026-06-29).** `test_apply_rtl_substitutions_three_sites` added to `test_stage6_comprehensive.py`. |
| **File** | [`test_stage6_comprehensive.py`](file:///d:/Cybersec/internship/CST_Auto_Remidiator-cst-engine-v1/tests/test_stage6_comprehensive.py) |

**Why it matters:**  
`apply_rtl_substitutions()` tracks `previous_start` to detect overlapping replacements. With 2 replacements this guard runs once. With 3 replacements it runs twice — the second comparison is the one that would catch an off-by-one in the offset tracking.

**Suggested fix:**  
Add a test with a `run:` command containing 3 untrusted expressions:

```python
def test_apply_rtl_substitutions_three_sites() -> None:
    script = (
        "echo ${{ github.event.issue.title }} "
        "${{ github.event.comment.body }} "
        "${{ github.head_ref }}"
    )
    replacements = (
        _replacement(script, "${{ github.event.issue.title }}", "$ISSUE_TITLE", "e0"),
        _replacement(script, "${{ github.event.comment.body }}", "$COMMENT_BODY", "e1"),
        _replacement(script, "${{ github.head_ref }}", "$HEAD_REF", "e2"),
    )
    result = apply_rtl_substitutions(script, replacements)
    assert result == "echo $ISSUE_TITLE $COMMENT_BODY $HEAD_REF"
```

---

### GAP-2 — No integration test using the full Stage 1–6 compiler pipeline on a real file

| | |
|---|---|
| **Status** | 🟢 **RESOLVED (2026-06-29).** `tests/test_stage6_integration.py` added with two tests: `test_stage6_integration_clean_passthrough_fixture` and `test_stage6_integration_mixed_fixture_only_remediate_sites_transformed`. The mixed-fixture test also revealed that Stage 5 does not replicate the legacy eval-sink bail rule — this is now documented in the test. |
| **Files** | [`testing/run_scenarios.py`](file:///d:/Cybersec/internship/CST_Auto_Remidiator-cst-engine-v1/testing/run_scenarios.py), [`fixtures/`](file:///d:/Cybersec/internship/CST_Auto_Remidiator-cst-engine-v1/fixtures/) |

**Why it matters:**  
Stage 6 (`MutationPlanner` + `CSTTransformer`) has never been validated end-to-end against a real on-disk YAML file. The `testing/expected/` oracle files were generated against the legacy pipeline, not the new compiler. A subtle incompatibility between Stage 5's classification output and Stage 6's planner input would only be caught by a real-file integration test.

**Suggested fix:**  
Add a `test_stage6_integration.py` (or a new class in `test_pipeline_integration.py`) that reads `fixtures/clean_passthrough.yml` from disk and drives it through the full Stage 1→6 pipeline:

```python
from cst_auto_remediator.yaml_cst.parser import parse_yaml
from cst_auto_remediator.yaml_cst.builder import build_cst
from cst_auto_remediator.gha_semantic.builder import build_semantic_model
from cst_auto_remediator.gha_metadata.engine import MetadataWrapper
from cst_auto_remediator.gha_analysis.analyzer import analyze_workflow
from cst_auto_remediator.gha_transform.planner import MutationPlanner
from cst_auto_remediator.gha_transform.transformer import CSTTransformer

def test_stage6_real_fixture_clean_passthrough():
    content = (FIXTURES / "clean_passthrough.yml").read_bytes()
    doc, meta = parse_yaml(content)
    cst = build_cst(doc, meta)
    semantic = build_semantic_model(cst)
    wrapper = MetadataWrapper(semantic.workflow)
    analysis = analyze_workflow(semantic.workflow, wrapper)
    plan = MutationPlanner(wrapper).build_plan(analysis)
    result = CSTTransformer().transform(plan)
    # assert exactly one REMEDIATE step was transformed
    assert len(result.applied_step_mutations) == 1
    # assert no YAML serialization happened (Stage 8 not yet implemented)
    assert result.cst is not None
```

---

### GAP-3 — No test for the pre-existing `env:` block augmentation path

| | |
|---|---|
| **Status** | 🟢 **RESOLVED (2026-06-29).** `test_cst_transformer_augments_pre_existing_env_block_preserving_identity` added; includes `is`-identity check on the preserved KEEP_ME entry. |
| **File** | [`transformer.py`](file:///d:/Cybersec/internship/CST_Auto_Remidiator-cst-engine-v1/src/cst_auto_remediator/gha_transform/transformer.py) lines 112–118 |

**What the untested path does:**

```python
# transformer.py:112-118 — step already has an env: block
if isinstance(entry.key, YamlScalar) and entry.key.value == "env":
    new_env_entries = list(entry.value.entries)       # keep existing vars
    new_env_entries.extend(                            # append new generated vars
        _make_env_entry(env) for env in mutation.env_entries
    )
    entries.append(entry.with_value(entry.value.with_entries(new_env_entries)))
```

**Why it matters:**  
If a step already has `env: EXISTING: value` and is also a REMEDIATE site, Stage 6 should preserve `EXISTING` and append the new var. The current tests only cover the case where the step has no `env:` block at all.

**Suggested fix:**  
Add a test with a REMEDIATE step that already contains an `env:` block:

```yaml
- name: existing-env
  env:
    KEEP_ME: some-value
  run: echo ${{ github.event.issue.title }}
```

After transformation, assert:
- `KEEP_ME` is still present and is the **same object** (`is`) as the original node.
- `ISSUE_TITLE` was appended after it.
- The `run:` value is `echo $ISSUE_TITLE`.

---

### GAP-4 — No test for `REMEDIATE` + `sink_kind != RUN_COMMAND` raising `Stage6InvariantError`

| | |
|---|---|
| **Status** | 🟢 **RESOLVED (2026-06-29).** `test_mutation_planner_raises_when_remediate_has_wrong_sink_kind` added. |
| **File** | [`planner.py`](file:///d:/Cybersec/internship/CST_Auto_Remidiator-cst-engine-v1/src/cst_auto_remediator/gha_transform/planner.py) lines 59–62 |

**The untested guard:**

```python
if classification.sink_kind is not SinkKind.RUN_COMMAND:
    raise Stage6InvariantError(
        f"REMEDIATE classification {stable_id!r} is not in a run command"
    )
```

**Why it matters:**  
If Stage 5 ever emits a `REMEDIATE + ENV_ASSIGNMENT` classification (due to a new analysis rule or a bug), Stage 6 would raise correctly — but there is no test asserting this behaviour.

**Suggested fix:**

```python
def test_mutation_planner_raises_when_remediate_sink_is_not_run_command():
    content = (
        b"jobs:\n"
        b"  build:\n"
        b"    steps:\n"
        b"      - run: echo ${{ github.event.issue.title }}\n"
    )
    _, _, wrapper, analysis = _workflow_resources(content)
    key = "jobs.build.steps.0.run.exprs.0"
    bad = replace(
        analysis.expression_classifications[key],
        sink_kind=SinkKind.ENV_ASSIGNMENT,
    )
    bad_analysis = replace(analysis, expression_classifications={key: bad})
    with pytest.raises(Stage6InvariantError, match="not in a run command"):
        MutationPlanner(wrapper).build_plan(bad_analysis)
```

---

### GAP-5 — No test verifying two different expressions with the same base name get distinct hash-suffixed names

| | |
|---|---|
| **Status** | 🟢 **RESOLVED (2026-06-29).** `test_gen_safe_var_name_two_expressions_with_same_base_get_distinct_names` added. |
| **File** | [`namer.py`](file:///d:/Cybersec/internship/CST_Auto_Remidiator-cst-engine-v1/src/cst_auto_remediator/gha_transform/namer.py), [`test_stage6_comprehensive.py`](file:///d:/Cybersec/internship/CST_Auto_Remidiator-cst-engine-v1/tests/test_stage6_comprehensive.py) |

**The scenario not covered:**  
`github.event.issue_title` and `github.event.issue.title` both produce the base name `ISSUE_TITLE`. In a single step plan, the second call to `gen_safe_var_name()` would see the first result in `reserved_names` and should fall back to the hash-suffix variant. This is never tested.

**Suggested fix:**

```python
def test_gen_safe_var_name_two_expressions_same_base():
    scope = ScopeMetadata(scope_type="step", env={}, parent_scope=None)
    expr_a = "${{ github.event.issue.title }}"
    expr_b = "${{ github.event.issue_title }}"   # different path, same base

    name_a = gen_safe_var_name(expr_a, scope)
    assert name_a == "ISSUE_TITLE"

    # simulate planner passing name_a as reserved
    name_b = gen_safe_var_name(expr_b, scope, reserved_names=[name_a])
    assert name_b != name_a
    assert len(name_b.rsplit("_", 1)[1]) == 8   # hash suffix
    assert len(name_b) <= 40
```

---

## Priority Order for Fixes

| Priority | Item | Effort | Impact |
|---|---|---|---|
| 1 | **DISC-1 + DISC-3** — Remove `build_semantic_model()` from `transformer.py` | Low (delete ~3 lines, update orchestrator) | High — fixes a stage-boundary violation and makes the matrix accurate |
| 2 | **DISC-2** — Resolve undefined architecture terms | None (human decision only) | Medium — blocks safe Stage 7/8 design |
| 3 | **GAP-2** — Write Stage 1–6 real-file integration test | Medium | High — the most dangerous gap for a security tool |
| 4 | **GAP-3** — Add pre-existing `env:` augmentation test | Low | Medium |
| 5 | **GAP-1** — Add 3-expression RTL test | Low | Medium |
| 6 | **GAP-4** — Add `sink_kind` guard negative test | Low | Low |
| 7 | **GAP-5** — Add same-base-name namer collision test | Low | Low |

---

## What is Already Fine

The following items from the audit were **confirmed correct** and require no changes:

- `REMEDIATE`-only filter uses `is not` identity check (not string compare) — `planner.py:52`
- RTL sort key and `reverse=True` verified in source — `rtl.py:17`
- RTL overlap detection and content pre-match guards — `rtl.py:21–31`
- All copy-on-write via `dataclasses.replace()` — zero `object.__setattr__` bypass found
- Structural sharing: untouched step/job siblings are the same object (`is`), not copies
- `REMEDIATE + scope=None` raises `Stage6InvariantError` with no silent fallback — `planner.py:55–58`
- Enum values are `SAFE / REMEDIATE / BAILOUT / SKIP` — no stale `PASS/BAIL/TRANSFORM`
- No file writes, YAML serialization, or security re-analysis anywhere in `gha_transform/`
- `is`-identity assertions exist in tests for untouched siblings
- 2-expression RTL test exists and also explicitly proves LTR ordering would be wrong
- `REMEDIATE + scope=None` negative test exists
- Mixed-decision test (REMEDIATE + SKIP + SAFE in same workflow) exists
- **All 145 tests pass** (`pytest tests -v`, 1.94s)
