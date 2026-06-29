# CST Auto Remediator — Project Secretary

> **Maintainer rule:** Whenever you change core behavior, add fixtures, or extend the
> pipeline, **update this file in the same change**. This document is the onboarding
> source of truth for humans and AI tools working on the repo.

**Last updated:** 2026-06-29  
**Scope implemented:** Stages 1–6 of the new compiler architecture (Parsing → Green CST →
Semantic Layer → Metadata Providers → Security Analysis → Transformation). Stage 6
(Transformation) completed 2026-06-29. Stages 7 (Verification) and 8 (Lossless Serializer)
are **not yet implemented**. The original 10-stage ingest/classify/validate/mutate
pipeline (`ingest.py`, `classify.py`, `traverse.py`, `validate.py`, `mutate.py`,
`pipeline.py`) is **deprecated and coexists during migration** — see the Legacy Pipeline
section below; do not extend it for new work.

---

## What this project does

Deterministic, rule-based auto-remediation for a specific class of **command injection**
in GitHub Actions workflow YAML files.

**Vulnerability:** Untrusted data (PR titles, issue bodies, branch names) interpolated
into `run:` shell commands via `${{ ... }}` is substituted by GitHub as plain text
*before* the shell parses the command — enabling injection.

**Fix (when safe):** Move the expression into `env:` and reference `$SAFE_VAR` in `run:`.
The shell treats env vars as opaque literals.

**Design principles:**

1. **CST / round-trip parsing** — use `ruamel.yaml` in round-trip mode so formatting,
   comments, and quote style outside the edit are preserved byte-for-byte.
2. **Determinism** — no LLM judgment; fixed enums and rule chains only.
3. **Bailout-first** — refuse to patch ambiguous or unsafe cases; log structured reasons.
4. **Audit trail** — every expression site gets a report row with offsets, classification,
   action, and reason.

---

## Repository layout

```
CST_Auto_Remidiator/
├── explanation.md          ← YOU ARE HERE (project secretary — keep updated)
├── README.md               ← Short project blurb
├── pyproject.toml          ← Package metadata, deps (ruamel.yaml>=0.18,<0.19), pytest config
│
├── src/cst_auto_remediator/  ← Core library (legacy pipeline plus compiler Stages 1–6)
│   ├── __init__.py         ← Public API export
│   ├── models.py           ← Shared types, enums, dataclasses
│   ├── ingest.py           ← Stage 1: read, validate, parse
│   ├── classify.py         ← Stage 2: expression scan + taint classification
│   ├── traverse.py         ← Stage 2: walk jobs/steps/run
│   ├── validate.py         ← Stage 3: rule chain (sinks, collisions)
│   ├── mutate.py           ← Stage 3: CST patch + byte-preserving text output
│   ├── pipeline.py         ← Orchestrator: wires Stages 1→2→3
│   │
│   ├── yaml_cst/           ← Stage 2: Immutable Lossless YAML CST Nodes & Builder
│   │   ├── nodes.py        ← Green CST Node classes (Frozen dataclasses)
│   │   ├── builder.py      ← CST Builder converting ruamel parsed maps/seqs
│   │   └── parser.py       ← Stage 1: UTF-8, YamlBomb, size limits and parser
│   │
│   ├── gha_semantic/       ← Stage 3: GHA Semantic Layer
│   │   ├── nodes.py        ← Semantic concepts (Workflow, Job, Step, run, env)
│   │   ├── scanner.py      ← Decoupled balanced-brace expression scanner
│   │   └── builder.py      ← Semantic model builder & Diagnostics (GHA001-GHA010)
│   │
│   ├── gha_metadata/       ← Stage 4: GHA Metadata Providers
│   │   ├── nodes.py        ← Metadata models (Position, Scope, Shell, Expression, Bundle)
│   │   ├── engine.py       ← MetadataWrapper cache engine & MetadataProvider
│   │   └── providers.py    ← Concrete Position, Scope, Shell, and Expression providers
│   │
│   ├── gha_analysis/       ← Stage 5: GHA Security Analysis
│   │   ├── nodes.py        ← Finding enums and analysis models (Trust, Sink, Decision, Statistics)
│   │   ├── classifier.py   ← Taint-source prefixes and environment variable taint propagation
│   │   ├── validator.py    ← Supported shells, runners, scalar styles, and quoting checkers
│   │   ├── diagnostics.py  ← Compiler warning and error diagnostics (ANA001-ANA005)
│   │   └── analyzer.py     ← analyze_workflow() central driver querying Stage 4 metadata
│   │
│   └── gha_transform/      ← Stage 6: Transformation planning and copy-on-write CST mutation
│       ├── nodes.py        ← MutationPlan, StepMutation, EnvVarEntry, SiteReplacement, result models
│       ├── namer.py        ← Deterministic env var naming with ScopeMetadata.env collision handling
│       ├── rtl.py          ← Right-to-left run-command substitution helper
│       ├── planner.py      ← MutationPlanner over SecurityAnalysisResult classifications
│       └── transformer.py  ← CSTTransformer applying plans through Green CST copy-on-write APIs
│
├── tests/                  ← pytest suite
│   ├── test_classify.py    ← Unit tests for classification
│   ├── test_validate.py    ← Unit tests for validation rules
│   ├── test_ingest.py      ← Stage 1 / line-ending tests
│   ├── test_fixtures.py    ← Integration tests over fixtures/
│   ├── test_already_remediated.py ← Already-remediated + testing/ scenarios
│   ├── test_stage2_comprehensive.py ← Stage 2 Green CST tests
│   ├── test_stage3_comprehensive.py ← Stage 3 GHA Semantic Layer tests
│   ├── test_stage4_comprehensive.py ← Stage 4 Metadata Providers tests
│   ├── test_stage5_comprehensive.py ← Stage 5 Security Analysis tests
│   ├── test_stage6_comprehensive.py ← Stage 6 Transformation tests
│   └── test_pipeline_integration.py ← End-to-end compiler integration tests
│
├── testing/                ← Complex integration scenarios (see testing/README.md)
│   ├── inputs/             ← Scenario YAML inputs
│   ├── expected/           ← Expected report + YAML oracle files
│   ├── output/             ← Latest run_scenarios.py outputs (for manual review)
│   └── run_scenarios.py    ← Regenerate testing/output/
│
├── fixtures/               ← Minimal YAML scenarios + expected outputs
│   ├── *.yml               ← Input workflows
│   ├── clean_passthrough2.yml ← Already-remediated workflow (verify_diff2.py)
│   ├── *.expected.json     ← Expected report entries (incl. start/end offsets)
│   └── *.expected.yml      ← Expected patched YAML (where applicable)
│
├── scripts/
│   └── regenerate_expected.py ← Regenerate fixtures/.expected.* after changes
│
├── verify_basic.py         ← Manual check: report, offsets, line endings
├── verify_diff.py          ← Manual diff: vulnerable fixture (expects changes)
├── verify_diff2.py         ← Manual diff: already-remediated fixture (expects NO diff)
├── verify_output.yml       ← Ephemeral output from verify_diff.py
└── verify_output2.yml      ← Ephemeral output from verify_diff2.py
```

## Architecture Flow (Version 1)

```
Parser
↓
Green CST
↓
Semantic Layer
↓
Metadata
↓
Transformation
↓
Synchronization Layer   ⚠ UNDEFINED — see note below
↓
ruamel Formatting Model ⚠ UNDEFINED — see note below
↓
Serializer
```

> **⚠ Open question (added 2026-06-29):** "Synchronization Layer" and "ruamel Formatting
> Model" appear in this diagram but are not defined anywhere else in this document, in
> the repository layout above, or in the Stage 7/8 descriptions in
> `CST_Auto_Remediator_V1_Architecture.pdf`. It's unclear whether these map onto an
> existing stage (e.g. part of Stage 7 Verification or Stage 8 Serialization under a
> different name) or are a planning artifact that hasn't been implemented yet. **Do not
> assume a meaning for these and build against it** — confirm with whoever added this
> diagram before treating either term as a real component, and update this note once
> resolved.

---

## Legacy pipeline (DEPRECATED — kept for reference during migration only)

> This section describes the **original 10-stage `ingest`/`classify`/`validate`/`mutate`
> pipeline**, which predates the June 2026 compiler-architecture redesign. It is kept
> running for existing tests during the migration cutover but is **not the current
> architecture** — see "Architecture Flow (Version 1)" above for the live 8-stage design.
> Do not extend this pipeline for new work; it will be removed once Stage 8 replaces the
> public entry point.

```
remediate_file(path)
    │
    ├─ Stage 1: ingest.py
    │     read bytes → SHA-256, UTF-8 check, 2 MB cap, detect line_ending
    │     parse with ruamel (maxAliasCount=10) → CommentedMap CST
    │     on failure → BAILED report (no offsets)
    │
    ├─ Stage 2: traverse.py + classify.py
    │     walk jobs.<id>.steps[].run only
    │     find ${{ ... }} spans → ExpressionSite list
    │     classify: UNTRUSTED | TRUSTED | AMBIGUOUS
    │     detect scalar_type: plain | block
    │
    └─ Stage 3: validate.py + mutate.py + pipeline.py
          per site: validate_site() → PATCHED | SKIPPED | BAILED
          if any PATCHED: apply_patches(CST) + build_patched_text(source_text)
          assert_byte_preservation() on unchanged lines
          return (yaml_string, report[])
```

---

## Core source files (detailed)

### `src/cst_auto_remediator/__init__.py`

**Role:** Package entry point.  
**Exports:** `remediate_file` — the only public API for this session.  
**Usage:** `from cst_auto_remediator import remediate_file`

---

### `src/cst_auto_remediator/models.py`

**Role:** Single source of truth for data shapes and fixed reason codes.

| Type | Purpose |
|------|---------|
| `ReasonCode` | Fixed enum for all bail/skip reasons (Stage 1 + Stage 3) |
| `Classification` | `UNTRUSTED`, `TRUSTED`, `AMBIGUOUS` |
| `ScalarType` | `plain` or `block` (`\|` / `>` scalars) |
| `Action` | `PATCHED`, `SKIPPED`, `BAILED` |
| `FileMetadata` | `path`, `size`, `sha256`, `encoding`, **`line_ending`** |
| `ExpressionSite` | One `${{ ... }}` occurrence with **start_offset/end_offset** relative to `run_value` |
| `IngestSuccess` / `IngestFailure` | Stage 1 result; success carries `source_text` (bytes-accurate) |
| `ReportEntry` | One JSON report row; `to_dict()` includes offsets for expression sites |
| `ValidationResult` | Output of `validate_site()` for one site |
| `PlannedPatch` | Approved mutation: site + generated env var name |

**Report fields (expression sites):**  
`file`, `job_id`, `step`, `step_id`, `action`, `reason`, `env_var_added`,
`expression_text`, `classification`, `scalar_type`, **`start_offset`**, **`end_offset`**

**Report fields (Stage 1 file bail):** only `file`, `action=BAILED`, `reason` — no offsets.

---

### `src/cst_auto_remediator/ingest.py` — Stage 1

**Role:** Ingestion + parser. No remediation logic here.

**Functions:**

| Function | Description |
|----------|-------------|
| `detect_line_ending(raw_bytes)` | `\r\n` if present in bytes, else `\n` |
| `read_source_text(raw_bytes)` | UTF-8 decode **without** normalizing newlines |
| `ingest(path)` | Full Stage 1; returns `IngestSuccess` or `IngestFailure` |
| `create_yaml_dumper()` | Configured ruamel instance for round-trip dump checks |

**Limits & bails:**

| Check | ReasonCode |
|-------|------------|
| File > 2 MB | `FILE_TOO_LARGE` |
| Invalid UTF-8 | `INVALID_ENCODING` |
| YAML parse error | `PARSE_ERROR` |
| Alias bomb (>10) | `YAML_BOMB` |

**Important:** SHA-256 is computed on **raw bytes** before decode. `source_text` preserves
original line endings for Stage 3 output assembly.

---

### `src/cst_auto_remediator/classify.py` — Stage 2 (classification only)

**Role:** Pure functions for expression discovery and taint labels. **No YAML traversal.**

| Function | Description |
|----------|-------------|
| `find_expressions(value)` | Regex scan for `${{ ... }}` per logical line; returns `(text, start, end)` offsets **relative to the run scalar string** |
| `extract_expression_body(text)` | Strip `${{` / `}}` wrapper |
| `classify_expression(body)` | Apply prefix/exact rules → `Classification` |

**UNTRUSTED rules:** `github.event.*`, `github.head_ref`, `github.base_ref`,
`fromJSON(inputs.*)`

**TRUSTED rules:** `secrets.*`, `vars.*`, `github.sha`, `github.run_id` (exact)

**AMBIGUOUS:** everything else — **not auto-remediated** (bailout-first)

---

### `src/cst_auto_remediator/traverse.py` — Stage 2 (traversal only)

**Role:** Walk parsed CST and build `ExpressionSite` list. Calls `classify.py`; does not validate or mutate.

**Traversal scope (current):** `jobs.<job_id>.steps[].run` for mutation candidates;  
`jobs.<job_id>.steps[].env` is scanned by `traverse_env_bindings()` for **audit only**
(already-remediated detection).

**Block scalar detection:** `LiteralScalarString` / `FoldedScalarString` → `ScalarType.BLOCK`.
Expressions inside block scalars are still **scanned and reported**; Stage 3 skips them.

**Already-remediated detection:** When `env:` binds an UNTRUSTED `${{ ... }}` and `run:`
references `$VAR` without embedding the same expression, the pipeline reports
`SKIPPED` / `ALREADY_REMEDIATED` and leaves the file byte-identical.

---

### `src/cst_auto_remediator/validate.py` — Stage 3 (rule chain only)

**Role:** Decide PATCHED / SKIPPED / BAILED per `ExpressionSite`. **No file I/O, no mutation.**

**Rule order in `validate_site()`:**

1. Block scalar → `SKIPPED` / `BLOCK_SCALAR_OUT_OF_SCOPE`
2. TRUSTED → `SKIPPED` / `TRUSTED`
3. AMBIGUOUS → `SKIPPED` / `AMBIGUOUS_EXPRESSION`
4. Sink detection → `BAILED` (`SINK_EVAL`, `SINK_BASH_C`, `SINK_SH_C`, `SINK_COMMAND_SUBSTITUTION`)
5. Single-quoted expression → `SKIPPED` / `SINGLE_QUOTED_EXPRESSION`
6. Env already binds same `${{ ... }}` value → `PATCHED` **run-only** (`insert_env=False`)
7. Existing env key collision (different value) → `BAILED` / `ENV_NAME_COLLISION`
8. Two expressions same generated name in one step → `BAILED` / `GENERATED_NAME_COLLISION`
9. Otherwise → `PATCHED` + new `env:` block (`insert_env=True`)

**Sink notes:** `\beval\b`, `\bbash\s+-c\b`, `\bsh\s+-c\b` only (not `/bin/bash -c` yet).
`$(...)` and backticks bail only when the **expression span** lies inside that region.

**Per-expression bail:** One bad site does not block patching other sites in the same step.

---

### `src/cst_auto_remediator/mutate.py` — Stage 3 (mutation + output)

**Role:** Apply approved patches and produce final YAML string.

| Function | Description |
|----------|-------------|
| `apply_patches(document, patches)` | In-place CST edit: insert `env:` before `run`, replace `${{ ... }}` with `$VAR` in run scalar |
| `serialize_document(document)` | ruamel dump — used to verify CST is dumpable (not the primary output path) |
| `build_patched_text(original, patches, line_ending)` | **Primary output:** surgical text edit preserving untouched bytes and **original line endings** |
| `assert_byte_preservation(...)` | Enforced check: only run + new env lines may differ |

**Why two mutation paths?** Full ruamel re-dump reformatted unrelated lines. CST edits
drive *what* changes; `build_patched_text` drives *how* the file bytes are assembled.

---

### `src/cst_auto_remediator/pipeline.py` — Orchestrator

**Role:** `remediate_file(path) -> (yaml_out | None, report[])`

1. `ingest()` — bail early on Stage 1 failure
2. `traverse_jobs()` — collect run expression sites
3. `traverse_env_bindings()` — detect already-remediated steps (report only)
4. For each run site: `validate_site()` → build `ReportEntry` (includes offsets)
5. Collect `PlannedPatch` for PATCHED sites (may be run-only if env already binds expr)
6. If patches: `apply_patches` + `build_patched_text(source_text, line_ending)`
7. `assert_byte_preservation`
8. Return unchanged `source_text` if no patches needed

---

### `src/cst_auto_remediator/gha_transform/` — Stage 6

**Role:** Build and apply immutable transformation plans. Stage 6 consumes Stage 5 `SecurityAnalysisResult` objects, filters to `AnalysisDecision.REMEDIATE`, generates deterministic env var bindings, applies right-to-left run-command substitutions, and returns a new CST/semantic workflow without serializing YAML or writing files.

| File | Purpose |
|------|---------|
| `nodes.py` | Frozen dataclasses for `MutationPlan`, `StepMutation`, `EnvVarEntry`, `SiteReplacement`, and `TransformationResult` |
| `namer.py` | `gen_safe_var_name()` using `ScopeMetadata.env`, POSIX-safe names, truncation, and deterministic hash suffixes on collision |
| `rtl.py` | `apply_rtl_substitutions()`, the only sanctioned Stage 6 string operation |
| `planner.py` | `MutationPlanner`, including the invariant that `REMEDIATE` classifications must have scope metadata |
| `transformer.py` | `CSTTransformer`, applying plans through Green CST copy-on-write methods and preserving untouched sibling identity |

**Key implementation details (verified 2026-06-29 via independent code audit):**

- Filter uses `is not` identity comparison on `AnalysisDecision.REMEDIATE` — not string equality.
- RTL sort is `sorted(replacements, key=lambda item: item.start_offset, reverse=True)` — verified in `rtl.py:17`.
- `rtl.py` additionally enforces range validity, overlap detection, and content pre-match before slicing — raises `ValueError` on any violation.
- All copy-on-write goes through `dataclasses.replace()` via `YamlNode.replace()`. Zero direct field assignment on frozen instances; no `object.__setattr__` bypass anywhere in the package.
- Structural sharing: untouched sibling steps and jobs are passed through by reference (same object), not copied. Verified by `is`-identity assertions in `test_stage6_comprehensive.py`.
- `REMEDIATE` classification with `scope=None` raises `Stage6InvariantError` immediately — no silent fallback to empty scope.

> **Stage 6 mutation contract (updated 2026-06-29):** `CSTTransformer.transform()` returns a new `YamlDocument` CST in `TransformationResult.cst` and sets `TransformationResult.workflow = None`. The semantic model is **not** rebuilt inside Stage 6 — that is the explicit responsibility of Stage 7 (Verification) or the pipeline orchestrator. If you need the post-transform semantic view, call `build_semantic_model(result.cst)` after Stage 6 returns.

---

## Fixtures (test scenarios)

| Fixture | Expected action | Purpose |
|---------|-----------------|---------|
| `clean_passthrough.yml` | PATCHED | Plain scalar, UNTRUSTED, no env collision |
| `bail_sink.yml` | BAILED / SINK_EVAL | Expression inside `eval` |
| `bail_collision.yml` | BAILED / ENV_NAME_COLLISION | Pre-existing `ISSUE_TITLE` env key |
| `block_scalar_flagged.yml` | SKIPPED / BLOCK_SCALAR_OUT_OF_SCOPE | `run: \|` — detected, not mutated |
| `crlf_preservation.yml` | PATCHED | File saved with `\r\n`; guards line-ending regression |
| `clean_passthrough2.yml` | SKIPPED / ALREADY_REMEDIATED | Already-fixed workflow; must pass through unchanged |

Each fixture has `*.expected.json`. Patched fixtures also have `*.expected.yml`.

### `testing/` scenarios (complex integration)

| Input | Purpose |
|-------|---------|
| `multi_step_mixed.yml` | Mixed: already-remediated + vulnerable + block + eval sink in one file |
| `partial_env_run_only.yml` | Env binds expression but run still has `${{ ... }}` — run-only patch |

Run: `python testing/run_scenarios.py` → writes `testing/output/` for manual review.

> **⚠ Legacy pipeline only (verified 2026-06-29):** `run_scenarios.py` calls `remediate_file()` from the **deprecated legacy pipeline** (`pipeline.py`), not the new Stage 1–6 compiler architecture. The `testing/expected/` oracle files therefore test legacy behavior only. There is currently no integration test that feeds a real YAML file through the full compiler pipeline (Stages 1–6) and verifies the resulting tree or YAML output. This is a known gap — see Known gaps section.

**Offset reference (run_value slice verification):**

| Fixture | start | end |
|---------|-------|-----|
| clean_passthrough | 22 | 53 |
| bail_sink | 11 | 42 |
| bail_collision | 22 | 53 |
| block_scalar_flagged | 22 | 53 |
| crlf_preservation | 6 | 37 |

Verify: `run_value[start:end] == expression_text`

---

## Tests & manual verification

```powershell
pip install -e ".[dev]"
pytest tests -v
python verify_basic.py
python verify_diff.py
python verify_diff2.py
python testing/run_scenarios.py
```

After changing expected outputs intentionally:

```powershell
python scripts/regenerate_expected.py
```

---

## Architectural Stage Guidelines & Invariants

To maintain a clean compiler structure, the following stage definitions and boundary rules are enforced:

### 1. Stage Ownership Matrix

| Stage | Owns |
| :--- | :--- |
| **Stage 1** | Parsing only |
| **Stage 2** | Syntax only |
| **Stage 3** | Semantics only |
| **Stage 4** | Metadata only |
| **Stage 5** | Security analysis only |
| **Stage 6** | Mutation only |
| **Stage 7** | Verification only |
| **Stage 8** | Serialization only |

### 2. Semantic Model Scope
Stage 3 models the general **GitHub Actions execution structure**, while Version 1 actively analyzes only `RunCommand` and `EnvBinding` expression sites.

### 3. Metadata Invariant: Facts, Not Decisions
Metadata Providers (Stage 4) gather objective facts about the CST/Semantic structure, they **never** make security decisions (which are deferred entirely to Stage 5):
* **Good Metadata (Stage 4)**: Effective shell, runner, env scopes, node paths, offset maps, duplicate expressions, step/run ordering.
* **Bad Metadata (Stage 4 - DO NOT DO)**: Trusted, untrusted, dangerous, vulnerable, malicious.

### 4. ExpressionSite Purity
`ExpressionSite` nodes remain strictly **syntax-oriented**. They represent syntax locations and character indices only.
We must **not** add metadata or analysis fields (such as `classification`, `reason`, `sink`, `severity`, or `patched`) directly to the `ExpressionSite` syntax/semantic node. Those facts and findings belong to Stage 4 (Metadata) and Stage 5 (Security Analysis / Finding logs) registries.

## Known gaps (future sessions — do not "fix" silently)

- Block scalar (`run: |` / `>`) remediation — detected only (out of V1 scope, deferred to V2)
- `/bin/bash -c`, `env bash -c` sink variants
- Single-quoted run flip to double-quoted for `$VAR` expansion
- Hash-suffix env name collision fallback (architecture doc) — currently bails with `GENERATED_NAME_COLLISION` in the legacy pipeline; new compiler-architecture naming collision handling lives in `gha_transform/namer.py`
- Stage 7 (Verification) and Stage 8 (Lossless Serializer) — not yet implemented
- CLI, sidecar report files — not implemented
- Traversal beyond `jobs.*.steps[].run`
- "Synchronization Layer" / "ruamel Formatting Model" in the Architecture Flow diagram are undefined — see the open question note above

**Stage 6 test gaps (identified 2026-06-29 via independent audit — all resolved 2026-06-29):**

- ~~No test with 3+ expression sites in a single `run:` command~~ → **FIXED:** `test_apply_rtl_substitutions_three_sites` added.
- ~~No integration test using the full Stage 1–6 compiler pipeline on a real YAML file~~ → **FIXED:** `tests/test_stage6_integration.py` added with two real-fixture tests.
- ~~Pre-existing `env:` augmentation path has no test~~ → **FIXED:** `test_cst_transformer_augments_pre_existing_env_block_preserving_identity` added.
- ~~No test for a `REMEDIATE` classification with `sink_kind != RUN_COMMAND`~~ → **FIXED:** `test_mutation_planner_raises_when_remediate_has_wrong_sink_kind` added.
- ~~No test verifying same-base-name hash-suffix collision~~ → **FIXED:** `test_gen_safe_var_name_two_expressions_with_same_base_get_distinct_names` added.

---

## Change log (secretary record)

| Date | Change |
|------|--------|
| 2026-06-24 | Initial Stages 1–3 implementation with ruamel CST |
| 2026-06-24 | Fixed report offsets (`start_offset`/`end_offset` threaded through `ReportEntry`) |
| 2026-06-24 | Fixed CRLF preservation via `FileMetadata.line_ending` + `build_patched_text` |
| 2026-06-24 | Added `crlf_preservation` fixture; `explanation.md` created as project secretary |
| 2026-06-24 | Added `ALREADY_REMEDIATED` detection, run-only patch for partial env binding |
| 2026-06-24 | Fixed `clean_passthrough2.yml` to already-remediated form; added `testing/` scenarios |
| 2026-06-28 | Completed Stage 2 Green CST Construction, enhanced copy-on-write methods, added structural equality, and added comprehensive test suite |
| 2026-06-28 | Completed Stage 3 GHA Semantic Layer: scanner, nodes, builder, diagnostics (GHA001-GHA010), and test_stage3_comprehensive.py |
| 2026-06-28 | Completed Stage 4 GHA Metadata Providers: wrapper cache engine, Position, Scope, Shell, and Expression providers, and test_stage4_comprehensive.py |
| 2026-06-28 | Completed Stage 5 GHA Security Analysis: enums, nodes, classifier, validator, diagnostics (ANA001-ANA005), analyzer, and test_stage5_comprehensive.py |
| 2026-06-29 | Completed Stage 6 Transformation: mutation plans, deterministic env var naming, RTL run substitutions, copy-on-write CST transformation, and test_stage6_comprehensive.py |
| 2026-06-29 | Doc cleanup: fixed stale header (was still saying "Stages 1–3"), relabeled the old 3-stage pipeline section as deprecated/legacy, fixed stale "Stages 4+ not implemented" gap line, flagged undefined "Synchronization Layer"/"ruamel Formatting Model" terms in the architecture flow diagram as an open question pending clarification |
| 2026-06-29 | Independent Stage 6 audit (separate AI session): verified RTL ordering, copy-on-write invariants, structural sharing, scope=None hard-error path, all 145 tests pass; documented undocumented `build_semantic_model` call in `transformer.py`, flagged `testing/run_scenarios.py` as legacy-pipeline-only, recorded 5 specific test gaps in Known gaps section |
| 2026-06-29 | Stage 6 audit fix pass: (1) removed `build_semantic_model()` call from `transformer.py` — Stage 6 now owns mutation only, `TransformationResult.workflow` is always `None`, semantic rebuild is Stage 7/orchestrator responsibility; (2) updated two existing Stage 6 tests to rebuild semantic in-test via `build_semantic_model(result.cst)`; (3) added `tests/test_stage6_integration.py` with two real-fixture Stage 1→6 pipeline integration tests; (4) added 4 new unit tests closing all 5 audit gaps (GAP-1/3/4/5 in comprehensive, GAP-2 in integration); total test count 145 → 151, all passing |

---

## Instructions for the next contributor (human or AI)

1. Read this file first.
2. Read `pipeline.py` for the end-to-end flow.
3. Run `pytest tests -v` before and after your change.
4. If behavior changes, update fixtures via `scripts/regenerate_expected.py` and verify offsets manually.
5. **Update this `explanation.md`** — especially the change log and any new gaps/fixtures.
6. Do not add LLM-based fix decisions; keep enums and rules deterministic.