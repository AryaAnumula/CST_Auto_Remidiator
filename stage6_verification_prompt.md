# Independent Verification Request — Stage 6 (Transformation), CST Auto-Remediator

## What this project is

This is a security-research prototype (ISFCR Research Center internship project) that
deterministically detects and fixes a specific class of **command injection (CWE-78)**
in GitHub Actions workflow YAML files.

**The vulnerability, briefly:** GitHub Actions lets workflows embed `${{ ... }}`
expressions inside `run:` shell commands. GitHub substitutes these expressions with
plain text *before* the shell parses the command. Several expression sources — PR
titles, issue bodies, branch names, issue comments — are written entirely by external,
unauthenticated actors. If that text contains shell metacharacters (`;`, `|`,
backticks), they get pasted into the command string and interpreted by the shell as new
commands, giving an attacker arbitrary code execution on the CI runner, often with
access to repository secrets.

**The fix:** move the untrusted expression into an `env:` block and reference it via
`$VAR` in the `run:` command instead, since environment variable expansion happens
after the shell has already finished parsing command structure.

**This tool automates that rewrite** across a workflow file via a multi-stage compiler
pipeline: parse losslessly into an immutable CST, build a semantic model on top, attach
metadata, run security analysis to classify trust, and — for confidently-untrusted
cases only — transform the tree to inject the `env:` binding and swap the inline
expression for `$VAR`.

## Project history and why you are being asked to verify independently

The project was originally a 10-stage `ingest`/`classify`/`validate`/`mutate` pipeline.
In June 2026 it was redesigned into an **8-stage compiler architecture** explicitly
modeled on LibCST/Roslyn principles (immutable nodes, typed semantic wrappers,
stateless metadata providers, visitor-based analysis, copy-on-write transformation,
verification-before-serialization).

**Important context about how this project has operated so far:** at every stage
transition, the person running this project has had one AI session implement a stage,
then deliberately brought in a *different* AI session to independently verify the prior
work — because this project has a documented, repeated history of:
- Architecture/planning documents drifting out of sync with actual implemented code.
- A teammate's own self-written "certification" review of his own Stages 1–5 work being
  accepted as a starting point but then needing direct source-code spot-checks (which
  did catch real naming discrepancies — e.g. a planning doc used decision names
  `PASS/SKIP/BAIL/TRANSFORM` while the actual implemented enum uses
  `SAFE/SKIP/BAILOUT/REMEDIATE`).
- A maintainer/onboarding doc (`explanation.md`) repeatedly falling out of date relative
  to the actual codebase (e.g. its header claiming only "Stages 1–3 implemented" long
  after Stages 4, 5, and 6 had actually been built and tested).

**You are the next link in that chain.** Your job is to independently verify Stage 6
(Transformation), which was just implemented by a prior AI session. Do not take any
prior session's self-report, any architecture document, or `explanation.md` at face
value — treat all of them as claims to check against the actual `.py` source and actual
test execution, not as ground truth. If you find a discrepancy between what a document
says and what the code does, **trust the code**, and report the discrepancy explicitly
rather than silently reconciling it in your own head.

## The 8-stage architecture (for your orientation — verify this against
`explanation.md` and source, don't assume it's still accurate)

1. **Lossless YAML Parsing** — `ruamel.yaml` backend.
2. **Green CST** — immutable frozen-dataclass `YamlNode` tree, round-trip invariant
   `serialize(parse(S)) == S`. Lives under something like `yaml_cst/`.
3. **GitHub Actions Semantic Layer** — `Workflow`/`Job`/`Step`/`RunCommand`/
   `ExpressionSite` wrapping the Green CST. Lives under something like `gha_semantic/`.
4. **Metadata Providers** — precomputed `PositionMetadata`, `ScopeMetadata`,
   `ShellMetadata`, etc., before any analysis runs. Lives under something like
   `gha_metadata/`.
5. **Security Analysis** — produces `ExpressionClassification` objects with a
   `decision` field of type `AnalysisDecision` (confirmed real enum values: `SAFE`,
   `REMEDIATE`, `BAILOUT`, `SKIP` — do not expect `PASS`/`TRANSFORM`/`BAIL`, those names
   come from an earlier planning doc and are not what's implemented). Lives under
   something like `gha_analysis/`.
6. **Transformation — THIS IS WHAT YOU ARE VERIFYING.** Should live under something
   like `gha_transform/`, with files resembling `nodes.py`, `namer.py`, `rtl.py`,
   `planner.py`, `transformer.py` — but **confirm the actual file names and module
   structure yourself**, do not assume this list is exactly right.
7. **Verification** — not yet implemented as of Stage 6's completion.
8. **Lossless Serializer** — not yet implemented as of Stage 6's completion.

## Stage 6's intended responsibilities (this is the spec it was built against —
your job is to check whether the actual code satisfies it)

1. **Input:** consumes the immutable Green CST, the Semantic Tree, the metadata layer,
   and a `SecurityAnalysisResult`.
2. **Filter:** processes only `ExpressionClassification` entries where
   `decision == AnalysisDecision.REMEDIATE`. Every other decision (`SAFE`, `BAILOUT`,
   `SKIP`) must be left completely untouched.
3. **Plan:** builds a deterministic, immutable `MutationPlan` before touching the tree.
4. **Name generation:** a deterministic function generates POSIX-safe environment
   variable names from the expression context, with a collision-detection fallback
   (originally specified to check against scope metadata's visible env vars, and on
   collision append a deterministic hash suffix — confirm what's actually
   implemented).
5. **RTL substitution:** when a single `RunCommand` has multiple expression sites, the
   *only* string manipulation in this entire stage is substituting `${{ }}` text with
   `$VAR` references applied **right-to-left** (descending by byte offset), operating
   on the decoded command-text string only — never on raw YAML bytes. This ordering is
   a stated correctness invariant: substituting earlier offsets first would invalidate
   the positions of later, not-yet-substituted sites.
6. **Apply via copy-on-write only:** every tree modification goes through the Green
   CST's copy-on-write API (`replace()` / `with_*()`-style methods). No in-place
   mutation. No string concatenation or regex rewriting of YAML text anywhere except
   the one sanctioned RTL substitution described above, and even that result must be
   wrapped into a new immutable node, never spliced into YAML text directly.
7. **Structural sharing:** any node not touched by a mutation must remain the *same
   object* (`is`, not just `==`) in the output tree as in the input tree — not a copy.
   Only nodes on the path from a changed node up to the root should be new objects.
8. **Output:** a new immutable tree plus a result object describing what was applied.
   Must not serialize to YAML, must not write to disk, must not re-run security
   analysis or verification — those are explicitly out of scope for this stage.

## Your task

### Step 1 — Locate the actual code

Find the actual Stage 6 implementation in the repository. Do not assume the file
names/paths from this prompt are correct — search for them, and report what you
actually find versus what was expected.

### Step 2 — Read and assess the code against the spec above

For each of the 8 responsibilities listed above, check the actual source and report,
specifically:
- Does it do what's claimed?
- Is there any in-place mutation anywhere (a method that modifies `self.x = ...` on an
  already-constructed frozen dataclass would be a contradiction worth flagging
  explicitly, even though `frozen=True` should prevent this at the language level —
  check for any `object.__setattr__` bypasses too)?
- Is there any string slicing, `.replace()`, or regex substitution operating on
  anything other than the one sanctioned RTL path on decoded command text? Flag every
  instance you find, even ones that look superficially harmless.
- Does the RTL substitution actually sort/iterate in the right order? Don't just trust
  a variable name like `sorted_descending` — check the actual sort key and `reverse`
  argument.
- Does structural sharing actually hold, or does the transformer secretly deep-copy
  more of the tree than necessary "to be safe"? This is a common shortcut a prior AI
  session might have taken without flagging it, since it produces correct output while
  violating the stated invariant.
- Is there a hard-error path (not a silent fallback) for any case where a `REMEDIATE`
  decision lacks required scope metadata? This was an explicit design decision on this
  project: a `REMEDIATE` classification with missing scope metadata should raise an
  exception, not silently default to empty-scope behavior. Confirm whether this is
  actually implemented or whether a fallback was quietly added instead.

### Step 3 — Find and run the actual test suite

**You need to locate this yourself — I do not know the exact path.** Search the
repository for test files related to Stage 6 (likely named something like
`test_stage6_comprehensive.py`, possibly alongside other `test_stageN_*.py` files for
earlier stages, in a `tests/` directory at the repo root — but confirm the real
location and naming convention rather than assuming).

Once located:
1. Run the full test suite (not just the Stage 6 file in isolation) and report exact
   pass/fail counts. If anything fails, show the actual failure output, not a summary.
2. Read the actual test file contents — don't just trust that tests exist and pass.
   Specifically check:
   - Are there tests asserting **object identity** (`is`) for untouched sibling nodes
     between input and output trees, or only equality (`==`)? Equality-only tests would
     pass even if structural sharing is silently violated by deep-copying — this is the
     single most important thing to check, because it's the kind of test gap that lets
     a real architectural violation hide behind a green test suite.
   - Is there a test with **multiple expression sites in a single `run:` command**,
     specifically exercising the RTL substitution path? A test suite with only
     single-expression fixtures would never catch an RTL ordering bug.
   - Is there a test that explicitly constructs a `REMEDIATE`-decision classification
     with missing/`None` scope metadata and asserts that it raises, or does no such
     negative test exist?
   - Is there a test confirming that `SAFE`/`BAILOUT`/`SKIP`-decision sites are left
     completely untouched in a workflow that also contains `REMEDIATE` sites (i.e. a
     mixed-decision, multi-site test) — or do existing tests only ever test one
     decision type per fixture?
3. If the existing fixtures/repo conventions include something like an
   `inputs`/`outputs`/`explanations` (or similarly named) folder structure for
   integration-style scenarios — check for this, it has been used elsewhere in this
   project for fixture-based verification — locate it if it exists and verify it was
   actually executed against the real Stage 6 code (not hand-written/predicted) for at
   least one realistic multi-job, multi-decision workflow file. If no such structure
   exists for Stage 6 yet, note that as a gap rather than assuming it's there.

### Step 4 — Report back plainly

Structure your findings as:
- **Confirmed working** — what you verified actually does what it claims, with the
  specific file/line evidence.
- **Test gaps** — specific missing test cases (especially the identity-vs-equality and
  RTL-multi-site and scope=None-invariant checks above), even if everything that exists
  currently passes.
- **Discrepancies** — any place where a document (this prompt, `explanation.md`, an
  architecture PDF if present in the repo) claims something the code doesn't actually
  do, or vice versa.
- **Anything you'd flag before trusting this code in a security tool** — be specific
  and concrete, not generic ("could use more tests" is not useful; "no test exercises
  the RTL path with 3+ expression sites in one command, only single-expression
  fixtures exist" is useful).

Do not soften this report to be reassuring. The entire point of bringing in a separate
AI session is to get an honest, independent check — treat a clean bill of health as
something you need to have actually earned through inspection, not something to default
to.
