# Compiler Walkthrough: Stages 1–4
## Technical Architecture and Implementation Guide for GHA CST Auto-Remediator

This document serves as the definitive technical guide for the compiler front-end of the CST Auto-Remediator. It outlines the project's motivations, pipeline structure, stage-by-stage implementation details, execution flows, and key design patterns. This guide is tailored for Computer Science students and researchers joining the project to help them fully understand the architecture and quickly become productive contributors.

---

## 1. Project Overview

### Research Title
*CST-Based Deterministic Auto-Remediation of Command Injection Vulnerabilities in GitHub Actions Workflows*

### Problem Statement
In modern CI/CD security, command injection in GitHub Actions (GHA) workflows represents a widespread and severe class of vulnerabilities. These vulnerabilities occur when untrusted user inputs—such as pull request titles, issue bodies, branch names, or commit comments—are directly interpolated into shell commands. 

GitHub Actions executes expressions enclosed in `${{ ... }}` by performing literal string substitution *before* passing the command to the target shell runner. Consequently, if an attacker submits an issue title containing shell metacharacters (e.g., `"; rm -rf /; "` or `` `curl attacker.com` ``), the runner evaluates and executes the attacker's commands with the privileges of the GHA runner. This can lead to secrets theft (e.g., repository tokens, cloud credentials), supply chain tampering, or malicious infrastructure usage.

### The Danger of GitHub Actions Command Injection
To illustrate the vulnerability, consider the following step definition:

```yaml
- name: Log Issue Title
  run: echo "The issue title is: ${{ github.event.issue.title }}"
```

When an issue title like `hello" && curl http://malicious.site` is processed, GitHub interpolates it directly. The shell command becomes:

```bash
echo "The issue title is: hello" && curl http://malicious.site
```

The shell parses this as two separate commands separated by `&&`, executing the unauthorized `curl` command. 

### Why Regex and String Replacement Approaches Fail
Simple regex-based search-and-replace scripts or standard YAML parsing tools are fundamentally inadequate for safe remediation:
1. **Lack of Syntactic Context:** Regex patterns cannot distinguish between executable shell commands, string literals, comments, or nested maps. A regex may corrupt formatting, rewrite comments, or ignore quotes.
2. **Newline and Formatting Loss:** Standard YAML parsers (like PyYAML or generic serialization libraries) load YAML into arbitrary Python dictionaries. When dumping the dictionary back to a file, they discard comments, alter indentation, change quoting styles, and reorder keys, creating massive, un-reviewable code diffs.
3. **Evasion Susceptibility:** Attackers bypass simple string replacement filters using nested expressions, double-brackets, parenthetical wrapping, or index access notation (e.g., `github['event']['issue']['title']`).
4. **Collision Risks:** Naive scripts injecting environment variables into `env:` blocks can collide with pre-existing variables, causing silent failures or breaking workflow runs.

### The Compiler-Inspired CST Solution
To remediate these issues safely and deterministically, this project utilizes a compiler-inspired **Concrete Syntax Tree (CST)** architecture. By treating the YAML workflow as code, we can parse it losslessly, construct an immutable syntax tree, run semantic checks, analyze scopes and positions, and perform surgical, byte-preserving refactorings.

Our design separates syntax representation from semantic modeling and metadata resolution:

```
GitHub Actions YAML
        ↓
     Stage 1: Parser (Generic YAML, Encoding, Size, and Bomb Checks)
        ↓
     Stage 2: Green CST (Immutable generic YAML nodes, Source spans)
        ↓
     Stage 3: Semantic Layer (Red/GHA concept mapping, Brace scanning, Diagnostics)
        ↓
     Stage 4: Metadata (Contextual Scopes, Shell configurations, stable IDs)
        ↓
     Stage 5: Security Analysis (Taint classification & Remediation planning) [Future]
        ↓
     Stage 6: Transformation (Surgical tree refactoring) [Future]
        ↓
     Stage 7: Verification (Post-mutation syntax and safety checks) [Future]
        ↓
     Stage 8: Serializer (Byte-preserving output emitter) [Future]
```

At the present stage of development, the compiler front-end (Stages 1–4) has been fully implemented, providing a robust, lossless foundation.

---

## 2. Overall Compiler Pipeline

The complete compiler pipeline contains eight distinct stages, separating ingestion, semantic reasoning, metadata query, safety analysis, transformation, verification, and serialization. 

```
                                workflow.yml
                                     │
                                     ▼
                      +------------------------------+
                      |           Stage 1            |
                      |    Lossless YAML Ingest      |
                      +------------------------------+
                                     │
                                     ▼
                      +------------------------------+
                      |           Stage 2            |
                      |      Immutable Green CST     |
                      +------------------------------+
                                     │
                                     ▼
  ========================================================================
                                IMPLEMENTED
  ========================================================================
                                     │
                                     ▼
                      +------------------------------+
                      |           Stage 3            |
                      |   GHA Semantic Layer (Red)   |
                      +------------------------------+
                                     │
                                     ▼
                      +------------------------------+
                      |           Stage 4            |
                      |     Metadata Engine/Bundle   |
                      +------------------------------+
                                     │
                                     ▼
  ========================================================================
                           FUTURE / PLANNED PHASES
  ========================================================================
                                     │
                                     ▼
                      +------------------------------+
                      |           Stage 5            |
                      |      Security Analysis       |
                      +------------------------------+
                                     │
                                     ▼
                      +------------------------------+
                      |           Stage 6            |
                      |     AST-to-AST Transform     |
                      +------------------------------+
                                     │
                                     ▼
                      +------------------------------+
                      |           Stage 7            |
                      |      Semantic Verify         |
                      +------------------------------+
                                     │
                                     ▼
                      +------------------------------+
                      |           Stage 8            |
                      |    Lossless Serialization    |
                      +------------------------------+
                                     │
                                     ▼
                           remediated workflow.yml
```

* **Implemented Phases (Stages 1–4):** Parse generic YAML byte streams, construct the immutable tree, resolve GitHub Actions execution logic, run structural diagnostics, and resolve scopes and position metadata.
* **Planned Phases (Stages 5–8):** Scan expressions for security classifications, rewrite the tree to bind variables to safe shell variables, verify that no untrusted expressions remain, and serialize the result back to disk, guaranteeing byte preservation.

---

## 3. Stage-by-Stage Deep Explanation

### Stage 1: Lossless YAML Ingest (Ingestion & Validation)

#### Purpose
Stage 1 ingests raw bytes from the filesystem, validates encoding, checks file constraints, detects environmental characteristics (like dominant line endings), and parses the document into a lossless intermediate form. It acts as the gateway to the compiler, preventing malformed, oversized, or malicious payloads from entering the pipeline.

#### Input
* Raw byte array (`bytes`) representing the YAML file content.

#### Output
* A tuple containing:
  * `parsed_doc` (`Any`): The `ruamel.yaml` round-trip parsed representation.
  * `metadata` (`dict[str, Any]`): Ingestion metadata (SHA-256, size, encoding, line-ending convention).

#### Responsibilities
* Check file size limit (capped at 2 MB to prevent Denial of Service).
* Validate that bytes are decodable as valid UTF-8.
* Compute the SHA-256 hash of the raw bytes for audit logs.
* Detect the dominant line-ending convention (`\r\n` vs `\n`).
* Configure the parser to preserve quotes, indentation, default flow styles, and comments.
* Check for recursive references (alias bombs / Billion Laughs attacks) and abort immediately.

#### What this stage explicitly must NOT do
* This stage **must not** evaluate GitHub Actions semantics. It has zero knowledge of "jobs", "steps", "runs", or variables.
* It **must not** mutate the source text or attempt to fix syntax errors.

#### Major Classes
* `FileTooLargeError`: Raised when the input byte size exceeds the 2 MB maximum limit.
* `InvalidEncodingError`: Raised when the byte stream is not valid UTF-8.
* `YamlBombError`: Raised when anchor-alias counts exceed safe limits (max 10 aliases).
* `ParsingError`: Raised when the YAML parser encounters a syntax error or an empty document.

#### Major Functions
* [detect_line_ending(raw_bytes: bytes) -> str](file:///c:/CST/src/cst_auto_remediator/yaml_cst/parser.py#L43): Scans the bytes for `\r\n` and returns `"\r\n"` if found, otherwise `"\n"`.
* [read_source_text(raw_bytes: bytes) -> str](file:///c:/CST/src/cst_auto_remediator/yaml_cst/parser.py#L50): Decodes the raw bytes as UTF-8 *without* normalizing line endings, preserving them exactly.
* [check_alias_bomb(node: Any, visited: set[int] = None, alias_counter: list[int] = None) -> None](file:///c:/CST/src/cst_auto_remediator/yaml_cst/parser.py#L55): Performs a depth-first search of the parsed YAML memory structures to detect cyclical or excessive anchor references.
* [parse_yaml(raw_bytes: bytes) -> tuple[Any, dict[str, Any]]](file:///c:/CST/src/cst_auto_remediator/yaml_cst/parser.py#L81): Orchestrates the validation, hash computation, line-ending detection, parsing via `ruamel.yaml`, and alias bomb checks.

#### Internal Flow
1. Check byte array size against `MAX_FILE_SIZE` (2 MB).
2. Hash raw bytes via SHA-256.
3. Call `detect_line_ending` to discover the newline convention.
4. Try to decode bytes via `read_source_text`. If a `UnicodeDecodeError` is caught, raise `InvalidEncodingError`.
5. Instantiate a `ruamel.yaml.YAML` parser in round-trip mode (`typ="rt"`), with quote preservation enabled, width set to 4096, and max alias count set to 10.
6. Parse the decoded source text string via `StringIO`. If a parser error is caught, map it to `ParsingError` or `YamlBombError`.
7. Recursively check for alias bombs in memory structures via `check_alias_bomb`.
8. Return the parsed `CommentedMap` or `CommentedSeq` alongside the metadata dict.

#### Architectural Notes
Most standard YAML libraries decode files while converting newlines to `\n` and stripping quotes or comments. Stage 1 guarantees lossless parsing by configuring `ruamel.yaml` in round-trip mode and storing the original encoding parameters separately. This allows downstream serialization stages to reproduce the file byte-for-byte outside modified regions.

---

### Stage 2: Immutable Green CST (Generic YAML Syntax)

#### Purpose
Stage 2 builds the **Green Concrete Syntax Tree (CST)**. It maps the unstable, mutable in-memory structures generated by `ruamel.yaml` into strongly typed, completely immutable syntax node classes. The Green CST models generic YAML syntax, preserving line and column offsets, scalar quoting styles, block types, and list structures.

#### Input
* The parsed ruamel intermediate object representation and metadata dict from Stage 1.

#### Output
* A `YamlDocument` object containing the root syntax node and associated file metadata.

#### Responsibilities
* Convert ruamel collections recursively into typed nodes (`YamlMapping`, `YamlSequence`, `YamlScalar`).
* Extract and assign the exact starting `SourceSpan` (line, column) for keys, values, maps, sequences, and list items.
* Preserve literal scalar types and styles (plain, single-quoted, double-quoted, folded, literal) and raw string formats.
* Enforce tree immutability using frozen dataclasses to ensure thread safety and simplify change tracking.
* Implement structural equality (`structurally_equal`) that compares syntax structures while ignoring random runtime node IDs.
* Provide copy-on-write (COW) replacement methods (`replace` and `with_*`) to facilitate safe, side-effect-free transformations.

#### What this stage explicitly must NOT do
* The Green CST **must not** contain any domain-specific semantics. It does not understand GitHub Actions workflows, jobs, step configurations, run scripts, or environment variables.
* It **must not** throw semantic validation errors (e.g., missing mandatory GHA keys).

#### Major Classes
* [SourceSpan](file:///c:/CST/src/cst_auto_remediator/yaml_cst/nodes.py#L16): Immutable dataclass holding `line: int` and `column: int`.
* [YamlNode](file:///c:/CST/src/cst_auto_remediator/yaml_cst/nodes.py#L22): Base immutable syntax node class, defining a random `node_id` and an optional `SourceSpan`.
* [YamlScalar](file:///c:/CST/src/cst_auto_remediator/yaml_cst/nodes.py#L84): Subclass representing scalar values (strings, integers, booleans, nulls) along with their quoting `style` (PLAIN, SINGLE_QUOTED, DOUBLE_QUOTED, folded, literal) and `raw_text`.
* [YamlKeyValue](file:///c:/CST/src/cst_auto_remediator/yaml_cst/nodes.py#L101): Subclass representing a key-value pair entry in a mapping.
* [YamlMapping](file:///c:/CST/src/cst_auto_remediator/yaml_cst/nodes.py#L116): Subclass representing a collection of `YamlKeyValue` entries.
* [YamlSequence](file:///c:/CST/src/cst_auto_remediator/yaml_cst/nodes.py#L136): Subclass representing a list of `YamlNode` items.
* [YamlDocument](file:///c:/CST/src/cst_auto_remediator/yaml_cst/nodes.py#L152): Root class representing the entire parsed YAML file wrapper, mapping the root node and metadata dict.

#### Major Functions
* [build_cst(parsed_doc: Any, metadata: dict[str, Any]) -> YamlDocument](file:///c:/CST/src/cst_auto_remediator/yaml_cst/builder.py#L31): Initiates the conversion of the ruamel document into the `YamlDocument` Green CST.
* [_build_node(val: Any, span: SourceSpan | None = None) -> YamlNode](file:///c:/CST/src/cst_auto_remediator/yaml_cst/builder.py#L43): Recursively converts ruamel values into corresponding `YamlNode` objects.
* [structurally_equal(self, other: YamlNode) -> bool](file:///c:/CST/src/cst_auto_remediator/yaml_cst/nodes.py#L33): Compares syntax nodes structurally, ignoring generated `node_id`s.
* Node replacement wrappers: `with_value()`, `with_style()`, `with_span()`, `with_key()`, `with_entries()`, `with_entry()`, `with_items()`, `with_item()`, `with_root()`, `with_metadata()`.

#### Internal Flow
1. `build_cst` invokes `_build_node` on the root object.
2. `_build_node` checks the runtime type of the input value:
   * **If `CommentedMap`:** Inspects its internal line-column tracker (`lc`). For each key-value pair, extracts the key span and value span, builds a `YamlScalar` key, recursively processes the value to get a value `YamlNode`, packages them into a `YamlKeyValue` node, and wraps the entries in a `YamlMapping`.
   * **If `CommentedSeq`:** Inspects its `lc` tracker. For each element, extracts its position, recursively processes the item, and wraps the items in a `YamlSequence`.
   * **If a Scalar:** Determines the quote type by checking the class (e.g., `SingleQuotedScalarString` -> `SINGLE_QUOTED`, `FoldedScalarString` -> `FOLDED`, `LiteralScalarString` -> `LITERAL`). Extracts the raw text and values, returning a `YamlScalar`.
3. Returns a `YamlDocument` holding the root node and Stage 1 metadata.

#### Architectural Notes
The "Green CST" is completely separate from GitHub Actions concepts. It represents pure, structural YAML syntax, making it highly reusable. The tree is immutable, meaning any modification must occur via Copy-on-Write (COW). When a child node changes, it returns a new child instance, and this change propagates up the tree to the root. Unchanged siblings are shared structurally in memory, maximizing performance and reducing memory allocations.

---

### Stage 3: GitHub Actions Semantic Layer (Red/Semantic Modeling)

#### Purpose
Stage 3 overlays domain-specific semantics on top of the generic Green CST. It maps generic mapping and sequence structures to structured GHA concepts: workflows, jobs, steps, run commands, and environment bindings. It parses expressions inside commands and performs balanced brace scanning. This stage also generates semantic diagnostic logs if it detects structural schema errors.

#### Input
* A `YamlDocument` representation of the Green CST.

#### Output
* A `SemanticBuildResult` object containing:
  * A `Workflow` root node (which wraps and maps GHA semantics).
  * A list of `Diagnostic` objects representing structural errors or warning logs.

#### Responsibilities
* Reconstruct GitHub Actions models (`Workflow`, `Job`, `Step`, `RunCommand`, `EnvBinding`) by traversing the Green CST.
* Wrap underlying Green CST nodes directly instead of copy-converting them, maintaining a link between syntax and semantics.
* Parse the contents of `run:` commands and `env:` bindings to isolate and extract `${{ ... }}` expressions.
* Perform balanced brace scanning to support nested delimiters, double-wrapped expressions, and quotes.
* Record the precise character offset bounds (`start_offset`, `end_offset`) of extracted expressions relative to their parent run strings.
* Collect and expose schema violations using stable, standardized diagnostic error codes (`GHA001` through `GHA010`).

#### What this stage explicitly must NOT do
* The semantic layer **must not** make security decisions. It does not classify expressions as trusted or untrusted, and it does not flag injection risks.
* It **must not** modify syntax trees or perform any mutations.

#### Major Classes
* [Diagnostic](file:///c:/CST/src/cst_auto_remediator/gha_semantic/nodes.py#L15): Immutable model representing an error or warning, containing a code, error message, span, and severity level (`error` or `warning`).
* [ExpressionSite](file:///c:/CST/src/cst_auto_remediator/gha_semantic/nodes.py#L23): Represents a parsed `${{ ... }}` expression site, holding the target CST `YamlScalar` node, the raw text, the inner expression body, and character offset markers.
* [EnvBinding](file:///c:/CST/src/cst_auto_remediator/gha_semantic/nodes.py#L32): Models an environment variable mapping inside `env:`, linking to the key-value CST node and nested expression sites.
* [RunCommand](file:///c:/CST/src/cst_auto_remediator/gha_semantic/nodes.py#L40): Models the step `run:` command, wrapping the corresponding CST key-value node, scalar command string, and expression sites.
* [Step](file:///c:/CST/src/cst_auto_remediator/gha_semantic/nodes.py#L47): Models a step within a job, tracking the step index, step ID, run command, and env bindings.
* [Job](file:///c:/CST/src/cst_auto_remediator/gha_semantic/nodes.py#L56): Models a job in the workflow, tracking the job ID and step list.
* [Workflow](file:///c:/CST/src/cst_auto_remediator/gha_semantic/nodes.py#L63): Models the root GHA workflow, mapping job IDs to job configurations.
* [SemanticBuildResult](file:///c:/CST/src/cst_auto_remediator/gha_semantic/nodes.py#L69): Wrapper packaging the resolved semantic workflow hierarchy and diagnostic lists.

#### Major Functions
* [build_semantic_model(cst: YamlDocument) -> SemanticBuildResult](file:///c:/CST/src/cst_auto_remediator/gha_semantic/builder.py#L32): Evaluates the Green CST mapping and returns the semantic model and diagnostics.
* [extract_expression_sites(scalar: YamlScalar) -> list[ExpressionSite]](file:///c:/CST/src/cst_auto_remediator/gha_semantic/scanner.py#L11): Scans scalar strings for expressions, tracking depth to support nested braces.

#### Standardized Diagnostic Codes
Stage 3 enforces the GHA schema using ten diagnostic validation rules:

| Code | Level | Description / Trigger Condition |
| :--- | :--- | :--- |
| **`GHA001`** | Error | Workflow root must be a YAML mapping. |
| **`GHA002`** | Error | Missing required `jobs` section in the root mapping. |
| **`GHA003`** | Error | The `jobs` section exists but is not a mapping. |
| **`GHA004`** | Error | A specific job definition (e.g., `jobs.build`) is not a mapping. |
| **`GHA005`** | Error | The `steps` section of a job is not a YAML sequence. |
| **`GHA006`** | Error | An individual step entry is not a mapping. |
| **`GHA007`** | Error | The `id` key of a step is not a YAML scalar. |
| **`GHA008`** | Error | The `run` key of a step is not a YAML scalar (e.g., is a map or sequence). |
| **`GHA009`** | Error | The `env` block of a step is not a YAML mapping. |
| **`GHA010`** | Error | An entry inside the `env` block is not a scalar-to-scalar binding. |

#### Internal Flow
1. Check if the CST root is a `YamlMapping`. If not, emit `GHA001` and abort.
2. Locate the `jobs` entry. If missing, emit `GHA002`; if it is not a mapping, emit `GHA003`.
3. Traverse job mapping entries. If a job entry is not a mapping, emit `GHA004`.
4. For each job, find the `steps` sequence. If it is not a sequence, emit `GHA005`.
5. Iterate through step sequence items. If any step is not a mapping, emit `GHA006`.
6. For each step mapping, parse its children:
   * Parse step `id` (must be scalar, else emit `GHA007`).
   * Parse step `run` command (must be scalar, else emit `GHA008`). Extract run expression sites via `extract_expression_sites`.
   * Parse step `env` mapping (must be mapping, else emit `GHA009`). For each key-value pair, assert that both are scalars (else emit `GHA010`). Extract expression sites from the env values.
7. Construct the `Workflow` object hierarchy wrapping the corresponding Green CST nodes, and return it within the `SemanticBuildResult`.

#### Architectural Notes
Rather than discarding the CST to build an independent semantic AST, Stage 3 wraps the generic Green nodes. This keeps the semantic tree lightweight and maintains a link to the original syntax representation. This link is critical for Stages 6 and 8, allowing the transformer to locate target nodes in the CST and rewrite them without losing formatting.

---

### Stage 4: Metadata Providers (Contextual Query System)

#### Purpose
Stage 4 computes contextual metadata over the semantic workflow tree. It resolves node scopes, shell properties, physical position paths, and duplicate expressions. Metadata is kept decoupled from the main semantic tree to prevent node objects from becoming bloated. The metadata engine resolves dependencies automatically and caches resolved metadata maps to optimize performance.

#### Input
* The `Workflow` semantic hierarchy from Stage 3.

#### Output
* Metadata maps cached on a central `MetadataWrapper` instance, queried per semantic node.

#### Responsibilities
* Resolve contextual properties (positions, variables, shells, duplicates) for all semantic nodes.
* Enforce the **"Facts, Not Decisions"** invariant: gather objective facts about the structure and context, leaving security classifications and remediation decisions to later stages.
* Expose a generic `MetadataProvider` base class and a central `MetadataWrapper` caching registry.
* Resolve provider dependency chains automatically based on declared dependencies.
* Package computed metadata into immutable metadata models.

#### What this stage explicitly must NOT do
* Metadata providers **must not** categorize inputs as trusted or untrusted.
* They **must not** identify security vulnerabilities, select variables for remediation, or plan modifications.

#### Major Classes
* [MetadataWrapper](file:///c:/CST/src/cst_auto_remediator/gha_metadata/engine.py#L16): The central manager that resolves provider dependency chains and caches metadata results.
* [MetadataProvider](file:///c:/CST/src/cst_auto_remediator/gha_metadata/engine.py#L50): Abstract base class for concrete providers, defining dependency declarations and resolve rules.
* [MetadataBundle](file:///c:/CST/src/cst_auto_remediator/gha_metadata/nodes.py#L62): Data package that bundles position, scope, shell, and expression metadata for a node.
* [PositionMetadata](file:///c:/CST/src/cst_auto_remediator/gha_metadata/nodes.py#L28): Tracks the target's node path (e.g., `jobs.build.steps.0.run`), path segments, parent semantic node reference, step index, and job ID.
* [ScopeMetadata](file:///c:/CST/src/cst_auto_remediator/gha_metadata/nodes.py#L38): Tracks environment variable scopes, mapping variables defined at the workflow, job, and step levels.
* [ShellMetadata](file:///c:/CST/src/cst_auto_remediator/gha_metadata/nodes.py#L45): Tracks the shell type (declared shell, effective shell, runner default) and its capabilities.
* [ShellCapabilities](file:///c:/CST/src/cst_auto_remediator/gha_metadata/nodes.py#L18): Tracks specific shell capabilities (e.g., variable syntax, quoting support).
* [ExpressionMetadata](file:///c:/CST/src/cst_auto_remediator/gha_metadata/nodes.py#L54): Tracks duplicate status, duplicate index, and expression ordering within the workflow.

#### Major Functions
* `MetadataWrapper.get(provider_class, node) -> Any`: Resolves and returns the cached metadata for a node.
* `MetadataWrapper.get_bundle(node) -> MetadataBundle`: Aggregates and returns the full metadata bundle for a node.

#### Concrete Metadata Providers
* **`PositionProvider`:** Traverses the workflow hierarchy to map physical path addresses (e.g., `jobs.build.steps.0.run.exprs.0`) and parent-child relationships.
* **`ScopeProvider`:** Maps variable scopes down the tree, resolving variable inheritance and overrides at the workflow, job, and step levels.
* **`ShellProvider`:** Determines the active shell for each step based on explicit declarations, job defaults, or runner fallbacks (e.g., defaulting to `bash` on Linux or `pwsh` on Windows).
* **`ExpressionProvider`:** Tracks expression execution order and identifies duplicate expressions.

#### Internal Flow
1. The client requests metadata for a node: `wrapper.get(ShellProvider, step)`.
2. `MetadataWrapper` checks if the provider is already cached:
   * **If cached:** Returns the metadata immediately.
   * **If not cached:** Recursively resolves any dependencies declared by the provider (e.g., `ShellProvider` requires `PositionProvider` and `ScopeProvider`).
3. Instantiates the provider and runs its `resolve(workflow)` method.
4. The provider traverses the semantic model and returns a map of Python object IDs (`id(node)`) to their computed metadata.
5. `MetadataWrapper` caches the resolved map and returns the requested node's metadata.

#### Architectural Notes
Decoupling metadata from semantic nodes keeps the semantic model clean and lightweight. It avoids polluting semantic nodes with transient, context-dependent properties like line numbers or shell capabilities. The central wrapper registry resolves metadata lazily and caches the results, ensuring that metadata is only computed when requested.

---

## 4. Complete Execution Walkthrough

Let us trace the execution of the compiler front-end (Stages 1–4) on a sample YAML file:

```yaml
name: Demo

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
      - run: echo "${{ github.event.issue.title }}"
```

### Stage 1 Ingest and Parser Output
The parser decodes the byte stream, validates its constraints, and processes the text using `ruamel.yaml` in round-trip mode.

#### Ingest Metadata Dict:
```python
{
    "size": 95,
    "sha256": "4b54e7d7a4b80b06b74681fb7f722a5bb01ff0f2da3e8c97cfc1d102e3bdf8a1",
    "encoding": "utf-8",
    "line_ending": "\n"
}
```

#### Ruamel Intermediate Representation:
A `CommentedMap` structure loaded in memory, preserving comments and formatting information:
```python
CommentedMap([
    ('name', 'Demo'),
    ('jobs', CommentedMap([
        ('build', CommentedMap([
            ('runs-on', 'ubuntu-latest'),
            ('steps', CommentedSeq([
                CommentedMap([('run', 'echo "${{ github.event.issue.title }}"')])
            ]))
        ]))
    ]))
])
```

---

### Stage 2 Green CST Output
Stage 2 converts the ruamel structures into a tree of immutable generic `YamlNode` objects.

```yaml
YamlDocument(
  node_id="a8f90c88bc3b4e...",
  span=SourceSpan(line=0, column=0),
  metadata={"size": 95, ...},
  root=YamlMapping(
    node_id="c7d91e88bc3b4f...",
    span=SourceSpan(line=0, column=0),
    entries=[
      # name: Demo
      YamlKeyValue(
        node_id="e321a088bc3b4a...",
        span=SourceSpan(line=0, column=0),
        key=YamlScalar(node_id="f88120...", span=SourceSpan(line=0, column=0), value="name", raw_text="name", style="PLAIN"),
        value=YamlScalar(node_id="b21102...", span=SourceSpan(line=0, column=5), value="Demo", raw_text="Demo", style="PLAIN")
      ),
      # jobs: ...
      YamlKeyValue(
        node_id="d120a188bc3b4b...",
        span=SourceSpan(line=2, column=0),
        key=YamlScalar(node_id="e112a3...", span=SourceSpan(line=2, column=0), value="jobs", raw_text="jobs", style="PLAIN"),
        value=YamlMapping(
          node_id="c331a488bc3b4c...",
          span=SourceSpan(line=3, column=2),
          entries=[
            # build: ...
            YamlKeyValue(
              node_id="a982a588bc3b4d...",
              span=SourceSpan(line=3, column=2),
              key=YamlScalar(node_id="b55123...", span=SourceSpan(line=3, column=2), value="build", raw_text="build", style="PLAIN"),
              value=YamlMapping(
                node_id="f771a788bc3b4e...",
                span=SourceSpan(line=4, column=4),
                entries=[
                  # runs-on: ubuntu-latest
                  YamlKeyValue(
                    node_id="e223a888bc3b4f...",
                    span=SourceSpan(line=4, column=4),
                    key=YamlScalar(node_id="a11223...", span=SourceSpan(line=4, column=4), value="runs-on", raw_text="runs-on", style="PLAIN"),
                    value=YamlScalar(node_id="c33445...", span=SourceSpan(line=4, column=13), value="ubuntu-latest", raw_text="ubuntu-latest", style="PLAIN")
                  ),
                  # steps: ...
                  YamlKeyValue(
                    node_id="d887b188bc3b5a...",
                    span=SourceSpan(line=6, column=4),
                    key=YamlScalar(node_id="e66332...", span=SourceSpan(line=6, column=4), value="steps", raw_text="steps", style="PLAIN"),
                    value=YamlSequence(
                      node_id="b998b288bc3b5b...",
                      span=SourceSpan(line=7, column=6),
                      items=[
                        # - run: echo "${{ github.event.issue.title }}"
                        YamlMapping(
                          node_id="a112c388bc3b5c...",
                          span=SourceSpan(line=7, column=8),
                          entries=[
                            YamlKeyValue(
                              node_id="f223c488bc3b5d...",
                              span=SourceSpan(line=7, column=8),
                              key=YamlScalar(node_id="d44556...", span=SourceSpan(line=7, column=8), value="run", raw_text="run", style="PLAIN"),
                              value=YamlScalar(node_id="e55667...", span=SourceSpan(line=7, column=13), value='echo "${{ github.event.issue.title }}"', raw_text='echo "${{ github.event.issue.title }}"', style="PLAIN")
                            )
                          ]
                        )
                      ]
                    )
                  )
                ]
              )
            )
          ]
        )
      )
    ]
  )
)
```

---

### Stage 3 Semantic Layer Output
Stage 3 parses the generic syntax tree into high-level GHA concepts.

#### Diagnostics List:
```python
[]  # Structural schema checks pass; no diagnostics are generated
```

#### Workflow Semantic Hierarchy:
```python
Workflow(
  node=YamlDocument(node_id="a8f90c88bc3b4e..."),
  jobs={
    "build": Job(
      node=YamlMapping(node_id="f771a788bc3b4e..."),
      job_id="build",
      steps=[
        Step(
          node=YamlMapping(node_id="a112c388bc3b5c..."),
          step_index=0,
          step_id=None,
          run_command=RunCommand(
            node=YamlKeyValue(node_id="f223c488bc3b5d..."),
            command=YamlScalar(node_id="e55667...", value='echo "${{ github.event.issue.title }}"'),
            expression_sites=[
              ExpressionSite(
                node=YamlScalar(node_id="e55667..."),
                expression_text="${{ github.event.issue.title }}",
                expression_body="github.event.issue.title",
                start_offset=12,  # Character index of "${{" within 'echo "${{...}}"'
                end_offset=43     # Character index of "}" within 'echo "${{...}}"'
              )
            ]
          ),
          env_bindings=[]
        )
      ]
    )
  }
)
```

---

### Stage 4 Metadata Output
Stage 4 maps semantic node references to contextual metadata.

#### 1. Position Metadata (`PositionProvider`)
* **Workflow Node Position:**
  ```python
  PositionMetadata(
      span=SourceSpan(line=0, column=0),
      parent=None,
      node_path="workflow",
      path_segments=("workflow",),
      step_index=None,
      job_id=None
  )
  ```
* **Job Node Position:**
  ```python
  PositionMetadata(
      span=SourceSpan(line=3, column=2),
      parent=Workflow(...),
      node_path="jobs.build",
      path_segments=("jobs", "build"),
      step_index=None,
      job_id="build"
  )
  ```
* **Step Node Position:**
  ```python
  PositionMetadata(
      span=SourceSpan(line=7, column=8),
      parent=Job(...),
      node_path="jobs.build.steps.0",
      path_segments=("jobs", "build", "steps", "0"),
      step_index=0,
      job_id="build"
  )
  ```
* **RunCommand Node Position:**
  ```python
  PositionMetadata(
      span=SourceSpan(line=7, column=8),
      parent=Step(...),
      node_path="jobs.build.steps.0.run",
      path_segments=("jobs", "build", "steps", "0", "run"),
      step_index=0,
      job_id="build"
  )
  ```
* **ExpressionSite Node Position:**
  ```python
  PositionMetadata(
      span=SourceSpan(line=7, column=13),
      parent=RunCommand(...),
      node_path="jobs.build.steps.0.run.exprs.0",
      path_segments=("jobs", "build", "steps", "0", "run", "exprs", "0"),
      step_index=0,
      job_id="build"
  )
  ```

#### 2. Scope Metadata (`ScopeProvider`)
* **Workflow Scope:** `ScopeMetadata(scope_type="workflow", env={}, parent_scope=None)`
* **Job Scope:** `ScopeMetadata(scope_type="job", env={}, parent_scope=WorkflowScope)`
* **Step Scope:** `ScopeMetadata(scope_type="step", env={}, parent_scope=JobScope)`

#### 3. Shell Metadata (`ShellProvider`)
* **Step Shell:**
  ```python
  ShellMetadata(
      declared_shell=None,
      effective_shell="bash",  # Default shell on Linux runner
      runner_default="bash",
      is_default=True,
      capabilities=ShellCapabilities(
          supports_env_assignment=True,
          supports_export=True,
          supports_double_quotes=True,
          supports_single_quotes=True,
          supports_command_substitution=True,
          supports_variable_reference=True
      )
  )
  ```

#### 4. Expression Metadata (`ExpressionProvider`)
* **Expression Site:**
  ```python
  ExpressionMetadata(
      stable_id="jobs.build.steps.0.run.exprs.0",
      expression_order=0,
      is_duplicate=False,
      duplicate_index=None
  )
  ```

---

## 5. Dependency Graph

### Core Phases Dependency Graph
The physical import structure is strictly linear, ensuring that parsing layers remain isolated from semantic and query layers.

```
       +---------------------------------------------+
       |                  Stage 1                    |
       |      cst_auto_remediator.yaml_cst.parser    |
       +---------------------------------------------+
                              │
                              ▼
       +---------------------------------------------+
       |                  Stage 2                    |
       |  cst_auto_remediator.yaml_cst.{nodes,build} |
       +---------------------------------------------+
                              │
                              ▼
       +---------------------------------------------+
       |                  Stage 3                    |
       | cst_auto_remediator.gha_semantic.{nodes...} |
       +---------------------------------------------+
                              │
                              ▼
       +---------------------------------------------+
       |                  Stage 4                    |
       | cst_auto_remediator.gha_metadata.{nodes...} |
       +---------------------------------------------+
```

---

### Metadata Provider Dependency Graph
Providers are resolved lazily on-demand. When resolving a metadata request, the engine checks and executes declared dependency providers first.

```
                       PositionProvider               ScopeProvider
                              │                             │
                              ├──────────────┬──────────────┘
                              │              │
                              ▼              ▼
                       ShellProvider   ExpressionProvider
```

---

## 6. Compiler Architecture

The design of the GHA CST Auto-Remediator is inspired by modern compiler and refactoring front-ends, sharing key architectural choices with frameworks like **Roslyn** (.NET), **LibCST** (Python), and **SwiftSyntax** (Swift).

```
  Compiler System             Roslyn / SwiftSyntax / LibCST Equivalent
  ──────────────────────────────────────────────────────────────────────────
  Stage 2 Green CST           Green Trees (Immutable, position-agnostic syntax)
  Stage 3 Semantic (Red)      Red Trees (Parented, context-aware semantic wrapper)
  Stage 4 Engine / Wrapper    SemanticModel (Query interface for scopes/types)
  Stage 4 Providers           Compilation Query Passes (Lazy, demand-driven)
```

### Key Architectural Concepts

#### 1. Green / Red Tree Separation
* **Green CST (Stage 2):** Pure, immutable syntax nodes that only track their value and children. They contain no reference to parent nodes or semantic rules, maximizing structural sharing and memory efficiency.
* **Red Tree (Stage 3):** A semantic wrapper layer overlaying GHA concepts onto green nodes. It allows code generators and static analyzers to query variables and scopes contextually.

#### 2. Lazy Demand-Driven Evaluation
Context-dependent properties like line numbers, variable scopes, and shell capabilities are resolved lazily on-demand rather than being computed during parsing. The `MetadataWrapper` serves as a query database that resolves metadata on-demand and caches the results, avoiding unnecessary computation for unused nodes.

#### 3. Separation of Concerns
Each phase in the compiler pipeline is isolated:
* Generic YAML parsing knows nothing about GitHub Actions.
* Semantic models know nothing about security policies or taint tracking.
* Metadata providers compile structural facts without making remediation decisions.

This strict separation ensures the codebase remains modular, testable, and maintainable.

---

## 7. Repository Layout

```
CST_Auto_Remidiator/
│
├── pyproject.toml              # Project metadata, dependencies, and testing configurations
├── explanation.md              # Project status document, acting as the primary developer source of truth
│
├── src/cst_auto_remediator/    # Core compiler codebase
│   ├── __init__.py             # Public API entry point exports
│   ├── models.py               # Shared data types, enums, and dataclasses
│   ├── ingest.py               # Ingestion orchestrator for Stage 1 validation
│   ├── classify.py             # Security classification rules for Stage 5 (Taint analysis)
│   ├── traverse.py             # AST search logic for Stage 5 traversal
│   ├── validate.py             # Validation checks and collision rules for Stage 5
│   ├── mutate.py               # Tree refactoring and serialization logic for Stages 6/8
│   ├── pipeline.py             # End-to-end orchestration pipeline
│   │
│   ├── yaml_cst/               # Stage 1 & Stage 2: Generic YAML Parser and Green CST
│   │   ├── __init__.py
│   │   ├── nodes.py            # Generic frozen YAML node dataclasses
│   │   ├── builder.py          # Green CST construction logic mapping ruamel objects
│   │   └── parser.py           # Generic YAML validation, bomb protection, and parsing
│   │
│   ├── gha_semantic/           # Stage 3: GitHub Actions Semantic Layer (Red Tree)
│   │   ├── __init__.py
│   │   ├── nodes.py            # GHA concept nodes (Workflows, Jobs, Steps)
│   │   ├── scanner.py          # Balanced-brace scanner extracting ${{ }} expressions
│   │   └── builder.py          # GHA semantic tree builder and diagnostics
│   │
│   └── gha_metadata/           # Stage 4: Metadata engine and providers
│       ├── __init__.py
│       ├── nodes.py            # Metadata models (Shell, Scope, Position, Bundle)
│       ├── engine.py           # Lazy dependency resolver and MetadataWrapper cache
│       └── providers.py        # Concrete providers (Position, Scope, Shell, Expression)
│
└── tests/                      # Pytest verification suites
    ├── test_parser.py          # Ingestion limits, encodings, and alias bomb tests
    ├── test_nodes.py           # Basic green node tests
    ├── test_stage2_comprehensive.py  # Comprehensive Green CST validation tests
    ├── test_stage3_comprehensive.py  # GHA semantic layer and diagnostic checks
    ├── test_stage4_comprehensive.py  # Cache, shell capability, and override scope tests
    └── test_pipeline_integration.py  # E2E pipeline integration tests
```

---

## 8. Design Decisions

### 1. Immutable Trees
All CST, semantic, and metadata nodes are declared as frozen dataclasses (`@dataclass(frozen=True)`). Immutability prevents state bugs, simplifies equality comparisons, and allows nodes to be shared structurally across multiple tree references without side effects.

### 2. Copy-on-Write (COW) Updates
Since the syntax tree is immutable, mutations are performed via Copy-on-Write. Sibling nodes that are not modified are shared structurally in memory, minimizing allocation overhead during tree refactorings.

### 3. Deterministic Node Paths as Stable IDs
Stage 4 maps expressions to stable, deterministic string IDs (e.g., `jobs.build.steps.0.run.exprs.0`) derived from their physical location in the tree. This ensures ID stability across compilation runs, which is critical for generating reliable audit reports.

### 4. External Metadata Caching
Computed facts like variable scopes or shell capabilities are stored in a centralized cache database rather than being stored as attributes on the nodes themselves. This keeps syntax and semantic nodes lightweight and easy to maintain.

### 5. Semantic Wrappers Over Copies
Semantic nodes in Stage 3 wrap generic Green CST nodes rather than copying their values. This preserves formatting and styling information, allowing downstream stages to perform lossless code mutations.

---

## 9. Testing Summary

The project maintains a comprehensive test suite (120+ tests) verifying code safety boundaries, AST transformations, and E2E compiler execution:

### Ingestion and Parsing Tests (`test_parser.py`)
* Validates file size limits (rejects files > 2 MB with `FileTooLargeError`).
* Rejects invalid UTF-8 byte streams.
* Detects and blocks Billion Laughs and cyclical YAML alias bomb attacks.
* Verifies that newlines and quotes are preserved.

### Green CST Validation (`test_stage2_comprehensive.py`)
* Verifies node hierarchy construction from raw YAML inputs.
* Asserves node immutability (checks that frozen structures prevent direct attribute mutation).
* Validates that Copy-on-Write transformations propagate updates up the tree while preserving unmodified sibling references.
* Verifies that generic scalars preserve quoting styles and values.
* Tests structural equality comparisons across trees.

### Semantic Layer Checks (`test_stage3_comprehensive.py`)
* Verifies structural schema checks and validates diagnostics for codes `GHA001` through `GHA010`.
* Tests balanced brace scanning for nested expressions.
* Verifies starting and ending character offsets, including offset tracking for UTF-8 multi-byte emoji characters.
* Validates workflow structures with empty steps.

### Metadata Providers Verification (`test_stage4_comprehensive.py`)
* Verifies position path tracking and parent-child metadata mappings.
* Validates variable scope resolution, checking that environment variables inherit and override correctly down the tree.
* Resolves active shell environments, verifying fallback logic for runners (e.g., Windows runner defaulting to `pwsh`).
* Verifies lazy dependency resolution and caching on the `MetadataWrapper` registry.

### E2E Integration Tests (`test_pipeline_integration.py`)
* Runs the end-to-end compiler pipeline against production workflows, verifying that all four stages work together smoothly without diagnostics.

---

## 10. Current Compiler State

| Stage | Name | Status | Purpose / Deliverable |
| :--- | :--- | :--- | :--- |
| **Stage 1** | Ingest & Parser | **Complete** | Validates byte constraints, encoding limits, and generates lossless ruamel mapping trees. |
| **Stage 2** | Green CST | **Complete** | Maps generic YAML structures to strongly typed, immutable Green syntax nodes with source spans. |
| **Stage 3** | Semantic Layer | **Complete** | Translates generic trees into GHA-specific concept hierarchies and collects diagnostic codes `GHA001`-`GHA010`. |
| **Stage 4** | Metadata Providers | **Complete** | Resolves contextual positions, scopes, shells, and expression tracking facts using a lazy query engine. |
| **Stage 5** | Security Analysis | *Planned* | Classifies expression taint variables and plans target variable transformations. |
| **Stage 6** | Transformation | *Planned* | Generates environment variable bindings and replaces vulnerable expressions with shell variables. |
| **Stage 7** | Verification | *Planned* | Post-mutation validation to ensure that no untrusted expressions remain. |
| **Stage 8** | Lossless Serializer | *Planned* | Emits the remediated AST back to disk, preserving newlines, styling, and formatting byte-for-byte. |

---

## 11. Future Roadmap

### Stage 5: Security Analysis (Planned)
* **Goal:** Analyze GHA expression sites to evaluate safety levels and identify command injection points.
* **Details:** Evaluates expression scopes and context (e.g., distinguishing untrusted sources like `github.event.issue.title` from trusted sources like `github.sha`).

### Stage 6: Transformation (Planned)
* **Goal:** Perform tree-to-tree refactoring to remediate vulnerabilities.
* **Details:** Rewrites the tree using Copy-on-Write updates, binding vulnerable expressions to environment variables and replacing inline commands with safe shell variable references (e.g., replacing `${{ github.event.issue.title }}` with `$ISSUE_TITLE`).

### Stage 7: Verification (Planned)
* **Goal:** Validate the modified workflow to ensure it is safe to write back to disk.
* **Details:** Performs a final check on the mutated AST to verify that all untrusted expressions have been successfully removed from executable steps.

### Stage 8: Lossless Serializer (Planned)
* **Goal:** Serialize the AST back to disk while preserving formatting.
* **Details:** Writes the mutated syntax tree back to the filesystem, preserving original formatting, newlines, comments, and quoting styles outside of the modified regions.

---

## 12. End-to-End Data Flow

The following diagram illustrates the lifecycle of a workflow file as it moves through the completed compiler front-end and planned transformation phases:

```
  vulnerable_workflow.yml
            │
            │  [Stage 1: Ingest Parser]
            ▼
    ruamel CommentedMap (Lossless Generic YAML representation)
            │
            │  [Stage 2: CST Builder]
            ▼
     YamlDocument (Immutable Green CST, Generic YAML Syntax Tree)
            │
            │  [Stage 3: GHA Semantic Builder]
            ▼
       Workflow (Red/Semantic model hierarchy wrapping CST nodes)
            │
            │  [Stage 4: Metadata Engine]
            ▼
     Metadata Bundle (Contextual Shells, Scopes, Paths, and IDs)
            │
  ==========│=====================================================
            │  COMPILER FRONT-END COMPLETED
  ==========│=====================================================
            │  [Stage 5: Security Analysis] (Planned)
            ▼
    Remediation Plan (Planned Patches, Variable Binding selections)
            │
            │  [Stage 6: AST-to-AST Transformer] (Planned)
            ▼
     Mutated AST (Surgically rewritten Red/CST nodes)
            │
            │  [Stage 7: Post-Mutation Verifier] (Planned)
            ▼
     Verified AST (Confirmed free of untrusted inline expressions)
            │
            │  [Stage 8: Serializer] (Planned)
            ▼
  remediated_workflow.yml (Lossless, byte-preserved safe YAML output)
```
