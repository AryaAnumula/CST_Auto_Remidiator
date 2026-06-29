"""Unit tests for Stage 2 YAML CST node models and builder."""

import pytest
from cst_auto_remediator.yaml_cst.parser import parse_yaml
from cst_auto_remediator.yaml_cst.builder import build_cst
from cst_auto_remediator.yaml_cst.nodes import (
    YamlDocument,
    YamlMapping,
    YamlSequence,
    YamlKeyValue,
    YamlScalar,
    SourceSpan,
)


def test_cst_hierarchy_and_traversal() -> None:
    content = (
        b"name: test-workflow\n"
        b"jobs:\n"
        b"  build:\n"
        b"    runs-on: ubuntu-latest\n"
        b"    steps:\n"
        b"      - name: setup\n"
        b"        run: echo\n"
    )
    doc_tree, meta = parse_yaml(content)
    cst = build_cst(doc_tree, meta)

    # 1. Correct node hierarchy & types
    assert isinstance(cst, YamlDocument)
    assert isinstance(cst.root, YamlMapping)
    assert len(cst.root.entries) == 2

    # Traversal mapping entries
    name_entry = cst.root.entries[0]
    assert isinstance(name_entry, YamlKeyValue)
    assert isinstance(name_entry.key, YamlScalar)
    assert name_entry.key.value == "name"
    assert isinstance(name_entry.value, YamlScalar)
    assert name_entry.value.value == "test-workflow"
    assert name_entry.value.style == "PLAIN"

    jobs_entry = cst.root.entries[1]
    assert jobs_entry.key.value == "jobs"
    assert isinstance(jobs_entry.value, YamlMapping)

    # 2. Source ranges (where available)
    assert name_entry.key.span is not None
    assert name_entry.key.span.line == 0
    assert name_entry.key.span.column == 0
    assert jobs_entry.key.span.line == 1
    assert jobs_entry.key.span.column == 0

    # Step sequence traversal
    job_build = jobs_entry.value.entries[0].value
    assert isinstance(job_build, YamlMapping)
    steps_entry = [e for e in job_build.entries if e.key.value == "steps"][0]
    assert isinstance(steps_entry.value, YamlSequence)
    assert len(steps_entry.value.items) == 1

    step_item = steps_entry.value.items[0]
    assert isinstance(step_item, YamlMapping)
    assert step_item.span is not None
    assert step_item.span.line == 5
    assert step_item.span.column == 8


def test_scalar_preservation_and_styles() -> None:
    content = (
        b"single: 'value'\n"
        b"double: \"value\"\n"
        b"plain: value\n"
    )
    doc_tree, meta = parse_yaml(content)
    cst = build_cst(doc_tree, meta)

    entries = {e.key.value: e.value for e in cst.root.entries}

    assert entries["single"].style == "SINGLE_QUOTED"
    assert entries["single"].value == "value"
    assert entries["single"].raw_text == "'value'"

    assert entries["double"].style == "DOUBLE_QUOTED"
    assert entries["double"].value == "value"
    assert entries["double"].raw_text == '"value"'

    assert entries["plain"].style == "PLAIN"
    assert entries["plain"].value == "value"
    assert entries["plain"].raw_text == "value"


def test_copy_on_write_replacement() -> None:
    content = (
        b"name: old-name\n"
        b"steps:\n"
        b"  - run: echo old\n"
        b"  - run: echo keep\n"
    )
    doc_tree, meta = parse_yaml(content)
    cst = build_cst(doc_tree, meta)

    # Verify copy-on-write immutability
    original_root = cst.root

    # Rebuild scalar value CoW
    new_scalar = YamlScalar(value="new-name", raw_text="new-name", style="PLAIN")
    mutated_mapping = original_root.with_entry("name", new_scalar)

    # Assert original remains unchanged
    assert original_root.entries[0].value.value == "old-name"
    assert mutated_mapping.entries[0].value.value == "new-name"

    # Assert sibling elements are shared (structural sharing check)
    assert original_root.entries[1] is mutated_mapping.entries[1]

    # Sequence item CoW replacement
    steps_seq = original_root.entries[1].value
    assert isinstance(steps_seq, YamlSequence)

    # Construct mutated mapping for item 0
    new_run_scalar = YamlScalar(value="echo new", raw_text="echo new", style="PLAIN")
    new_step_mapping = steps_seq.items[0].with_entry("run", new_run_scalar)

    mutated_seq = steps_seq.with_item(0, new_step_mapping)

    # Assert original unchanged
    assert steps_seq.items[0].entries[0].value.value == "echo old"
    assert mutated_seq.items[0].entries[0].value.value == "echo new"
    # Sibling index 1 is shared
    assert steps_seq.items[1] is mutated_seq.items[1]
