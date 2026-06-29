"""
Comprehensive unit tests for Stage 2: Green CST Construction.
Verifies all Stage 2 requirements including node hierarchy, immutability,
parent-child relationships/ownership, traversal, scalar preservation,
copy-on-write replacement, and deterministic construction.
"""

import pytest
from dataclasses import FrozenInstanceError
from cst_auto_remediator.yaml_cst.parser import parse_yaml
from cst_auto_remediator.yaml_cst.builder import build_cst
from cst_auto_remediator.yaml_cst.nodes import (
    SourceSpan,
    YamlDocument,
    YamlMapping,
    YamlSequence,
    YamlKeyValue,
    YamlScalar,
    YamlNode,
)


def test_correct_node_hierarchy() -> None:
    content = (
        b"workflow_name: test\n"
        b"on: push\n"
        b"jobs:\n"
        b"  build:\n"
        b"    runs-on: ubuntu-latest\n"
        b"    steps:\n"
        b"      - name: setup\n"
        b"        run: echo hello\n"
    )
    doc_tree, meta = parse_yaml(content)
    cst = build_cst(doc_tree, meta)

    # YamlDocument properties
    assert isinstance(cst, YamlDocument)
    assert isinstance(cst.metadata, dict)
    assert cst.metadata["sha256"] is not None

    # Root mapping
    assert isinstance(cst.root, YamlMapping)
    assert len(cst.root.entries) == 3

    # Keys and entry hierarchy
    entry_workflow = cst.root.entries[0]
    assert isinstance(entry_workflow, YamlKeyValue)
    assert isinstance(entry_workflow.key, YamlScalar)
    assert entry_workflow.key.value == "workflow_name"
    assert isinstance(entry_workflow.value, YamlScalar)
    assert entry_workflow.value.value == "test"

    entry_jobs = cst.root.entries[2]
    assert entry_jobs.key.value == "jobs"
    assert isinstance(entry_jobs.value, YamlMapping)

    job_build = entry_jobs.value.entries[0]
    assert job_build.key.value == "build"
    assert isinstance(job_build.value, YamlMapping)

    # Sequence hierarchy
    steps_entry = [e for e in job_build.value.entries if e.key.value == "steps"][0]
    assert isinstance(steps_entry.value, YamlSequence)
    assert len(steps_entry.value.items) == 1
    assert isinstance(steps_entry.value.items[0], YamlMapping)


def test_immutable_reconstruction_and_cow() -> None:
    content = (
        b"key: old_value\n"
        b"list:\n"
        b"  - item0\n"
        b"  - item1\n"
    )
    doc_tree, meta = parse_yaml(content)
    cst = build_cst(doc_tree, meta)

    # 1. Immutability checks (frozen dataclasses)
    with pytest.raises(FrozenInstanceError):
        cst.root.entries[0].value.value = "new_value"  # type: ignore

    with pytest.raises(FrozenInstanceError):
        cst.root.span = SourceSpan(100, 100)  # type: ignore

    # 2. Copy-on-Write (replace API)
    orig_scalar = cst.root.entries[0].value
    assert isinstance(orig_scalar, YamlScalar)
    new_scalar = orig_scalar.with_value("new_value")
    
    assert orig_scalar.value == "old_value"  # original untouched
    assert new_scalar.value == "new_value"
    assert new_scalar.node_id == orig_scalar.node_id  # identity preserved
    assert new_scalar.style == orig_scalar.style

    # 3. Sibling structural sharing
    orig_mapping = cst.root
    assert isinstance(orig_mapping, YamlMapping)
    
    mutated_mapping = orig_mapping.with_entry("key", new_scalar)
    assert mutated_mapping.entries[0].value is new_scalar
    # list entry is shared structurally
    assert mutated_mapping.entries[1] is orig_mapping.entries[1]
    assert mutated_mapping.node_id == orig_mapping.node_id

    # 4. Helper with_* replacement methods
    # Test YamlScalar.with_style and with_span
    s1 = YamlScalar(value="hello", style="PLAIN")
    s2 = s1.with_style("SINGLE_QUOTED")
    s3 = s2.with_span(SourceSpan(1, 2))
    assert s1.style == "PLAIN"
    assert s2.style == "SINGLE_QUOTED"
    assert s3.span == SourceSpan(1, 2)
    assert s3.node_id == s1.node_id

    # Test YamlKeyValue replacement methods
    kv1 = YamlKeyValue(key=s1, value=s2)
    kv2 = kv1.with_key(s3)
    kv3 = kv1.with_value(s1)
    kv4 = kv1.with_span(SourceSpan(5, 6))
    assert kv2.key is s3
    assert kv3.value is s1
    assert kv4.span == SourceSpan(5, 6)
    assert kv4.node_id == kv1.node_id

    # Test YamlMapping replacement methods
    m1 = YamlMapping(entries=[kv1])
    m2 = m1.with_entries([kv2])
    m3 = m1.with_span(SourceSpan(10, 11))
    assert m2.entries == [kv2]
    assert m3.span == SourceSpan(10, 11)
    assert m3.node_id == m1.node_id

    # Test YamlSequence replacement methods
    seq1 = YamlSequence(items=[s1])
    seq2 = seq1.with_items([s2])
    seq3 = seq1.with_span(SourceSpan(12, 13))
    assert seq2.items == [s2]
    assert seq3.span == SourceSpan(12, 13)
    assert seq3.node_id == seq1.node_id

    # Test YamlDocument replacement methods
    doc1 = YamlDocument(root=m1, metadata={"file": "test.yml"})
    doc2 = doc1.with_root(m2)
    doc3 = doc1.with_metadata({"file": "other.yml"})
    doc4 = doc1.with_span(SourceSpan(0, 0))
    assert doc2.root is m2
    assert doc3.metadata == {"file": "other.yml"}
    assert doc4.span == SourceSpan(0, 0)
    assert doc4.node_id == doc1.node_id


def test_parent_child_ownership() -> None:
    content = (
        b"parent_key:\n"
        b"  child_key: child_value\n"
    )
    doc_tree, meta = parse_yaml(content)
    doc = build_cst(doc_tree, meta)

    # Downward ownership assertion
    root_map = doc.root
    assert isinstance(root_map, YamlMapping)
    kv_parent = root_map.entries[0]
    assert kv_parent.key.value == "parent_key"
    
    child_map = kv_parent.value
    assert isinstance(child_map, YamlMapping)
    kv_child = child_map.entries[0]
    assert kv_child.key.value == "child_key"
    assert kv_child.value.value == "child_value"

    # Upward rebuild simulation verifying copy-on-write propagation
    new_child_val = kv_child.value.with_value("new_child_value")
    new_kv_child = kv_child.with_value(new_child_val)
    new_child_map = child_map.with_entries([new_kv_child])
    new_kv_parent = kv_parent.with_value(new_child_map)
    new_root_map = root_map.with_entries([new_kv_parent])
    new_doc = doc.with_root(new_root_map)

    # Original unchanged
    assert doc.root.entries[0].value.entries[0].value.value == "child_value"  # type: ignore
    
    # New document has the update
    assert new_doc.root.entries[0].value.entries[0].value.value == "new_child_value"  # type: ignore

    # Identity verification (node_ids are preserved, showing they represent the same logical node)
    assert new_doc.node_id == doc.node_id
    assert new_doc.root.node_id == doc.root.node_id
    assert new_doc.root.entries[0].node_id == doc.root.entries[0].node_id


def test_mapping_and_sequence_traversal() -> None:
    content = (
        b"empty_map: {}\n"
        b"empty_seq: []\n"
        b"seq:\n"
        b"  - val1\n"
        b"  - val2\n"
    )
    doc_tree, meta = parse_yaml(content)
    cst = build_cst(doc_tree, meta)

    entries = {e.key.value: e.value for e in cst.root.entries}

    # Empty structures traversal
    empty_map = entries["empty_map"]
    assert isinstance(empty_map, YamlMapping)
    assert len(empty_map.entries) == 0

    empty_seq = entries["empty_seq"]
    assert isinstance(empty_seq, YamlSequence)
    assert len(empty_seq.items) == 0

    # Sequence traversal
    seq = entries["seq"]
    assert isinstance(seq, YamlSequence)
    assert len(seq.items) == 2
    assert seq.items[0].value == "val1"
    assert seq.items[1].value == "val2"


def test_scalar_preservation_and_styles() -> None:
    content = (
        b"int_val: 42\n"
        b"float_val: 3.14\n"
        b"bool_true: true\n"
        b"bool_false: false\n"
        b"null_val: null\n"
        b"tilde_val: ~\n"
        b"empty_val:\n"
        b"single_quoted: 'hello'\n"
        b"double_quoted: \"world\"\n"
        b"literal_val: |\n"
        b"  line 1\n"
        b"  line 2\n"
        b"folded_val: >\n"
        b"  line 1\n"
        b"  line 2\n"
    )
    doc_tree, meta = parse_yaml(content)
    cst = build_cst(doc_tree, meta)

    entries = {e.key.value: e.value for e in cst.root.entries}

    assert entries["int_val"].value == 42
    assert entries["int_val"].raw_text == "42"
    assert entries["int_val"].style == "PLAIN"

    assert entries["float_val"].value == 3.14
    assert entries["float_val"].raw_text == "3.14"

    assert entries["bool_true"].value is True
    assert entries["bool_true"].raw_text == "true"

    assert entries["bool_false"].value is False
    assert entries["bool_false"].raw_text == "false"

    assert entries["null_val"].value is None
    assert entries["null_val"].raw_text == "null" or entries["null_val"].raw_text == ""

    assert entries["tilde_val"].value is None
    assert entries["empty_val"].value is None

    assert entries["single_quoted"].style == "SINGLE_QUOTED"
    assert entries["single_quoted"].value == "hello"
    assert entries["single_quoted"].raw_text == "'hello'"

    assert entries["double_quoted"].style == "DOUBLE_QUOTED"
    assert entries["double_quoted"].value == "world"
    assert entries["double_quoted"].raw_text == '"world"'

    assert entries["literal_val"].style == "LITERAL"
    assert entries["literal_val"].value == "line 1\nline 2\n"
    assert entries["literal_val"].raw_text.startswith("|")

    assert entries["folded_val"].style == "FOLDED"
    assert entries["folded_val"].value == "line 1 line 2\n"
    assert entries["folded_val"].raw_text.startswith(">")


def test_deterministic_tree_construction() -> None:
    content = (
        b"name: workflow\n"
        b"on: push\n"
        b"jobs:\n"
        b"  test:\n"
        b"    steps:\n"
        b"      - run: echo\n"
    )
    # Parse 1
    doc_tree1, meta1 = parse_yaml(content)
    cst1 = build_cst(doc_tree1, meta1)

    # Parse 2
    doc_tree2, meta2 = parse_yaml(content)
    cst2 = build_cst(doc_tree2, meta2)

    # Random node IDs mean standard equality returns False
    assert cst1.node_id != cst2.node_id
    assert cst1 != cst2

    # Structural equality check passes
    assert cst1.structurally_equal(cst2) is True
    assert cst2.structurally_equal(cst1) is True

    # Mutated tree must not be structurally equal
    mutated_cst = cst1.with_root(
        cst1.root.with_entry("name", cst1.root.entries[0].value.with_value("changed_name"))  # type: ignore
    )
    assert cst1.structurally_equal(mutated_cst) is False


def test_source_range_preservation() -> None:
    content = (
        b"key: value\n"
        b"nested:\n"
        b"  inner: 123\n"
    )
    doc_tree, meta = parse_yaml(content)
    cst = build_cst(doc_tree, meta)

    # key span: line 0, col 0
    key_entry = cst.root.entries[0]
    assert key_entry.key.span is not None
    assert key_entry.key.span.line == 0
    assert key_entry.key.span.column == 0

    # value span: line 0, col 5
    assert key_entry.value.span is not None
    assert key_entry.value.span.line == 0
    assert key_entry.value.span.column == 5

    # nested key span: line 1, col 0
    nested_entry = cst.root.entries[1]
    assert nested_entry.key.span is not None
    assert nested_entry.key.span.line == 1
    assert nested_entry.key.span.column == 0

    # inner key span: line 2, col 2
    inner_entry = nested_entry.value.entries[0]  # type: ignore
    assert inner_entry.key.span is not None
    assert inner_entry.key.span.line == 2
    assert inner_entry.key.span.column == 2

    # inner value span: line 2, col 9
    assert inner_entry.value.span is not None
    assert inner_entry.value.span.line == 2
    assert inner_entry.value.span.column == 9
