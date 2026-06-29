"""
Stage 7 — Format-preserving YAML Serializer.

Translates the mutated Green CST YamlDocument back into format-accurate YAML bytes,
retaining comments, quote styles, spacing, and other original formatting.
"""

from __future__ import annotations

import copy
from io import StringIO
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.scalarstring import (
    DoubleQuotedScalarString,
    FoldedScalarString,
    LiteralScalarString,
    PlainScalarString,
    SingleQuotedScalarString,
)

from cst_auto_remediator.yaml_cst.nodes import (
    YamlDocument,
    YamlKeyValue,
    YamlMapping,
    YamlNode,
    YamlScalar,
    YamlSequence,
)


class SerializationContext:
    """
    Ephemeral context for a single serialization operation.
    Maps CST nodes (via their Python object ID) to the original parsed ruamel.yaml objects
    by traversing both structures in parallel.
    """

    def __init__(self, original_ruamel_root: Any, original_cst: YamlDocument):
        self.cst_to_ruamel: dict[int, Any] = {}
        if original_cst.root is not None:
            self._build_mapping(original_cst.root, original_ruamel_root)

    def _build_mapping(self, cst_node: YamlNode, ruamel_node: Any) -> None:
        if cst_node is None or ruamel_node is None:
            return

        self.cst_to_ruamel[id(cst_node)] = ruamel_node

        if isinstance(cst_node, YamlMapping) and isinstance(ruamel_node, dict):
            for entry in cst_node.entries:
                key_val = entry.key.value
                if key_val in ruamel_node:
                    self._build_mapping(entry.value, ruamel_node[key_val])
                    self.cst_to_ruamel[id(entry.key)] = key_val

        elif isinstance(cst_node, YamlSequence) and isinstance(ruamel_node, list):
            for idx in range(min(len(cst_node.items), len(ruamel_node))):
                self._build_mapping(cst_node.items[idx], ruamel_node[idx])


def _build_orig_to_copy(orig: Any, copied: Any, orig_to_copy: dict[int, Any]) -> None:
    """Build a mapping of original ruamel object IDs to their copied counterparts."""
    orig_to_copy[id(orig)] = copied
    if isinstance(orig, dict) and isinstance(copied, dict):
        for k in orig:
            if k in copied:
                _build_orig_to_copy(orig[k], copied[k], orig_to_copy)
    elif isinstance(orig, list) and isinstance(copied, list):
        for idx in range(min(len(orig), len(copied))):
            _build_orig_to_copy(orig[idx], copied[idx], orig_to_copy)


def to_ruamel(node: YamlNode) -> Any:
    """Construct new ruamel.yaml structures for brand-new/mutated nodes recursively."""
    if isinstance(node, YamlScalar):
        if node.style == "SINGLE_QUOTED":
            return SingleQuotedScalarString(node.value)
        elif node.style == "DOUBLE_QUOTED":
            return DoubleQuotedScalarString(node.value)
        elif node.style == "FOLDED":
            return FoldedScalarString(node.value)
        elif node.style == "LITERAL":
            return LiteralScalarString(node.value)
        else:
            if node.value is None:
                return None
            if isinstance(node.value, (int, float, bool)):
                return node.value
            return PlainScalarString(node.value)

    elif isinstance(node, YamlMapping):
        m = CommentedMap()
        for entry in node.entries:
            key_str = entry.key.value
            m[key_str] = to_ruamel(entry.value)
        return m

    elif isinstance(node, YamlSequence):
        s = CommentedSeq()
        for item in node.items:
            s.append(to_ruamel(item))
        return s

    elif isinstance(node, YamlDocument):
        return to_ruamel(node.root)

    raise TypeError(f"Cannot convert unsupported YamlNode to ruamel: {type(node)}")


def sync_cst_to_ruamel(
    mutated_node: YamlNode,
    copy_ruamel: Any,
    cst_to_ruamel: dict[int, Any],
    orig_to_copy: dict[int, Any],
) -> None:
    """
    Recursively sync changes from a mutated CST node into a copied ruamel.yaml object.
    Untouched subtrees are identified via cst_to_ruamel and preserved without modification.
    """
    if id(mutated_node) in cst_to_ruamel:
        # Structural Sharing Invariant: Node is untouched, skip sync for this entire subtree.
        return

    if isinstance(mutated_node, YamlMapping):
        # 1. Sync deleted keys
        mutated_keys = {entry.key.value for entry in mutated_node.entries}
        for key in list(copy_ruamel.keys()):
            if key not in mutated_keys:
                del copy_ruamel[key]

        # 2. Sync entries (keys and values)
        for idx, entry in enumerate(mutated_node.entries):
            key_str = entry.key.value
            if key_str in copy_ruamel:
                val_node = entry.value
                if id(val_node) in cst_to_ruamel:
                    pass
                else:
                    current_copy_val = copy_ruamel[key_str]
                    if isinstance(val_node, YamlScalar):
                        copy_ruamel[key_str] = to_ruamel(val_node)
                    elif isinstance(val_node, YamlMapping) and isinstance(current_copy_val, dict):
                        sync_cst_to_ruamel(val_node, current_copy_val, cst_to_ruamel, orig_to_copy)
                    elif isinstance(val_node, YamlSequence) and isinstance(current_copy_val, list):
                        sync_cst_to_ruamel(val_node, current_copy_val, cst_to_ruamel, orig_to_copy)
                    else:
                        copy_ruamel[key_str] = to_ruamel(val_node)
            else:
                # Key is new (e.g. step env injection). Insert key at its exact index.
                new_val = to_ruamel(entry.value)
                copy_ruamel.insert(idx, key_str, new_val)

    elif isinstance(mutated_node, YamlSequence):
        # 1. Sync deleted sequence items (truncation)
        if len(mutated_node.items) < len(copy_ruamel):
            del copy_ruamel[len(mutated_node.items):]

        # 2. Sync sequence items
        for idx, item in enumerate(mutated_node.items):
            if idx < len(copy_ruamel):
                if id(item) in cst_to_ruamel:
                    pass
                else:
                    current_copy_item = copy_ruamel[idx]
                    if isinstance(item, YamlScalar):
                        copy_ruamel[idx] = to_ruamel(item)
                    elif isinstance(item, YamlMapping) and isinstance(current_copy_item, dict):
                        sync_cst_to_ruamel(item, current_copy_item, cst_to_ruamel, orig_to_copy)
                    elif isinstance(item, YamlSequence) and isinstance(current_copy_item, list):
                        sync_cst_to_ruamel(item, current_copy_item, cst_to_ruamel, orig_to_copy)
                    else:
                        copy_ruamel[idx] = to_ruamel(item)
            else:
                # Item is new, append it
                copy_ruamel.append(to_ruamel(item))


def detect_indentation(text: str) -> tuple[int, int, int]:
    """
    Detect (mapping_indent, sequence_indent, sequence_offset) from original YAML text.
    Defaults to (2, 4, 2) if not found.
    """
    lines = text.splitlines()
    mapping_indent = 2
    sequence_indent = 4
    sequence_offset = 2

    # 1. Detect mapping indent
    indents = []
    for line in lines:
        stripped = line.lstrip()
        if stripped and not stripped.startswith(('#', '-')):
            indents.append(len(line) - len(stripped))

    unique_indents = sorted(list(set(indents)))
    diffs = [unique_indents[i+1] - unique_indents[i] for i in range(len(unique_indents)-1)]
    non_zero_diffs = [d for d in diffs if d > 0]
    if non_zero_diffs:
        mapping_indent = min(non_zero_diffs)

    # 2. Detect sequence indent and offset
    for idx, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith('-'):
            seq_spaces = len(line) - len(stripped)
            parent_spaces = None
            for p_idx in range(idx - 1, -1, -1):
                p_line = lines[p_idx]
                p_stripped = p_line.lstrip()
                if p_stripped and p_stripped.endswith(':') and not p_stripped.startswith('#'):
                    p_spaces = len(p_line) - len(p_stripped)
                    if p_spaces < seq_spaces:
                        parent_spaces = p_spaces
                        break
            if parent_spaces is not None:
                sequence_offset = seq_spaces - parent_spaces
                sequence_indent = sequence_offset + 2
                break

    return mapping_indent, sequence_indent, sequence_offset


def restore_blank_lines(original_text: str, serialized_text: str) -> str:
    """
    Restore blank lines from original_text into serialized_text based on the
    non-blank lines that follow them.
    """
    line_ending = "\r\n" if "\r\n" in original_text else "\n"
    orig_lines = original_text.splitlines()
    ser_lines = serialized_text.splitlines()

    preceding_blanks: dict[str, list[list[str]]] = {}

    current_blanks = []
    for line in orig_lines:
        if not line.strip():
            current_blanks.append(line)
        else:
            key = line.strip()
            preceding_blanks.setdefault(key, []).append(current_blanks)
            current_blanks = []

    final_lines = []
    consumed_counts: dict[str, int] = {}

    for line in ser_lines:
        if not line.strip():
            continue

        key = line.strip()
        if key in preceding_blanks:
            idx = consumed_counts.get(key, 0)
            if idx < len(preceding_blanks[key]):
                blanks = preceding_blanks[key][idx]
                final_lines.extend(blanks)
                consumed_counts[key] = idx + 1

        final_lines.append(line)

    if current_blanks:
        final_lines.extend(current_blanks)

    return line_ending.join(final_lines) + line_ending


def serialize_document(
    mutated_document: YamlDocument,
    original_ruamel_root: Any,
    original_cst: YamlDocument,
    original_text: str | None = None,
) -> bytes:
    """
    Serialize a mutated CST YamlDocument back into formatted YAML bytes.
    Uses the original parsed ruamel root to preserve comments and layout.
    """
    context = SerializationContext(original_ruamel_root, original_cst)

    if isinstance(mutated_document.metadata, dict):
        line_ending = mutated_document.metadata.get("line_ending", "\n")
        encoding = mutated_document.metadata.get("encoding", "utf-8")
    else:
        line_ending = getattr(mutated_document.metadata, "line_ending", "\n")
        encoding = getattr(mutated_document.metadata, "encoding", "utf-8")

    if mutated_document.root is original_cst.root:
        # No mutations applied. Use original ruamel object as-is.
        final_ruamel = original_ruamel_root
    else:
        # Mutations exist. Copy original structure and synchronize changes.
        final_ruamel = copy.deepcopy(original_ruamel_root)
        orig_to_copy: dict[int, Any] = {}
        _build_orig_to_copy(original_ruamel_root, final_ruamel, orig_to_copy)

        if mutated_document.root is not None:
            sync_cst_to_ruamel(
                mutated_document.root,
                final_ruamel,
                context.cst_to_ruamel,
                orig_to_copy,
            )

    # Output generation
    yaml_printer = YAML(typ="rt")
    yaml_printer.preserve_quotes = True
    yaml_printer.default_flow_style = False
    yaml_printer.width = 4096

    if original_text is not None:
        mapping_indent, sequence_indent, sequence_offset = detect_indentation(original_text)
        yaml_printer.indent(mapping=mapping_indent, sequence=sequence_indent, offset=sequence_offset)

    out_stream = StringIO()
    yaml_printer.dump(final_ruamel, out_stream)
    serialized_str = out_stream.getvalue()

    if original_text is not None:
        serialized_str = restore_blank_lines(original_text, serialized_str)

    # Re-apply line endings
    if line_ending == "\r\n":
        serialized_str = serialized_str.replace("\r\n", "\n").replace("\n", "\r\n")
    else:
        serialized_str = serialized_str.replace("\r\n", "\n")

    return serialized_str.encode(encoding)
