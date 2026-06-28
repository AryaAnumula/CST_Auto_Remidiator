"""
Stage 2 — Lossless YAML CST Nodes.

Immutable syntax nodes for representing parsed YAML structures.
"""

from __future__ import annotations

import dataclasses
import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class SourceSpan:
    line: int
    column: int


@dataclass(frozen=True)
class YamlNode:
    node_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    span: SourceSpan | None = None

    def replace(self, **kwargs: Any) -> YamlNode:
        """
        Generic copy-on-write replacement method.
        Returns a new instance of the same node type with the specified fields replaced.
        """
        return dataclasses.replace(self, **kwargs)

    def structurally_equal(self, other: YamlNode) -> bool:
        """
        Check if two nodes are structurally equal, ignoring node_id.
        """
        if type(self) is not type(other):
            return False
        if self.span != other.span:
            return False

        if isinstance(self, YamlScalar):
            assert isinstance(other, YamlScalar)
            return (
                self.value == other.value
                and self.raw_text == other.raw_text
                and self.style == other.style
            )
        elif isinstance(self, YamlKeyValue):
            assert isinstance(other, YamlKeyValue)
            return (
                self.key.structurally_equal(other.key)
                and self.value.structurally_equal(other.value)
            )
        elif isinstance(self, YamlMapping):
            assert isinstance(other, YamlMapping)
            if len(self.entries) != len(other.entries):
                return False
            return all(
                e1.structurally_equal(e2)
                for e1, e2 in zip(self.entries, other.entries)
            )
        elif isinstance(self, YamlSequence):
            assert isinstance(other, YamlSequence)
            if len(self.items) != len(other.items):
                return False
            return all(
                i1.structurally_equal(i2)
                for i1, i2 in zip(self.items, other.items)
            )
        elif isinstance(self, YamlDocument):
            assert isinstance(other, YamlDocument)
            if (self.root is None) != (other.root is None):
                return False
            if self.root is not None and other.root is not None:
                if not self.root.structurally_equal(other.root):
                    return False
            return self.metadata == other.metadata

        return True


@dataclass(frozen=True)
class YamlScalar(YamlNode):
    value: Any = None
    raw_text: str = ""
    style: str = "PLAIN"  # PLAIN, SINGLE_QUOTED, DOUBLE_QUOTED

    def with_value(self, new_value: Any, new_raw: str | None = None) -> YamlScalar:
        raw = new_raw if new_raw is not None else str(new_value)
        return self.replace(value=new_value, raw_text=raw)

    def with_style(self, new_style: str) -> YamlScalar:
        return self.replace(style=new_style)

    def with_span(self, new_span: SourceSpan | None) -> YamlScalar:
        return self.replace(span=new_span)


@dataclass(frozen=True)
class YamlKeyValue(YamlNode):
    key: YamlScalar = None
    value: YamlNode = None

    def with_key(self, new_key: YamlScalar) -> YamlKeyValue:
        return self.replace(key=new_key)

    def with_value(self, new_value: YamlNode) -> YamlKeyValue:
        return self.replace(value=new_value)

    def with_span(self, new_span: SourceSpan | None) -> YamlKeyValue:
        return self.replace(span=new_span)


@dataclass(frozen=True)
class YamlMapping(YamlNode):
    entries: list[YamlKeyValue] = field(default_factory=list)

    def with_entries(self, new_entries: list[YamlKeyValue]) -> YamlMapping:
        return self.replace(entries=new_entries)

    def with_entry(self, key_name: str, new_value: YamlNode) -> YamlMapping:
        new_entries = []
        for entry in self.entries:
            if entry.key.value == key_name:
                new_entries.append(entry.with_value(new_value))
            else:
                new_entries.append(entry)
        return self.replace(entries=new_entries)

    def with_span(self, new_span: SourceSpan | None) -> YamlMapping:
        return self.replace(span=new_span)


@dataclass(frozen=True)
class YamlSequence(YamlNode):
    items: list[YamlNode] = field(default_factory=list)

    def with_items(self, new_items: list[YamlNode]) -> YamlSequence:
        return self.replace(items=new_items)

    def with_item(self, index: int, new_item: YamlNode) -> YamlSequence:
        new_items = list(self.items)
        new_items[index] = new_item
        return self.replace(items=new_items)

    def with_span(self, new_span: SourceSpan | None) -> YamlSequence:
        return self.replace(span=new_span)


@dataclass(frozen=True)
class YamlDocument(YamlNode):
    root: YamlNode = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def with_root(self, new_root: YamlNode) -> YamlDocument:
        return self.replace(root=new_root)

    def with_metadata(self, new_metadata: dict[str, Any]) -> YamlDocument:
        return self.replace(metadata=new_metadata)

    def with_span(self, new_span: SourceSpan | None) -> YamlDocument:
        return self.replace(span=new_span)
