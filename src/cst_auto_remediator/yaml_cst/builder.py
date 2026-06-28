"""
Stage 2 — Lossless YAML CST Builder.

Recursive builder that translates ruamel.yaml CommentedMap / CommentedSeq / scalars
into the typed immutable YamlDocument Concrete Syntax Tree (CST).
"""

from __future__ import annotations

from typing import Any

from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.scalarstring import (
    DoubleQuotedScalarString,
    FoldedScalarString,
    LiteralScalarString,
    SingleQuotedScalarString,
)

from cst_auto_remediator.yaml_cst.nodes import (
    SourceSpan,
    YamlNode,
    YamlScalar,
    YamlKeyValue,
    YamlMapping,
    YamlSequence,
    YamlDocument,
)


def build_cst(parsed_doc: Any, metadata: dict[str, Any]) -> YamlDocument:
    """
    Recursively convert a parsed ruamel.yaml document into an immutable YamlDocument tree.
    """
    root_node = _build_node(parsed_doc)
    return YamlDocument(
        span=root_node.span,
        root=root_node,
        metadata=metadata,
    )


def _build_node(val: Any, span: SourceSpan | None = None) -> YamlNode:
    if isinstance(val, CommentedMap):
        entries = []
        lc = getattr(val, "lc", None)
        for k, v in val.items():
            k_line, k_col = (None, None)
            if lc is not None:
                try:
                    k_line, k_col = lc.key(k)
                except (KeyError, AttributeError):
                    pass
            k_span = SourceSpan(k_line, k_col) if k_line is not None else None
            key_node = YamlScalar(span=k_span, value=k, raw_text=str(k), style="PLAIN")

            val_span = None
            if lc is not None:
                try:
                    v_line, v_col = lc.value(k)
                    val_span = SourceSpan(v_line, v_col)
                except (KeyError, AttributeError):
                    pass
            if val_span is None and isinstance(v, (CommentedMap, CommentedSeq)):
                v_lc = getattr(v, "lc", None)
                if v_lc is not None:
                    val_span = SourceSpan(v_lc.line, v_lc.col)

            val_node = _build_node(v, val_span)
            kv_span = k_span
            entries.append(YamlKeyValue(span=kv_span, key=key_node, value=val_node))

        map_span = span
        if map_span is None and lc is not None:
            map_span = SourceSpan(lc.line, lc.col)
        return YamlMapping(span=map_span, entries=entries)

    elif isinstance(val, CommentedSeq):
        items = []
        lc = getattr(val, "lc", None)
        for i, item in enumerate(val):
            item_span = None
            if lc is not None:
                try:
                    item_line, item_col = lc.item(i)
                    item_span = SourceSpan(item_line, item_col)
                except (KeyError, IndexError, AttributeError):
                    pass

            if item_span is None and isinstance(item, (CommentedMap, CommentedSeq)):
                item_lc = getattr(item, "lc", None)
                if item_lc is not None:
                    item_span = SourceSpan(item_lc.line, item_lc.col)

            items.append(_build_node(item, item_span))

        seq_span = span
        if seq_span is None and lc is not None:
            seq_span = SourceSpan(lc.line, lc.col)
        return YamlSequence(span=seq_span, items=items)

    else:
        # Scalar value
        style = "PLAIN"
        if isinstance(val, SingleQuotedScalarString):
            style = "SINGLE_QUOTED"
            raw_text = f"'{val}'"
        elif isinstance(val, DoubleQuotedScalarString):
            style = "DOUBLE_QUOTED"
            raw_text = f'"{val}"'
        elif isinstance(val, FoldedScalarString):
            style = "FOLDED"
            raw_text = f">{val}"
        elif isinstance(val, LiteralScalarString):
            style = "LITERAL"
            raw_text = f"|{val}"
        else:
            if val is None:
                raw_text = ""
            elif isinstance(val, bool):
                raw_text = str(val).lower()
            else:
                raw_text = str(val)

        return YamlScalar(span=span, value=val, raw_text=raw_text, style=style)
