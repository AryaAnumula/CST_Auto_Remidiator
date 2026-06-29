"""
Stage 3 — Balanced Brace Expression Scanner.
"""

from __future__ import annotations

from cst_auto_remediator.yaml_cst.nodes import YamlScalar
from cst_auto_remediator.gha_semantic.nodes import ExpressionSite


def extract_expression_sites(scalar: YamlScalar) -> list[ExpressionSite]:
    """
    Extract all balanced ${{ ... }} expression sites from a YamlScalar node.
    """
    text = scalar.value
    if not isinstance(text, str):
        return []

    results: list[ExpressionSite] = []
    pos = 0
    while pos < len(text):
        start = text.find("${{", pos)
        if start == -1:
            break

        # Look for matching }} with brace nesting awareness
        cursor = start + 3
        depth = 1
        end = -1
        while cursor < len(text):
            if text.startswith("${{", cursor):
                depth += 1
                cursor += 3
            elif text.startswith("}}", cursor):
                depth -= 1
                cursor += 2
                if depth == 0:
                    end = cursor
                    break
            else:
                cursor += 1

        if end == -1:
            # Unclosed expression
            pos = start + 3
            continue

        expr_text = text[start:end]
        expr_body = expr_text[3:-2].strip()
        results.append(
            ExpressionSite(
                node=scalar,
                expression_text=expr_text,
                expression_body=expr_body,
                start_offset=start,
                end_offset=end,
            )
        )
        pos = end

    return results
