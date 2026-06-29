"""
Stage 6 - Right-to-left run-command substitutions.
"""

from __future__ import annotations

from cst_auto_remediator.gha_transform.nodes import SiteReplacement


def apply_rtl_substitutions(script_text: str, replacements: tuple[SiteReplacement, ...]) -> str:
    """
    Apply expression substitutions to decoded run-command text from right to left.
    """
    result = script_text
    previous_start = len(script_text) + 1

    for replacement in sorted(replacements, key=lambda item: item.start_offset, reverse=True):
        start = replacement.start_offset
        end = replacement.end_offset

        if start < 0 or end < start or end > len(script_text):
            raise ValueError(
                f"invalid replacement range {start}:{end} for script length {len(script_text)}"
            )
        if end > previous_start:
            raise ValueError("overlapping replacements are not supported")
        if script_text[start:end] != replacement.original_text:
            raise ValueError(
                f"replacement text mismatch at {start}:{end}: "
                f"expected {replacement.original_text!r}"
            )

        result = result[:start] + replacement.replacement_text + result[end:]
        previous_start = start

    return result
